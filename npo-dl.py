#!/usr/bin/env python3
import sys
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import base64
import os
from dotenv import load_dotenv

# Try to load from .env
load_dotenv()
VWKEYS_API_KEY = os.getenv("VWKEYS_API_KEY", "NONE")
DOWNLOAD_DIR = os.getenv("DOWNLOAD_DIR", "npovideos")

def get_slug_from_url(npo_url: str) -> str:
    """
    Extracts the episode slug from the URL (e.g. "spoorloos_107").
    Example path: /start/serie/spoorloos/seizoen-21/spoorloos_107/afspelen
    """
    print(npo_url)
    parsed = urlparse(npo_url)
    path = parsed.path
    parts = path.split("/")
    if len(parts) < 5:
        raise ValueError("Invalid URL format.")
    return parts[5]

def get_product_id_from_html(html_content: str, target_slug: str) -> str:
    """
    Extract the correct productId by matching the 'slug' in the JSON (the __NEXT_DATA__).
    If an episode has 'slug' == target_slug (e.g. 'spoorloos_107'),
    return that episode's 'productId' (e.g. 'KN_1735212').
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # Find the __NEXT_DATA__ script
    next_data_script = soup.find("script", {"id": "__NEXT_DATA__"})
    if not next_data_script or not next_data_script.string:
        raise ValueError("Could not find __NEXT_DATA__ script in HTML.")

    data = json.loads(next_data_script.string)

    # The queries are typically under props -> pageProps -> dehydratedState -> queries
    all_queries = data.get("props", {}) \
                     .get("pageProps", {}) \
                     .get("dehydratedState", {}) \
                     .get("queries", [])

    # We search all queries for 'state'->'data' which might be a list of episodes
    for query in all_queries:
        query_state = query.get("state", {})
        episode_data = query_state.get("data", None)

        # If data is a list, it may contain episodes
        if isinstance(episode_data, list):
            for item in episode_data:
                if not isinstance(item, dict):
                    continue
                # Check if the slug matches
                if item.get("slug") == target_slug and "productId" in item:
                    return item["productId"]

    raise ValueError(f"Could not find productId for slug '{target_slug}' in the HTML.")

def get_player_token(product_id: str, session: requests.Session) -> str:
    """
    Calls /start/api/domain/player-token?productId=... to get the JWT token.
    """
    url = f"https://npo.nl/start/api/domain/player-token?productId={product_id}"
    resp = session.get(url)
    if resp.status_code != 200:
        raise ValueError(f"Failed to get player token (status={resp.status_code}).")

    data = resp.json()
    if "jwt" not in data:
        raise ValueError("JWT not found in player-token response.")
    return data["jwt"]

def get_stream_info(jwt: str, session: requests.Session) -> dict:
    """
    Calls the 'stream-link' endpoint with the JWT to retrieve stream info
    (streamURL, drmToken, subtitles, etc.).
    """
    url = "https://prod.npoplayer.nl/stream-link"
    headers = {
        "Authorization": jwt,
        "Content-Type": "application/json",
        "Origin": "https://npo.nl",
        "Referer": "https://npo.nl/",
    }

    # Adjust this body if you need a different streaming profile or DRM
    payload = {
        "profileName": "dash",
        "drmType": "widevine",
        "referrerUrl": "https://npo.nl/start/serie/",
        "ster": {
            "identifier": "npo-app-desktop",
            "deviceType": 4,
            "player": "web"
        }
    }

    resp = session.post(url, headers=headers, json=payload)
    if resp.status_code != 200:
        raise ValueError(f"Failed to get stream info (status={resp.status_code}).")

    return resp.json()

def parse_pssh_from_mpd(mpd_xml: str) -> str:
    """
    Parse the MPD XML and extract the pssh from:
       mpdData["MPD"]["Period"]["AdaptationSet"][1]["ContentProtection"][3].pssh
    This is a very specific path and assumes that the second AdaptationSet
    and the 4th ContentProtection node contain the target PSSH element.
    If not found, returns an empty string.
    """
    soup = BeautifulSoup(mpd_xml, "xml")
    periods = soup.find_all("Period")
    if len(periods) < 1:
        return ""

    adaptation_sets = periods[0].find_all("AdaptationSet")
    if len(adaptation_sets) < 2:
        return ""

    content_protections = adaptation_sets[1].find_all("ContentProtection")
    if len(content_protections) < 4:
        return ""

    target_cp = content_protections[3]
    pssh_elem = target_cp.find("cenc:pssh")

    if pssh_elem and pssh_elem.text:
        return pssh_elem.text.strip()

    return ""

def get_widevine_keys(
    pssh: str,
    x_custom_data: str,
    license_url: str = "https://npo-drm-gateway.samgcloud.nepworldwide.nl/authentication",
    build_info: str = "",
    force: bool = False
) -> dict:
    """
    Performs a multi-step Widevine license acquisition via https://getwvkeys.cc:
      1) POST (pssh + license_url + build_info + force) to getwvkeys.cc
         - If 'x-cache' is present in response headers, the server returns a cached 'keys' array.
         - Otherwise, we receive a 'challenge' (base64) and 'session_id'.
      2) Decode the base64 'challenge' into bytes and POST those bytes to the license server.
      3) Base64-encode the license server's binary response and POST it back to getwvkeys.cc (with the same 'session_id').
      4) Receive final keys.

    :param pssh: Base64-encoded PSSH string
    :param x_custom_data: Some token or DRM auth data required by the license server
    :param license_url: The actual Widevine license server endpoint
    :param build_info: (Optional) Additional param used by getwvkeys.cc
    :param force: (Optional) If True, forces re-fetching keys even if cached
    :param verbose: (Optional) If True, prints extra logs
    :return: dict with the final JSON response from getwvkeys.cc (including "keys")
    """
    api_url = "https://getwvkeys.cc/pywidevine"

    # Headers for the getwvkeys API
    api_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/90.0.4430.85 Safari/537.36"
        ),
        "Content-Type": "application/json",
        "X-API-Key": VWKEYS_API_KEY,
        "x-custom-data": x_custom_data
    }

    # The initial payload to getwvkeys
    payload = {
        "pssh": pssh,
        "license_url": license_url,
        "buildInfo": build_info,
        "force": force,
    }

    try:
        # STEP 1: Call the getwvkeys API
        r1 = requests.post(api_url, headers=api_headers, json=payload)

        if r1.status_code != 200 and r1.status_code != 302:
            print("[get_widevine_keys] Error from getwvkeys.cc:", r1.status_code, r1.text)
            return {}

        # Attempt to parse JSON
        data1 = r1.json()

        # If x-cache is in response headers, we have a cached result with keys
        if "x-cache" in r1.headers:
            # The server returns a direct "keys" array
            return data1

        # Not cached => we have to do the challenge/response
        if "challenge" not in data1 or "session_id" not in data1:
            print("[get_widevine_keys] Unexpected response (no challenge/session_id).")
            return {}

        challenge_b64 = data1["challenge"]
        session_id = data1["session_id"]

        # STEP 2: decode the base64 challenge into raw bytes
        challenge_bytes = base64.b64decode(challenge_b64)

        # We now POST these bytes to the real license server
        # Make sure we pass the same 'x_custom_data' if it is required by that server.
        # Typically, you also want no JSON content-type here, because it's a binary POST.
        license_headers = {
            "User-Agent": api_headers["User-Agent"],
            "x-custom-data": x_custom_data,
        }

        r2 = requests.post(license_url, headers=license_headers, data=challenge_bytes)

        if r2.status_code != 200:
            print("[get_widevine_keys] License server error:", r2.status_code, r2.text)
            return {}

        # STEP 3: Base64-encode the license server's binary response
        license_b64 = base64.b64encode(r2.content).decode('utf-8')

        # Prepare second call to getwvkeys with session_id + license response
        payload2 = {
            "pssh": pssh,
            "license_url": license_url,
            "buildInfo": build_info,
            "force": force,
            "session_id": session_id,
            "response": license_b64
        }

        r3 = requests.post(api_url, headers=api_headers, json=payload2)

        if r3.status_code != 200:
            print("[get_widevine_keys] Error from getwvkeys.cc on final step:", r3.status_code, r3.text)
            return {}

        data3 = r3.json()
        return data3

    except Exception as e:
        print("[get_widevine_keys] Exception:", str(e))
        return {}

def get_npo_stream_info(npo_url: str) -> dict:
    """
    Orchestrates the entire process:
    1. Parse the slug (e.g. "spoorloos_107") from the URL.
    2. GET the page HTML.
    3. Extract the matching productId for that slug.
    4. GET the JWT token from /player-token.
    5. POST to /stream-link with the JWT to get final stream info.
    6. If drmToken is present, fetch the MPD and parse the PSSH.
    7. If both pssh and drmToken are available, call getwvkeys.cc to get Widevine keys.

    Returns a dict with all relevant data:
      - slug
      - productId
      - streamURL
      - drmType
      - drmToken
      - pssh (if found)
      - wideVineKeyResponse (if retrieved)
      - fullResponse (raw JSON from stream-link)
    """

    slug = get_slug_from_url(npo_url)

    with requests.Session() as s:
        # 1. GET the page
        resp = s.get(npo_url)
        if resp.status_code != 200:
            raise ValueError(f"Could not retrieve the page (status={resp.status_code}).")

        # 2. Extract productId matching the slug
        product_id = get_product_id_from_html(resp.text, slug)

        # 3. Get JWT
        jwt_token = get_player_token(product_id, s)

        # 4. Get final stream info
        stream_info = get_stream_info(jwt_token, s)
        stream_data = stream_info.get("stream", {})

        drm_token = stream_data.get("drmToken")
        pssh = ""
        widevine_key_response = None

        # 5. If a DRM token is present, retrieve the MPD and parse the PSSH.
        if drm_token:
            mpd_url = stream_data.get("streamURL")
            if mpd_url:
                mpd_resp = s.get(mpd_url)
                if mpd_resp.status_code == 200:
                    pssh = parse_pssh_from_mpd(mpd_resp.text)
                else:
                    pssh = ""

            # 6. If we have both pssh and drmToken, call getwvkeys.cc
            if pssh and drm_token:
                widevine_key_response = get_widevine_keys(pssh, drm_token)

        # Generate file name with seriename/SxxExx
        parsed = urlparse(npo_url).path.split("/")
        filename = f"{parsed[3]}-{parsed[4]}-{parsed[5]}"

        return {
            "filename": filename,
            "slug": slug,
            "productId": product_id,
            "streamURL": stream_data.get("streamURL"),
            "drmType": stream_data.get("drmType"),
            "drmToken": drm_token,
            "pssh": pssh,
            "wideVineKeyResponse": widevine_key_response,
            "fullResponse": stream_info
        }
    
def download_from_info(info: dict):
    """
    Downloads the stream from the given info dict.
    """
    # Check if file is not already downloaded
    if os.path.isfile(DOWNLOAD_DIR + "/" + info["filename"] + ".mkv"):
        print(f"Video already exists.")
        return
    
    # Download mpd using yt-dlp
    mpd_url = info["streamURL"]
    filename_format = 'encrypted#' + info["filename"] + '.%(ext)s'
    args = [
        '--allow-u',
        '--downloader',
        'aria2c',
        '-f',
        'bv,ba',
        '-P',
        DOWNLOAD_DIR + '/',
        '-o',
        filename_format,
        mpd_url
    ];
    runned = run_command('yt-dlp', args)
    print(runned)

    # Decrypt the video
    key = None
    if info["wideVineKeyResponse"] not in [None, {}]:
        key = info["wideVineKeyResponse"]["keys"][0]["key"]
    
    return decrypt_files(filename_format, key)


def decrypt_files(filename_format, key):
    """
    Decrypts the downloaded encrypted file.
    """
    file_path = DOWNLOAD_DIR + "/" + filename_format
    mp4_file = file_path.replace('.%(ext)s', '.mp4')
    m4a_file = file_path.replace('.%(ext)s', '.m4a')

    # Combine video and audio
    combined_file = file_path.replace('.%(ext)s', '.mkv').replace('encrypted#', '')
    args = ['-i',mp4_file,'-i',m4a_file,'-c','copy',combined_file]
    if key:
        args = [
            '-decryption_key',
            key.split(':')[1],
            '-i',
            mp4_file,
            '-decryption_key',
            key,
            '-i',
            m4a_file,
            '-c',
            'copy',
            combined_file
        ]
    runned = run_command('ffmpeg', args)
    print(runned)

    # Remove the decrypted files
    os.remove(mp4_file)
    os.remove(m4a_file)

    return combined_file
        

def run_command(command, args):
    """
    Run a command with arguments and return the output.
    """
    import subprocess
    process = subprocess.Popen([command] + args, stdout=subprocess.PIPE)
    output, error = process.communicate()
    return output
    

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <npo-url>")
        sys.exit(1)

    npo_url = sys.argv[1]

    try:
        info = get_npo_stream_info(npo_url)
        print("=== NPO Stream Info ===")
        print(f"Filename:              {info['filename']}")
        print(f"Slug:                  {info['slug']}")
        print(f"ProductId:             {info['productId']}")
        print(f"Stream URL:            {info['streamURL']}")
        print(f"DRM Type:              {info['drmType']}")
        print(f"DRM Token:             {info['drmToken']}")
        print(f"PSSH:                  {info['pssh']}")
        print(f"WideVineKeyResponse:   {info['wideVineKeyResponse']}")
        # Or dump everything:
        # print(json.dumps(info["fullResponse"], indent=2))
        download_from_info(info)
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
