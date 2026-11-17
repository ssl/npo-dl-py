#!/usr/bin/env python3
"""Download episodes, seasons or whole series from NPO Start."""
import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

API_BASE = "https://npo.nl/start/api/domain"
STREAM_LINK_URL = "https://prod.npoplayer.nl/stream-link"
GETWVKEYS_URL = "https://getwvkeys.cc/pywidevine"
# Used when the stream response does not name a license server itself.
DEFAULT_LICENSE_URL = "https://drm.npoplayer.nl/proxyEngine.aspx"
# Older stream responses carry a drmToken that goes to this gateway instead.
LEGACY_LICENSE_URL = "https://npo-drm-gateway.samgcloud.nepworldwide.nl/authentication"
WIDEVINE_SCHEME = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0"
)
REQUEST_TIMEOUT = 30
ENCRYPTED_PREFIX = "encrypted#"

VERBOSE = False


class NpoError(Exception):
    """An expected failure with a message meant for the user."""


def debug(*args):
    if VERBOSE:
        print(*args)


def env(name: str) -> str:
    """Read an env var, treating the placeholders from .env.example as unset."""
    value = (os.getenv(name) or "").strip()
    return "" if value.lower() in ("none", "abc123") else value


class Session(requests.Session):
    """requests.Session with a browser User-Agent and a default timeout."""

    def __init__(self):
        super().__init__()
        self.headers["User-Agent"] = USER_AGENT

    def request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", REQUEST_TIMEOUT)
        return super().request(method, url, **kwargs)


# --------------------------------------------------------------------------
# Episode lookup
# --------------------------------------------------------------------------

@dataclass
class Episode:
    product_id: str
    slug: str
    filename: str
    plus_only: bool

    @property
    def url(self) -> str:
        return f"https://npo.nl/start/afspelen/{self.slug}"


def api_get(session: Session, endpoint: str, **params):
    resp = session.get(f"{API_BASE}/{endpoint}", params=params)
    if resp.status_code == 404:
        raise NpoError(f"Not found on NPO Start: {endpoint} {params}")
    if resp.status_code != 200:
        raise NpoError(f"NPO API {endpoint} failed (status={resp.status_code}).")
    data = resp.json()
    if not isinstance(data, (dict, list)):
        raise NpoError(f"Not found on NPO Start: {endpoint} {params}")
    return data


def first_number(value) -> int | None:
    match = re.search(r"\d+", str(value or ""))
    return int(match.group()) if match else None


def build_filename(program: dict) -> str:
    """'Serie - S07E01 - Titel', falling back to the slug when data is missing."""
    series = (program.get("series") or {}).get("title")
    season = first_number((program.get("season") or {}).get("seasonKey"))
    number = first_number(program.get("programKey"))
    title = program.get("title") or ""

    if series and season is not None and number is not None:
        parts = [series, f"S{season:02d}E{number:02d}"]
        if title and title != series:
            parts.append(title)
        name = " - ".join(parts)
    else:
        name = title if title and not series else program["slug"]

    # Characters that are illegal in filenames or special to yt-dlp templates.
    return re.sub(r'[/\\?%*:|"<>]', "#", name).strip()


def to_episode(program: dict) -> Episode:
    restrictions = program.get("restrictions") or []
    plus_only = bool(restrictions) and not any(
        r.get("subscriptionType") == "free" for r in restrictions
    )
    return Episode(
        product_id=program["productId"],
        slug=program["slug"],
        filename=build_filename(program),
        plus_only=plus_only,
    )


def get_season_episodes(session: Session, season: dict) -> list[Episode]:
    programs = api_get(session, "programs-by-season", guid=season["guid"])
    programs.sort(key=lambda p: first_number(p.get("programKey")) or 0)
    return [to_episode(p) for p in programs]


def resolve_episodes(session: Session, npo_url: str) -> list[Episode]:
    """
    Turn an NPO Start URL into the list of episodes it refers to. Supported:
      /start/afspelen/<episode>
      /start/serie/<series>[/afleveringen]
      /start/serie/<series>[/afleveringen]/<season>
      /start/serie/<series>/<season>/<episode>[/afspelen]
    """
    parts = [p for p in urlparse(npo_url).path.split("/") if p]
    if parts[:1] == ["start"]:
        parts = parts[1:]
    if parts and parts[-1] == "afspelen" and len(parts) > 1:
        parts = parts[:-1]

    if len(parts) == 2 and parts[0] in ("afspelen", "video"):
        return [to_episode(api_get(session, "program-detail", slug=parts[1]))]

    if len(parts) >= 2 and parts[0] == "serie":
        series_slug = parts[1]
        rest = [p for p in parts[2:] if p != "afleveringen"]

        if len(rest) >= 2:
            return [to_episode(api_get(session, "program-detail", slug=rest[1]))]

        seasons = api_get(session, "series-seasons", slug=series_slug)
        if rest:
            seasons = [s for s in seasons if s.get("slug") == rest[0]]
            if not seasons:
                raise NpoError(f"Season '{rest[0]}' not found for '{series_slug}'.")
        seasons.sort(key=lambda s: first_number(s.get("seasonKey")) or 0)

        episodes = []
        for season in seasons:
            episodes.extend(get_season_episodes(session, season))
        return episodes

    raise NpoError(f"Unsupported NPO Start URL: {npo_url}")


# --------------------------------------------------------------------------
# Login and stream info
# --------------------------------------------------------------------------

def form_value(soup: BeautifulSoup, name: str) -> str:
    field = soup.find("input", {"name": name})
    if not field or field.get("value") is None:
        raise NpoError(f"Login failed: field '{name}' missing from NPO response.")
    return field.get("value")


def npo_login(session: Session, mail: str, password: str) -> None:
    """Logs the session in to NPO ID and NPO Start."""
    url = "https://id.npo.nl/account/login"
    resp = session.get(url)
    if resp.status_code != 200:
        raise NpoError(f"Failed to get login page (status={resp.status_code}).")

    token = form_value(BeautifulSoup(resp.text, "html.parser"),
                       "__RequestVerificationToken")
    login = session.post(url, data={
        "__RequestVerificationToken": token,
        "EmailAddress": mail,
        "Password": password,
    })
    if login.status_code != 200:
        raise NpoError(f"Login failed (status={login.status_code}).")
    if "profiel.npo.nl/callback" not in login.text:
        raise NpoError("Login failed. Please check your credentials.")

    soup = BeautifulSoup(login.text, "html.parser")
    session.post("https://profiel.npo.nl/callback", data={
        name: form_value(soup, name)
        for name in ("code", "scope", "state", "session_state", "iss")
    })

    profile = session.get("https://profiel.npo.nl/dashboard")
    if mail.lower() not in profile.text.lower():
        raise NpoError("Login failed. Please check your credentials.")

    # Sign the NPO ID in to NPO Start and follow the redirects for its cookies.
    csrf = session.get("https://npo.nl/start/api/auth/csrf").json()
    signin = session.post("https://npo.nl/start/api/auth/signin/npo-id", data={
        "callbackUrl": "https://npo.nl/start/",
        "csrfToken": csrf["csrfToken"],
        "json": "true",
    }).json()
    session.get(signin["url"], allow_redirects=True)

    print("Successfully logged in to NPO.")


def get_player_token(session: Session, product_id: str) -> str:
    resp = session.get(f"{API_BASE}/player-token", params={"productId": product_id})
    if resp.status_code != 200:
        raise NpoError(f"Failed to get player token (status={resp.status_code}).")
    jwt = resp.json().get("jwt")
    if not jwt:
        raise NpoError("JWT not found in player-token response.")
    return jwt


def get_stream(session: Session, episode: Episode) -> dict:
    """Returns the 'stream' object (streamURL, drm, ...) for an episode."""
    jwt = get_player_token(session, episode.product_id)
    resp = session.post(
        STREAM_LINK_URL,
        headers={
            "Authorization": jwt,
            "Origin": "https://npo.nl",
            "Referer": "https://npo.nl/",
        },
        json={
            "profileName": "dash",
            "drmType": "widevine",
            "referrerUrl": episode.url,
        },
    )
    if resp.status_code == 402:
        raise NpoError("This is NPO Plus content; set NPO_MAIL and NPO_PASS "
                       "of an account with a Plus subscription.")
    if resp.status_code == 451:
        raise NpoError("NPO does not allow this programme from your location.")
    if resp.status_code != 200:
        raise NpoError(f"Failed to get stream info (status={resp.status_code}).")

    stream = resp.json().get("stream") or {}
    if not stream.get("streamURL"):
        raise NpoError("No stream URL in stream-link response.")
    return stream


# --------------------------------------------------------------------------
# DRM
# --------------------------------------------------------------------------

def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_mpd(mpd_xml: str) -> tuple[str, dict[str, str]]:
    """
    Returns (pssh, kids) from a DASH manifest. The PSSH is taken from the
    ContentProtection element with the Widevine scheme id, wherever it sits.
    kids maps 'video'/'audio' to the default_KID (hex, no dashes) of that track.
    """
    pssh = ""
    kids: dict[str, str] = {}
    root = ET.fromstring(mpd_xml)

    for adaptation in root.iter():
        if local_name(adaptation.tag) != "AdaptationSet":
            continue
        kind = (adaptation.get("contentType")
                or (adaptation.get("mimeType") or "").split("/")[0])
        for protection in adaptation.iter():
            if local_name(protection.tag) != "ContentProtection":
                continue
            for attr, value in protection.attrib.items():
                if local_name(attr) == "default_KID" and kind:
                    kids.setdefault(kind, value.replace("-", "").lower())
            if (protection.get("schemeIdUri") or "").lower() == WIDEVINE_SCHEME:
                for child in protection:
                    if local_name(child.tag) == "pssh" and child.text and not pssh:
                        pssh = child.text.strip()
    return pssh, kids


def get_widevine_keys(pssh: str, license_url: str, api_key: str,
                      custom_data: str = "") -> list[str]:
    """
    Gets the content keys ('kid:key' strings) through getwvkeys.cc:
      1) POST the pssh; a cached result returns the keys right away,
         otherwise we get a license challenge and a session id.
      2) POST the challenge to the license server.
      3) POST the license back to getwvkeys.cc to receive the keys.
    """
    api_headers = {"Content-Type": "application/json", "X-API-Key": api_key}
    license_headers = {"User-Agent": USER_AGENT}
    if custom_data:
        api_headers["x-custom-data"] = custom_data
        license_headers["x-custom-data"] = custom_data

    payload = {"pssh": pssh, "license_url": license_url,
               "buildInfo": "", "force": False}

    def keys_from(data: dict) -> list[str]:
        keys = [k["key"] for k in data.get("keys") or [] if k.get("key")]
        if not keys:
            raise NpoError("getwvkeys.cc returned no keys.")
        return keys

    r1 = requests.post(GETWVKEYS_URL, headers=api_headers, json=payload,
                       timeout=REQUEST_TIMEOUT)
    if r1.status_code != 200:
        raise NpoError(f"getwvkeys.cc error (status={r1.status_code}): "
                       f"{r1.text[:200]}")
    data = r1.json()
    if "x-cache" in r1.headers:
        return keys_from(data)
    if "challenge" not in data or "session_id" not in data:
        raise NpoError("Unexpected getwvkeys.cc response (no challenge).")

    r2 = requests.post(license_url, headers=license_headers,
                       data=base64.b64decode(data["challenge"]),
                       timeout=REQUEST_TIMEOUT)
    if r2.status_code != 200:
        raise NpoError(f"License server error (status={r2.status_code}): "
                       f"{r2.text[:200]}")

    payload.update(session_id=data["session_id"],
                   response=base64.b64encode(r2.content).decode())
    r3 = requests.post(GETWVKEYS_URL, headers=api_headers, json=payload,
                       timeout=REQUEST_TIMEOUT)
    if r3.status_code != 200:
        raise NpoError(f"getwvkeys.cc error on final step "
                       f"(status={r3.status_code}): {r3.text[:200]}")
    return keys_from(r3.json())


def get_keys(session: Session, stream: dict, episode: Episode,
             download_dir: Path, api_key: str) -> tuple[list[str], dict[str, str]]:
    """Returns (keys, kids) for a stream; keys is empty when there is no DRM."""
    mpd = session.get(stream["streamURL"])
    if mpd.status_code != 200:
        raise NpoError(f"Failed to get manifest (status={mpd.status_code}).")
    pssh, kids = parse_mpd(mpd.text)
    debug("PSSH:", pssh or "(none)")

    drm = stream.get("drm") or {}
    drm_token = stream.get("drmToken") or ""
    if not pssh:
        if drm or drm_token:
            raise NpoError("Stream is DRM protected but no Widevine PSSH "
                           "was found in the manifest.")
        return [], kids

    cache_file = download_dir / "keys" / f"{episode.filename}.json"
    if cache_file.is_file():
        cached = json.loads(cache_file.read_text())
        if cached.get("pssh") == pssh and cached.get("keys"):
            debug("Using cached keys from", cache_file)
            return cached["keys"], kids

    if not api_key:
        raise NpoError("This video is DRM protected: set GETWVKEYS_API_KEY in "
                       ".env (key from https://getwvkeys.cc/me).")

    if drm.get("licenseUrl"):
        keys = get_widevine_keys(pssh, drm["licenseUrl"], api_key)
    elif drm_token:
        keys = get_widevine_keys(pssh, LEGACY_LICENSE_URL, api_key, drm_token)
    else:
        keys = get_widevine_keys(pssh, DEFAULT_LICENSE_URL, api_key)

    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps({"pssh": pssh, "keys": keys}))
    return keys, kids


def pick_key(keys: list[str], kid: str | None) -> str | None:
    """Returns the bare key for a track, matching on KID when there are several."""
    if not keys:
        return None
    for entry in keys:
        entry_kid, _, key = entry.partition(":")
        if kid and key and entry_kid.replace("-", "").lower() == kid:
            return key
    return keys[0].rpartition(":")[2]


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------

def run(command: list[str]) -> None:
    """Runs a command with live output and raises if it fails."""
    debug("Running:", " ".join(command))
    result = subprocess.run(command)
    if result.returncode != 0:
        raise NpoError(f"{command[0]} failed (exit code {result.returncode}).")


def track_kind(path: Path) -> str:
    """'video' or 'audio', by asking ffprobe what the file contains."""
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "stream=codec_type",
         "-of", "csv=p=0", str(path)],
        capture_output=True, text=True,
    ).stdout
    return "video" if "video" in out else "audio"


def download(stream_url: str, filename: str, keys: list[str],
             kids: dict[str, str], download_dir: Path) -> Path:
    download_dir.mkdir(parents=True, exist_ok=True)
    prefix = f"{ENCRYPTED_PREFIX}{filename}."

    args = ["yt-dlp", "--allow-unplayable-formats", "-f", "bv,ba",
            "-P", str(download_dir),
            "-o", f"{prefix}f%(format_id)s.%(ext)s"]
    if shutil.which("aria2c"):
        args += ["--downloader", "aria2c"]
    run(args + [stream_url])

    parts = sorted(
        p for p in download_dir.iterdir()
        if p.name.startswith(prefix)
        and p.suffix not in (".part", ".ytdl", ".aria2")
    )
    if not parts:
        raise NpoError("yt-dlp finished but no downloaded files were found.")

    # Mux (and decrypt) into a temp file so a failed run never looks finished.
    target = download_dir / f"{filename}.mkv"
    temp = download_dir / f"{filename}.part.mkv"
    args = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-stats", "-y"]
    for part in parts:
        key = pick_key(keys, kids.get(track_kind(part)))
        if key:
            args += ["-decryption_key", key]
        args += ["-i", str(part)]
    for index in range(len(parts)):
        args += ["-map", str(index)]
    try:
        run(args + ["-c", "copy", str(temp)])
    except NpoError:
        temp.unlink(missing_ok=True)
        raise
    temp.replace(target)

    for part in parts:
        part.unlink()
    return target


def process_episode(session: Session, episode: Episode, args,
                    download_dir: Path, api_key: str) -> str:
    """Handles one episode; returns 'done' or 'skipped'."""
    target = download_dir / f"{episode.filename}.mkv"
    if not args.keys_only and target.is_file():
        print("  Already downloaded, skipping.")
        return "skipped"

    stream = get_stream(session, episode)
    debug("Stream URL:", stream["streamURL"])
    keys, kids = get_keys(session, stream, episode, download_dir, api_key)

    if args.keys_only:
        for key in keys:
            print(f"  {key}")
        if not keys:
            print("  No DRM.")
        return "done"

    debug("Keys:", keys)
    path = download(stream["streamURL"], episode.filename, keys, kids,
                    download_dir)
    print(f"  Saved {path}")
    return "done"


def main() -> int:
    global VERBOSE

    parser = argparse.ArgumentParser(
        description="Download an episode, season or series from NPO Start.")
    parser.add_argument("url", help="NPO Start URL of an episode, season or series")
    parser.add_argument("-o", "--output", help="download directory "
                        "(default: DOWNLOAD_DIR from .env, or 'npovideos')")
    parser.add_argument("-k", "--keys-only", action="store_true",
                        help="only print the DRM keys, do not download")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print stream URLs, PSSH, keys and commands")
    args = parser.parse_args()
    VERBOSE = args.verbose

    download_dir = Path(args.output or env("DOWNLOAD_DIR") or "npovideos")
    # VWKEYS_API_KEY is the name older versions of this script used.
    api_key = env("GETWVKEYS_API_KEY") or env("VWKEYS_API_KEY")

    if not args.keys_only:
        missing = [t for t in ("yt-dlp", "ffmpeg", "ffprobe") if not shutil.which(t)]
        if missing:
            print(f"Error: {', '.join(missing)} not found; please install.")
            return 1

    failed = 0
    with Session() as session:
        try:
            episodes = resolve_episodes(session, args.url)
            if not episodes:
                raise NpoError("No episodes found for this URL.")
            print(f"Found {len(episodes)} episode(s).")

            mail, password = env("NPO_MAIL"), env("NPO_PASS")
            logged_in = False
            if mail and password:
                try:
                    npo_login(session, mail, password)
                    logged_in = True
                except (NpoError, requests.RequestException, KeyError,
                        ValueError) as e:
                    print(f"Warning: continuing without login: {e}")
            if not logged_in:
                # Anonymous sessions need the next-auth cookies as well.
                session.get("https://npo.nl/start/api/auth/session")
        except (NpoError, requests.RequestException) as e:
            print("Error:", e)
            return 1

        for number, episode in enumerate(episodes, 1):
            print(f"[{number}/{len(episodes)}] {episode.filename}")
            if episode.plus_only and not logged_in:
                print("  NPO Plus only and not logged in, skipping.")
                failed += 1
                continue
            try:
                process_episode(session, episode, args, download_dir, api_key)
            except (NpoError, requests.RequestException) as e:
                print("  Error:", e)
                failed += 1

    if failed:
        print(f"{failed} of {len(episodes)} episode(s) failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
