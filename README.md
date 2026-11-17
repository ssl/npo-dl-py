# npo-dl-py

A command-line tool for saving programmes from NPO Start as `.mkv` files. Give it a link to an episode, a season or a whole series and it downloads everything in the best available quality.

## Features

- Download a single episode, a whole season or a complete series.
- Downloads the best available video and audio quality into one `.mkv`.
- Optional login for NPO Plus content.
- DRM keys are cached in `<download dir>/keys`, or printed with `--keys-only`.

## Installation

Make sure **ffmpeg** and **yt-dlp** are installed. Use `brew`, `apt` or `winget` to install these. **aria2c** is optional and is used for faster downloads when present. Python 3.10 or newer is required.

1. Clone the repository:
    ```bash
    git clone https://github.com/ssl/npo-dl-py.git
    ```
2. Navigate to the project directory:
    ```bash
    cd npo-dl-py
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Make the env file
    ```bash
    cp .env.example .env
    ```
5. Enter your key from https://getwvkeys.cc/me as `GETWVKEYS_API_KEY` in the env file. Videos without DRM download without a key.

6. To download 'Plus' videos, enter your NPO credentials in the env file.

## Usage

Run the script with an NPO Start link to an episode, a season or a series:
```bash
python npo-dl.py https://npo.nl/start/afspelen/<episode>
python npo-dl.py https://npo.nl/start/serie/<series>/afleveringen/<season>
python npo-dl.py https://npo.nl/start/serie/<series>
```

Options:

| Option | Description |
| --- | --- |
| `-o`, `--output DIR` | Download directory (default: `DOWNLOAD_DIR` from the env file, or `npovideos`) |
| `-k`, `--keys-only` | Only print the DRM keys, do not download |
| `-v`, `--verbose` | Print stream URLs, PSSH, keys and the commands that are run |

Files are saved as `Series - S01E02 - Title.mkv`. Episodes that already exist are skipped, and the exit code is non-zero when an episode fails.