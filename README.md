# npo-dl-py

npo-dl-py is a Python-based tool for downloading media from NPO (Nederlandse Publieke Omroep). Inspired by [Ewoodss/npo-dl](https://github.com/Ewoodss/npo-dl)

## Features

- Download all videos from NPO.
- Support for multiple formats and resolutions.
- Easy-to-use command-line interface.

## Installation

Make sure **ffmpeg** and **yt-dlp** are installed. Use `brew`, `apt` or `winget` to install these.

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
5. Enter your key from https://getwvkeys.cc in the env file.

6. To download 'Plus' videos, enter your NPO credentials in the env file.

## Usage

Run the script with NPO Start 'afspelen' link:
```bash
python npo-dl.py <npo_url>
```