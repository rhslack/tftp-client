# TFTP Client

Simple and Powerful TFTP Client.

## Features
- **RFC Support**: 
    - Negotiation Options (RFC 2347)
    - Block Size Option (RFC 2348)
    - Timeout Option (RFC 2349)

## Installation

Using [PDM](https://pdm.fming.dev/):

```bash
pdm install
```

Or install it as a tool:

```bash
pip install .
```

## Usage

### Download a file
```bash
tftp-client get <host> <filename> --blksize 1024 --timeout 10
```

### Upload a file
```bash
tftp-client put <host> <filename> --mode netascii
```

## Options
- `--port`: TFTP server port (default: 69)
- `--blksize`: Block size in bytes (RFC 2348)
- `--timeout`: Timeout in seconds (RFC 2349)
- `--mode`: Transfer mode (`octet` or `netascii`)
- `--output`: (Only for `get`) Output filename

## License
MIT
