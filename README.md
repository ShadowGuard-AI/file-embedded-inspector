![Banner](banner.png)

# file-embedded-inspector
Scans files for embedded objects (e.g., ZIP archives within documents, hidden files) and reports their presence and type. - Focused on File operations and analysis

## Signature set

The scan searches for exactly these signatures and reports them by these type names:

- ZIP: `PK` followed by bytes 03 04
- PNG: the 8 byte PNG header
- JPEG: bytes FF D8 FF
- GIF: `GIF8`
- PDF: `%PDF`
- MZ: `MZ`

Chunk reads overlap by at least the longest signature length minus one byte, so a signature straddling a chunk boundary is still detected.

## Notes

- A signature at offset 0 is reported as the file's own type, not as embedded content.
- A missing file exits 1. An empty file exits 1 with a plain line and is never reported clean.


## Install
`git clone https://github.com/ShadowStrikeHQ/file-embedded-inspector`

## Usage
`./file-embedded-inspector [params]`

## Parameters
- `-h`: Show help message and exit

## License
Copyright (c) ShadowStrikeHQ
