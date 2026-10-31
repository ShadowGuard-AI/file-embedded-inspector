import argparse
import logging
import sys
import os
import zipfile
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: An argument parser object.
    """
    parser = argparse.ArgumentParser(description="Scans files for embedded objects and reports their presence and type.")
    parser.add_argument("file_path", type=str, help="Path to the file to be analyzed.")
    return parser

SIGNATURES = {
    "ZIP": b"PK\x03\x04",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "JPEG": b"\xff\xd8\xff",
    "GIF": b"GIF8",
    "PDF": b"%PDF",
    "MZ": b"MZ",
}

CHUNK_SIZE = 4096


def find_embedded_signatures(file_path):
    """Scan a file for known signatures, overlapping chunk reads so a
    signature straddling a chunk boundary is still found.

    Returns a list of (offset, type name) pairs, in offset order.
    """
    longest = max(len(sig) for sig in SIGNATURES.values())
    overlap = longest - 1
    found = {}
    buffer = b""
    buffer_start = 0
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            buffer = buffer + chunk
            for name, sig in SIGNATURES.items():
                pos = buffer.find(sig)
                while pos != -1:
                    found[buffer_start + pos] = name
                    pos = buffer.find(sig, pos + 1)
            if len(buffer) > overlap:
                drop = len(buffer) - overlap
                buffer = buffer[drop:]
                buffer_start += drop
    return sorted(found.items())


def detect_hidden_files(file_path):
    """
    Detects if a file path represents a hidden file on Unix-like systems or Windows.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file is hidden, False otherwise.
    """
    path = Path(file_path)
    
    if os.name == 'nt': #windows
        if path.parts[-1].startswith("."):
            return True
        try:
            import ctypes
            FILE_ATTRIBUTE_HIDDEN = 0x02
            attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attributes & FILE_ATTRIBUTE_HIDDEN:
                return True
        except Exception as e:
            logging.error(f"Error detecting hidden file on windows: {e}")
    
    elif os.name == 'posix': #unix-like
        if path.parts[-1].startswith("."):
            return True
    
    return False

def main():
    parser = setup_argparse()
    args = parser.parse_args()
    file_path = args.file_path

    if not file_path:
        logging.error("File path is required.")
        sys.exit(1)

    if not os.path.exists(file_path):
        logging.error(f"File does not exist: {file_path}")
        sys.exit(1)

    if not os.path.isfile(file_path):
        logging.error(f"Not a file: {file_path}")
        sys.exit(1)

    if os.path.getsize(file_path) == 0:
        logging.error(f"File is empty, nothing to inspect: {file_path}")
        sys.exit(1)

    logging.info(f"Analyzing file: {file_path}")

    try:
        hits = find_embedded_signatures(file_path)
    except Exception as e:
        logging.error(f"Error checking file for embedded content: {e}")
        sys.exit(1)

    embedded = []
    for offset, name in hits:
        if offset == 0:
            logging.info(f"File type: {name} (signature at offset 0, the file's own type, not embedded content)")
        else:
            embedded.append((offset, name))
            logging.warning(f"Detected an embedded {name} signature at offset {offset} in: {file_path}")

    hidden = detect_hidden_files(file_path)
    if hidden:
        logging.warning(f"Detected a hidden file: {file_path}")

    if not embedded and not hidden:
        logging.info(f"No embedded objects detected in: {file_path}")


if __name__ == "__main__":
    # Usage Example:
    # Create a dummy file for testing with an embedded ZIP archive:
    # echo "This is a test file with a ZIP archive" > test_file.txt
    # printf 'PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00test.txt\x01\x00\t\x00\x00\x00test\x03\x00\x00\x00' >> test_file.txt

    # Example 1: Running from the command line to detect an embedded zip
    # python main.py test_file.txt

    # Example 2: Running from command line to check normal file (no hidden/zip)
    # python main.py another_file.txt

    # Example 3: Running from command line to detect a hidden file
    # python main.py .hidden_file.txt
    # touch .hidden_file.txt

    # Example 4: Checking a non existent file
    # python main.py non_existent_file.txt

    main()