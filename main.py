import argparse
import logging
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

def is_zip_file_embedded(file_path):
    """
    Checks if a file contains a ZIP archive embedded within it.

    Args:
        file_path (str): Path to the file to check.

    Returns:
        bool: True if a ZIP archive is found, False otherwise.
    """
    try:
        with open(file_path, 'rb') as f:
            # Read the file in chunks to handle large files
            chunk_size = 4096
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if b"PK\x03\x04" in chunk:  # ZIP file signature
                   return True
            
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return False
    except Exception as e:
        logging.error(f"Error checking file for embedded zip: {e}")
        return False
    return False


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
    """
    Main function to execute the file embedded inspector.
    """
    parser = setup_argparse()
    args = parser.parse_args()
    file_path = args.file_path

    # Input validation
    if not file_path:
        logging.error("File path is required.")
        return

    if not os.path.exists(file_path):
         logging.error(f"File does not exist: {file_path}")
         return

    logging.info(f"Analyzing file: {file_path}")

    # Check for embedded ZIP archives
    if is_zip_file_embedded(file_path):
        logging.warning(f"Detected an embedded ZIP archive in: {file_path}")

    # Check for hidden file
    if detect_hidden_files(file_path):
        logging.warning(f"Detected a hidden file: {file_path}")
    

    if not is_zip_file_embedded(file_path) and not detect_hidden_files(file_path):
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