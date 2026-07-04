#!/usr/bin/env python3
"""
SearchJPG.py - Self-contained OCR receipt search.

Just run it:

    python3 SearchJPG.py

On the first run it builds its own private Python environment next to this
file (a hidden .venv folder), installs everything it needs, and re-launches
itself inside that environment. You are never asked to set up pip, a venv, or
"break system packages." After that first run, startup is fast.

It also checks that the Tesseract OCR engine is installed and offers to
install it for you (Homebrew on macOS, apt on Linux).

Then it asks you what to search for. Type a store name, a dollar amount like
54.99, a card's last four digits, whatever appears on the receipt. It reads
every image once, remembers the text, and lets you run as many searches as you
want without re-reading the images each time.
"""

import os
import sys
import subprocess
import shutil

# --- CONFIGURATION -----------------------------------------------------------

# Default folder to search. You can accept this at the prompt by pressing Enter,
# or type a different path when it asks.
DEFAULT_IMAGE_FOLDER = r'/Users/mannyfernandez/Desktop/F1Receipts'

# Image types to read. Add or remove extensions as needed.
IMAGE_EXTENSIONS = ('.jpg', '.jpeg', '.png', '.tif', '.tiff', '.bmp', '.gif')

# Where the private environment lives (hidden folder next to this script).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(SCRIPT_DIR, '.venv')

# Python packages the script installs into its private environment.
# pillow-heif is optional and adds support for iPhone .heic photos.
REQUIRED_PACKAGES = ['pytesseract', 'Pillow']
OPTIONAL_PACKAGES = ['pillow-heif']

# -----------------------------------------------------------------------------


def venv_python():
    """Path to the Python interpreter inside our private environment."""
    if os.name == 'nt':
        return os.path.join(VENV_DIR, 'Scripts', 'python.exe')
    return os.path.join(VENV_DIR, 'bin', 'python')


def in_our_venv():
    """True if we are already running inside the environment we created."""
    return os.path.abspath(sys.prefix) == os.path.abspath(VENV_DIR)


def bootstrap_environment():
    """Create the private environment, install packages, then re-launch here."""
    if in_our_venv():
        return  # Already inside it. Nothing to do.

    just_created = False
    if not os.path.exists(venv_python()):
        print("First-time setup: building a self-contained environment...")
        subprocess.check_call([sys.executable, '-m', 'venv', VENV_DIR])
        just_created = True

    if just_created:
        print("Installing required packages. This happens only once...")
        subprocess.check_call([venv_python(), '-m', 'pip', 'install',
                               '--upgrade', 'pip', '--quiet'])
        subprocess.check_call([venv_python(), '-m', 'pip', 'install', '--quiet']
                              + REQUIRED_PACKAGES)
        # Optional packages: try, but do not fail the whole setup if unavailable.
        try:
            subprocess.check_call([venv_python(), '-m', 'pip', 'install',
                                   '--quiet'] + OPTIONAL_PACKAGES)
        except subprocess.CalledProcessError:
            print("Note: optional HEIC support could not be installed. "
                  "Continuing without it.")
        print("Setup complete.\n")

    # Re-launch this same script using the private environment's Python.
    os.execv(venv_python(),
             [venv_python(), os.path.abspath(__file__)] + sys.argv[1:])


# Build/enter the environment before importing anything that needs installing.
bootstrap_environment()

# From here down we are guaranteed to be inside the private environment.
try:
    import pytesseract
    from PIL import Image
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet']
                          + REQUIRED_PACKAGES)
    import pytesseract
    from PIL import Image

# Register HEIC support if the optional package installed successfully.
try:
    import pillow_heif
    pillow_heif.register_heif_opener()
    if '.heic' not in IMAGE_EXTENSIONS:
        IMAGE_EXTENSIONS = IMAGE_EXTENSIONS + ('.heic',)
except ImportError:
    pass


def find_tesseract():
    """Locate the Tesseract engine, checking PATH and common install paths."""
    found = shutil.which('tesseract')
    if found:
        return found
    candidates = [
        '/opt/homebrew/bin/tesseract',   # macOS, Apple Silicon
        '/usr/local/bin/tesseract',      # macOS, Intel
        '/usr/bin/tesseract',            # Linux
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def ensure_tesseract():
    """Return a path to Tesseract, offering to install it if it is missing."""
    path = find_tesseract()
    if path:
        return path

    print("The Tesseract OCR engine is not installed.")

    brew = shutil.which('brew')
    apt = shutil.which('apt-get')

    if brew:
        answer = input("Install it now with Homebrew? [Y/n]: ").strip().lower()
        if answer in ('', 'y', 'yes'):
            subprocess.check_call([brew, 'install', 'tesseract'])
            return find_tesseract()
    elif apt:
        answer = input("Install it now with apt (may prompt for sudo)? "
                       "[Y/n]: ").strip().lower()
        if answer in ('', 'y', 'yes'):
            subprocess.check_call(['sudo', 'apt-get', 'update'])
            subprocess.check_call(['sudo', 'apt-get', 'install', '-y',
                                   'tesseract-ocr'])
            return find_tesseract()
    else:
        print("Could not find a package manager to install Tesseract.")
        print("On macOS: install Homebrew from https://brew.sh, then run "
              "'brew install tesseract'.")

    return None


def read_all_images(folder):
    """OCR every image in the folder once and return {filename: text}."""
    if not os.path.exists(folder):
        print(f"Error: the folder '{folder}' does not exist.")
        return None

    filenames = sorted(
        f for f in os.listdir(folder)
        if f.lower().endswith(IMAGE_EXTENSIONS)
    )

    if not filenames:
        print(f"No image files found in '{folder}'.")
        return {}

    print(f"\nReading {len(filenames)} image(s). Please wait...\n")
    cache = {}
    for i, filename in enumerate(filenames, start=1):
        file_path = os.path.join(folder, filename)
        print(f"  [{i}/{len(filenames)}] {filename}", end="", flush=True)
        try:
            with Image.open(file_path) as img:
                cache[filename] = pytesseract.image_to_string(img)
            print("  ok")
        except Exception as e:
            cache[filename] = ""
            print(f"  could not read ({e})")

    print("\nDone reading. You can now search as many times as you like.")
    return cache


def search_cache(cache, term):
    """Search already-read text for a term and print matches with context."""
    term_lower = term.lower()
    matches = 0

    print(f"\n--- Results for '{term}' ---")
    for filename, text in cache.items():
        if term_lower in text.lower():
            matches += 1
            print(f"\n[MATCH] {filename}")
            # Show the lines that contain the term so you can see the context.
            for line in text.splitlines():
                if term_lower in line.lower():
                    cleaned = line.strip()
                    if cleaned:
                        print(f"    > {cleaned}")

    print(f"\n--- Found in {matches} file(s). ---")


def main():
    tess_path = ensure_tesseract()
    if not tess_path:
        print("Cannot continue without Tesseract. Exiting.")
        sys.exit(1)
    pytesseract.pytesseract.tesseract_cmd = tess_path

    # Ask which folder to search, defaulting to the configured one.
    prompt = f"Folder to search [{DEFAULT_IMAGE_FOLDER}]: "
    folder = input(prompt).strip() or DEFAULT_IMAGE_FOLDER

    cache = read_all_images(folder)
    if not cache:
        return

    # Interactive search loop.
    while True:
        term = input("\nSearch for (blank to quit): ").strip()
        if not term:
            print("Goodbye.")
            break
        search_cache(cache, term)


if __name__ == "__main__":
    main()
