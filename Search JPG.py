import pytesseract
from PIL import Image
import os

# --- CONFIGURATION ---

pytesseract.pytesseract.tesseract_cmd = r'/opt/homebrew/bin/tesseract'

# Path to the folder containing your .jpg files
IMAGE_FOLDER = r'/Users/mannyfernandez/Desktop/Receipts'
#IMAGE_FOLDER = r'/Users/fernandezm/Desktop/OldReceipts'

# The text you want to search for (supports special chars like $)
SEARCH_TERM = "58.27"



# WINDOWS ONLY: If you get a "Tesseract not found" error, uncomment the line below
# and update the path to where you installed Tesseract.
# pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# ---------------------

def search_text_in_images(folder_path, term):
    print(f"--- Starting Search for '{term}' ---\n")
    
    # Verify folder exists
    if not os.path.exists(folder_path):
        print(f"Error: The folder '{folder_path}' does not exist.")
        return

    files_found = 0
    
    # Loop through every file in the directory
    for filename in os.listdir(folder_path):
        # Check if the file is a JPG image (case insensitive check)
        if filename.lower().endswith((".jpg", ".jpeg")):
            file_path = os.path.join(folder_path, filename)
            
            try:
                # Open the image using Pillow
                with Image.open(file_path) as img:
                    # Extract text from image
                    # explicit config can help with symbols, but default is usually fine
                    text = pytesseract.image_to_string(img)
                    
                    # specific check: Convert both to lower case for insensitive search
                    # BUT keep the symbol integrity.
                    if term.lower() in text.lower():
                        print(f"[MATCH FOUND] Found in file: {filename}")
                        # Optional: Print the context or line where it was found
                        # print(f"   Context: {text.strip()[:50]}...") 
                        files_found += 1
                    else:
                        # Optional: print scanned files to track progress
                        # print(f"[Scanned] {filename} - No match")
                        pass

            except Exception as e:
                print(f"Could not process {filename}: {e}")

    print(f"\n--- Search Complete. Matches found in {files_found} files. ---")

if __name__ == "__main__":
    search_text_in_images(IMAGE_FOLDER, SEARCH_TERM)
