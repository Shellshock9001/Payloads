# Ransomware Simulator – File Encryption & Decryption  

## About  
This project demonstrates file encryption and decryption using Python 3. It simulates how ransomware locks files, making them unreadable until the correct password is provided.  
**For educational purposes only. Do NOT use on important files.**  

## Disclaimer  
Do NOT encrypt files you do not own.  
Encrypted files will remain locked unless decrypted with the correct password.  
This tool is for ethical hacking education only.  

## Dependencies & Installation  
This script requires Python 3 and the following libraries: cryptography (for encryption), colorama (for colorful output), tqdm (for progress bars).  
To install them, run: ``` pip install cryptography colorama tqdm ```
## Important Setup Step (Before Running the Script)  
1. Open `ransomware_simulator.py` in a text editor and **change the secret passphrase** to something unique.  
2. Find this line in the script:  
   `SECRET_PASSPHRASE = "Release the prisoners"`  
3. Edit `"Release the prisoners"` and set your own **strong passphrase**.  
4. **This script encrypts entire directories, NOT single files.** You must provide a folder path, and every file inside will be encrypted.  

## How to Use (Step-by-Step)  

1. **Prepare a test folder**  
   - Create a folder with sample files to encrypt (DO NOT use important files).  
   - Example: mkdir ~/Desktop/test && cp ~/somefile.txt ~/Desktop/test  

2. **Encrypt an Entire Folder**  
   - Run: python3 ransomware_simulator.py encrypt ~/Desktop/test  
   - The script will:  
     - Scan the folder and list all files found  
     - Display: "Scanning directory: /path/to/folder"  
     - Encrypt each file, showing: "Encrypting: filename.txt"  
     - Once complete, it will display: "Encryption complete!"  

3. **Verify Encryption**  
   - Try opening a file. You will see random unreadable data because it is encrypted.  

4. **Decrypt an Entire Folder**  
   - Run: python3 ransomware_simulator.py decrypt ~/Desktop/test  
   - The script will:  
     - Scan for encrypted files  
     - Ask: "Enter the passphrase to unlock your files:"  
     - If correct, it will display: "Decrypting: filename.txt" and restore the files  
     - If the wrong passphrase is entered, an error will appear: "Incorrect passphrase. Decryption aborted!"  

5. **Verify Decryption**  
   - Open the files again. If decrypted successfully, they will be restored to their original readable format.  

## How Encryption & Decryption Work  

Encryption:  
- The script scans the **entire folder** for files.  
- Uses a password to create an encryption key.  
- Encrypts **each file inside the folder**, making them unreadable.  
- Overwrites the original files with encrypted versions.  

Decryption:  
- The script scans for **all encrypted files in the folder**.  
- Asks for the correct password.  
- Uses the key to restore the original files.  

📢 **Important:** If you forget the passphrase, you **CANNOT** recover your files.  

## Color Guide (What You Will See)  

- Blue – Information (scanning, checking directories)  
- Cyan – Steps explained  
- Yellow – Encryption in progress  
- Green – Decryption success  
- Red – Errors and warnings  
- Magenta – Completed actions  

## Warnings  

- If you lose the passphrase, files are permanently locked.  
- Do NOT encrypt system files – this can break your OS.  
- Test this script ONLY on files you can afford to lose.  
- This script only works on **entire directories**, not individual files.  

## Troubleshooting  

- **Files are unreadable after encryption** → They are encrypted. Run the decrypt command and enter the correct passphrase.  
- **I lost the passphrase. Can I recover my files?** → No, encryption is one-way. Without the passphrase, files are permanently locked.  
- **"No files found for encryption/decryption" error** → Ensure the folder has files and that they haven’t been renamed manually.  
- **I want to encrypt a single file** → The script only works on full directories. Put the file inside a folder and encrypt that folder.  

## Contributing  
Fork this repository and submit a pull request if you’d like to improve it.  

## License  
MIT License – For educational use only.  
