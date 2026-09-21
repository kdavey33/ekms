# EKMS v2 - Encryption Key Management System

Welcome to the Encryption Key Management System (EKMS) version 2! 

EKMS is a homegrown, completely offline Python application designed to give you absolute control over the encryption and decryption of your files. It utilizes robust cryptographic standards (PBKDF2HMAC for key derivation and AES-GCM for streaming encryption) to securely manage your data.

## 🌟 Key Features

* **Interactive Curses TUI:** A clean, keyboard-driven terminal interface to handle your workflows without needing to memorize CLI commands.
* **Infinite File Size Support:** Powered by a chunked AES-GCM streaming engine, EKMS can encrypt files of any size (even 100GB+ videos) using virtually zero RAM.
* **Yearly Key Rotation:** EKMS automatically generates 53 unique cryptographic keys for the current year. Encrypted files are tagged with their encryption year and week (e.g., `document.Y2026.W39.enc`), ensuring extreme compartmentalization.
* **Secure File Scrubbing:** An optional "Scrub" feature overwrites your original files with cryptographically random bytes before deletion, preventing forensic recovery.
* **Recursive Directory Support:** Select entire folders, and EKMS will automatically find and process all files inside them.
* **Real-time Process Log:** Watch the encryption and scrubbing progress in real-time with an ASCII progress bar and scrolling log.

---

## 🛠️ Installation

1. Ensure you have Python 3.x installed.
2. Clone or download this repository.
3. Install the required cryptographic library:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage Guide

EKMS can be run in two modes: the Interactive Terminal UI (TUI) or the Command Line Interface (CLI).

### 1. Interactive TUI (Recommended)
To launch the interactive application, simply run the script with no arguments:
```bash
python3 ekms.py
```

**TUI Navigation:**
* Use the **Up/Down Arrows** to navigate menus.
* Press **Enter** to select an option or open a directory.
* Press **Spacebar** to toggle the selection of files/directories in the file browser.
* Press **C** to confirm your file selection.
* Press **S** on the main menu to toggle **[Secure Scrub]** on or off.

### 2. Command Line Interface (CLI)
For automation or power-users, you can bypass the TUI entirely using arguments:

**Initialize Keys:**
```bash
python3 ekms.py init
```

**Encrypt Files/Folders:**
```bash
python3 ekms.py encrypt /path/to/file.txt /path/to/folder
```
*(Add `--scrub` to securely delete the original files after encryption)*

**Decrypt Files/Folders:**
```bash
python3 ekms.py decrypt /path/to/file.Y2026.W39.enc /path/to/folder
```
*(Add `--scrub` to securely delete the encrypted files after decryption)*

---

## 🔐 The Master Key File (`master_keys_v2.enc`)

When you run the **Initialize** command, EKMS prompts you for a Master Password. It uses this password to derive a strong master key, generates 53 weekly keys for the current year, and saves everything encrypted in a file named `master_keys_v2.enc`.

> [!WARNING]
> **CRITICAL:** Do NOT lose your Master Password or your `master_keys_v2.enc` file. If either of these is lost or corrupted, **all of your encrypted files will be permanently unrecoverable.** 

If a new year begins, you do not need to re-initialize. Simply run an encrypt/decrypt command, and EKMS will automatically generate the 53 keys for the new year and securely append them to your existing `master_keys_v2.enc` file.
