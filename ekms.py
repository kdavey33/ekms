import argparse
import sys
import getpass
import datetime
import base64
from ekms_crypto import init_master_file, load_keys, ensure_current_year_keys, encrypt_file, decrypt_file, EKMSCryptoError
from ekms_utils import secure_delete, get_all_files

def run_cli():
    parser = argparse.ArgumentParser(description="Encryption Key Management System (EKMS v2)")
    subparsers = parser.add_subparsers(dest="command")
    
    init_parser = subparsers.add_parser('init', help='Initialize the master key file')
    
    encrypt_parser = subparsers.add_parser('encrypt', help="Encrypt files")
    encrypt_parser.add_argument('files', nargs='+', help='Files or directories to encrypt')
    encrypt_parser.add_argument('--scrub', action='store_true', help='Securely delete original files after encryption')
    
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt files')
    decrypt_parser.add_argument('files', nargs='+', help='Files or directories to decrypt')
    decrypt_parser.add_argument('--scrub', action='store_true', help='Securely delete encrypted files after decryption')
    
    args = parser.parse_args()
    
    if args.command == 'init':
        pw1 = getpass.getpass("Enter NEW master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match!")
            sys.exit(1)
        try:
            init_master_file(pw1)
            print("Initialization successful.")
        except EKMSCryptoError as e:
            print(f"Error: {e}")
            sys.exit(1)
            
    elif args.command in ('encrypt', 'decrypt'):
        password = getpass.getpass("Enter master password: ")
        try:
            keys_dict = load_keys(password)
            keys_dict = ensure_current_year_keys(password, keys_dict)
        except EKMSCryptoError as e:
            print(f"Error: {e}")
            sys.exit(1)
            
        all_files = get_all_files(args.files)
        
        current_year = datetime.date.today().year
        current_week = datetime.date.today().isocalendar()[1]
        
        success = 0
        for f in all_files:
            try:
                if args.command == 'encrypt':
                    if f.endswith('.enc'):
                        continue
                    week_key_b64 = keys_dict[str(current_year)][current_week - 1]
                    week_key_bytes = base64.b64decode(week_key_b64)
                    encrypt_file(f, week_key_bytes, current_year, current_week)
                    print(f"Encrypted: {f}")
                else:
                    if not f.endswith('.enc'):
                        continue
                    decrypt_file(f, keys_dict)
                    print(f"Decrypted: {f}")
                    
                if args.scrub:
                    secure_delete(f)
                    print(f"Scrubbed: {f}")
                    
                success += 1
            except Exception as e:
                print(f"Error processing {f}: {e}")
                
        print(f"Completed {success} files.")

def main():
    if len(sys.argv) > 1:
        run_cli()
    else:
        try:
            from ekms_tui import run_tui
            run_tui()
        except ImportError as e:
            print(f"Error loading TUI: {e}")
            print("Running in CLI mode instead. Use -h for help.")
            sys.exit(1)

if __name__ == '__main__':
    main()
