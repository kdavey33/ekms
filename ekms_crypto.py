import base64
import json
import os
import datetime
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MASTER_KEYS_FILE = "master_keys_v2.enc"
CHUNK_SIZE = 64 * 1024  # 64 KB

class EKMSCryptoError(Exception):
    pass

def get_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode())

def init_master_file(password: str):
    if os.path.exists(MASTER_KEYS_FILE):
        raise EKMSCryptoError(f"{MASTER_KEYS_FILE} already exists.")
        
    salt = os.urandom(16)
    master_key = get_master_key(password, salt)
    aesgcm = AESGCM(master_key)
    
    # Generate current year's keys
    current_year = str(datetime.date.today().year)
    weekly_keys = [base64.b64encode(AESGCM.generate_key(bit_length=256)).decode('utf-8') for _ in range(53)]
    
    keys_dict = {
        current_year: weekly_keys
    }
    
    keys_json = json.dumps(keys_dict).encode('utf-8')
    nonce = os.urandom(12)
    encrypted_keys = aesgcm.encrypt(nonce, keys_json, None)
    
    data = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "keys": base64.b64encode(encrypted_keys).decode('utf-8')
    }
    
    with open(MASTER_KEYS_FILE, 'w') as out_f:
        json.dump(data, out_f)
        
def load_keys(password: str) -> dict:
    if not os.path.exists(MASTER_KEYS_FILE):
        raise EKMSCryptoError(f"{MASTER_KEYS_FILE} not found. Please run init first.")
        
    with open(MASTER_KEYS_FILE, 'r') as in_f:
        data = json.load(in_f)
        
    salt = base64.b64decode(data["salt"])
    nonce = base64.b64decode(data["nonce"])
    encrypted_keys = base64.b64decode(data["keys"])
    
    master_key = get_master_key(password, salt)
    aesgcm = AESGCM(master_key)
    
    try:
        decrypted_keys_json = aesgcm.decrypt(nonce, encrypted_keys, None)
        return json.loads(decrypted_keys_json.decode('utf-8'))
    except InvalidTag:
        raise EKMSCryptoError("Invalid master password or corrupted key file.")

def update_keys(password: str, keys_dict: dict):
    with open(MASTER_KEYS_FILE, 'r') as in_f:
        data = json.load(in_f)
        
    salt = base64.b64decode(data["salt"])
    master_key = get_master_key(password, salt)
    aesgcm = AESGCM(master_key)
    
    keys_json = json.dumps(keys_dict).encode('utf-8')
    nonce = os.urandom(12)
    encrypted_keys = aesgcm.encrypt(nonce, keys_json, None)
    
    data["nonce"] = base64.b64encode(nonce).decode('utf-8')
    data["keys"] = base64.b64encode(encrypted_keys).decode('utf-8')
    
    with open(MASTER_KEYS_FILE, 'w') as out_f:
        json.dump(data, out_f)

def ensure_current_year_keys(password: str, keys_dict: dict):
    current_year = str(datetime.date.today().year)
    if current_year not in keys_dict:
        weekly_keys = [base64.b64encode(AESGCM.generate_key(bit_length=256)).decode('utf-8') for _ in range(53)]
        keys_dict[current_year] = weekly_keys
        update_keys(password, keys_dict)
    return keys_dict

def encrypt_file(filepath: str, week_key_bytes: bytes, year: int, week: int, callback=None) -> str:
    """
    Encrypts a file using chunked AES-GCM streaming.
    Returns the path to the newly created encrypted file.
    """
    out_filepath = f"{filepath}.Y{year}.W{week}.enc"
    
    file_key = AESGCM.generate_key(bit_length=256)
    week_aesgcm = AESGCM(week_key_bytes)
    
    # Encrypt the file key using the week key
    file_key_nonce = os.urandom(12)
    encrypted_file_key = week_aesgcm.encrypt(file_key_nonce, file_key, None)
    
    file_aesgcm = AESGCM(file_key)
    
    total_size = os.path.getsize(filepath)
    
    with open(filepath, 'rb') as in_f, open(out_filepath, 'wb') as out_f:
        # Write header
        out_f.write(b"EKMS")
        out_f.write(file_key_nonce) # 12 bytes
        out_f.write(encrypted_file_key) # 32 + 16 = 48 bytes
        
        chunk_index = 0
        while True:
            chunk = in_f.read(CHUNK_SIZE)
            if not chunk:
                break
                
            # Deterministic nonce based on chunk_index
            chunk_nonce = struct.pack(">Q", 0) + struct.pack(">I", chunk_index) # 12 bytes
            encrypted_chunk = file_aesgcm.encrypt(chunk_nonce, chunk, None)
            
            # Write chunk length and encrypted chunk
            out_f.write(struct.pack(">I", len(encrypted_chunk)))
            out_f.write(encrypted_chunk)
            
            chunk_index += 1
            if callback:
                callback(in_f.tell(), total_size)
            
    return out_filepath

def decrypt_file(filepath: str, keys_dict: dict, callback=None) -> str:
    """
    Decrypts a chunked AES-GCM encrypted file.
    Returns the path to the decrypted file.
    """
    parts = filepath.split('.')
    if len(parts) < 4 or not parts[-3].startswith('Y') or not parts[-2].startswith('W') or parts[-1] != 'enc':
        raise EKMSCryptoError(f"Invalid filename format for {filepath}")
        
    year = parts[-3][1:]
    week = parts[-2][1:]
    
    if year not in keys_dict:
        raise EKMSCryptoError(f"Keys for year {year} not found in master key file.")
        
    try:
        week_idx = int(week) - 1
    except ValueError:
        raise EKMSCryptoError(f"Invalid week format in {filepath}")
        
    if week_idx < 0 or week_idx >= 53:
        raise EKMSCryptoError(f"Week out of bounds in {filepath}")
        
    week_key_b64 = keys_dict[year][week_idx]
    week_key_bytes = base64.b64decode(week_key_b64)
    week_aesgcm = AESGCM(week_key_bytes)
    
    out_filepath = '.'.join(parts[:-3])
    
    total_size = os.path.getsize(filepath)
    
    with open(filepath, 'rb') as in_f, open(out_filepath, 'wb') as out_f:
        magic = in_f.read(4)
        if magic != b"EKMS":
            raise EKMSCryptoError(f"Invalid file signature in {filepath}")
            
        file_key_nonce = in_f.read(12)
        encrypted_file_key = in_f.read(48)
        
        try:
            file_key = week_aesgcm.decrypt(file_key_nonce, encrypted_file_key, None)
        except InvalidTag:
            raise EKMSCryptoError(f"Failed to decrypt file key for {filepath}. Wrong master password or corrupted file.")
            
        file_aesgcm = AESGCM(file_key)
        
        chunk_index = 0
        while True:
            len_bytes = in_f.read(4)
            if not len_bytes:
                break
                
            chunk_len = struct.unpack(">I", len_bytes)[0]
            encrypted_chunk = in_f.read(chunk_len)
            
            chunk_nonce = struct.pack(">Q", 0) + struct.pack(">I", chunk_index)
            
            try:
                chunk = file_aesgcm.decrypt(chunk_nonce, encrypted_chunk, None)
            except InvalidTag:
                raise EKMSCryptoError(f"Failed to decrypt chunk {chunk_index} in {filepath}. File may be corrupted.")
                
            out_f.write(chunk)
            chunk_index += 1
            if callback:
                callback(in_f.tell(), total_size)
            
    return out_filepath
