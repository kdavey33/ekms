import os
import secrets

def secure_delete(filepath: str, passes: int = 3, callback=None):
    """
    Overwrites the file with random bytes multiple times before deleting it.
    """
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return

    length = os.path.getsize(filepath)
    if length == 0:
        os.remove(filepath)
        return

    # To avoid loading huge random strings into memory, write in chunks
    chunk_size = 64 * 1024  # 64KB
    total_bytes = length * passes
    bytes_processed = 0

    try:
        for p in range(passes):
            with open(filepath, 'r+b') as f:
                f.seek(0)
                written = 0
                while written < length:
                    write_size = min(chunk_size, length - written)
                    f.write(secrets.token_bytes(write_size))
                    written += write_size
                    bytes_processed += write_size
                    if callback:
                        callback(bytes_processed, total_bytes)
                f.flush()
                os.fsync(f.fileno())

        os.remove(filepath)
    except Exception as e:
        print(f"Error securely deleting {filepath}: {e}")

def get_all_files(paths: list) -> list:
    """
    Given a list of paths (files or directories), returns a flattened list
    of all file paths recursively.
    """
    all_files = []
    for path in paths:
        if os.path.isfile(path):
            all_files.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    all_files.append(os.path.join(root, file))
    return all_files
