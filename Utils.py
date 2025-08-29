import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone
# from datetime import datetime, timedelta, UTC

class Utils:
    @staticmethod
    def calculate_file_hash(file_path, hash_algorithm='md5'):
        """Calculate the hash of a file."""
        hash_func = hashlib.new(hash_algorithm)
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):  # Read in chunks to handle large files
                    hash_func.update(chunk)
            return hash_func.hexdigest()

        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return None
