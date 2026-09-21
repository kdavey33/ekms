import unittest
from unittest.mock import patch
import os
import ekms_crypto

class TestEKMSv2(unittest.TestCase):
    def setUp(self):
        if os.path.exists("master_keys_v2.enc"):
            os.remove("master_keys_v2.enc")
        with open("test_file.txt", "w") as f:
            f.write("Hello, World! " * 1000) # Ensure it's somewhat large

    def tearDown(self):
        if os.path.exists("master_keys_v2.enc"):
            os.remove("master_keys_v2.enc")
        
        for f in os.listdir("."):
            if f.startswith("test_file.txt"):
                try:
                    os.remove(f)
                except:
                    pass

    def test_crypto_pipeline(self):
        # Init master file
        ekms_crypto.init_master_file("mypassword")
        self.assertTrue(os.path.exists("master_keys_v2.enc"))
        
        # Load keys
        keys_dict = ekms_crypto.load_keys("mypassword")
        keys_dict = ekms_crypto.ensure_current_year_keys("mypassword", keys_dict)
        
        # Encrypt
        import datetime
        current_year = datetime.date.today().year
        current_week = datetime.date.today().isocalendar()[1]
        
        import base64
        week_key_b64 = keys_dict[str(current_year)][current_week - 1]
        week_key_bytes = base64.b64decode(week_key_b64)
        
        enc_file = ekms_crypto.encrypt_file("test_file.txt", week_key_bytes, current_year, current_week)
        self.assertTrue(os.path.exists(enc_file))
        
        # Remove original
        os.remove("test_file.txt")
        
        # Decrypt
        dec_file = ekms_crypto.decrypt_file(enc_file, keys_dict)
        self.assertTrue(os.path.exists(dec_file))
        
        # Verify content
        with open(dec_file, "r") as f:
            content = f.read()
        self.assertEqual(content, "Hello, World! " * 1000)

if __name__ == '__main__':
    unittest.main()
