import os 
from Crypto.Cipher import AES
import base64 

class CreateAES:
    # Generation of key
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Error! Key must be 16, 24 or 32 bytes.")
        
        self.key = key

    #Generation of key length
    @staticmethod
    def generate_key(key_size_bits: int = 128) -> bytes:
        if key_size_bits not in (128, 192, 256):
            raise ValueError("Only 128, 192 or 256 bits.")
        
        bytes_length = key_size_bits // 8
        
        return os.urandom(bytes_length)

    
    # Adding padding and unpadding
    def add_pad(self, data: bytes) -> bytes: 
        create_padding_length = 16 - (len(data) % 16)
        padding = bytes([create_padding_length]) * create_padding_length
        return data + padding

    def unpad(self, padded_data: bytes) -> bytes:
        cut_padding_length = padded_data[-1]
        if cut_padding_length == 0 or cut_padding_length > 16:
            raise ValueError("Incorrect size of padding")
            
        for i in range(1, cut_padding_length + 1):
            if padded_data[-i] != cut_padding_length:
                raise ValueError("Garbage padding!")
        return padded_data[:-cut_padding_length]


    # Tool for Student 2 (Hacker)
    def decrypt_message(self, ciphertext: bytes) -> str:
        data_cbc = self.decryption_cbc(ciphertext)
        return data_cbc.decode('utf-8', errors='ignore') # Just skipping all errors in case of invalid padding

    def verify_oracle(self, ciphertext: bytes) -> bool:
        try:
            self.decryption_cbc(ciphertext)
            return True
        except:
            return False # In case of invalid padding

    
    def encryption_ecb(self, text: bytes) -> bytes: # ECB
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_data = self.add_pad(text) 
        return cipher.encrypt(padded_data)

    def decryption_ecb(self, ciphertext: bytes) -> bytes:
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_data = cipher.decrypt(ciphertext)
        return self.unpad(padded_data)

    

    # CBC method
    def encryption_cbc(self, text: bytes) -> bytes: # CBC
        init_vector = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CBC, init_vector)
        padded_data = self.add_pad(text)
        encrypted_data = cipher.encrypt(padded_data)
        return init_vector + encrypted_data 

    def decryption_cbc(self, ciphertext: bytes) -> bytes:
        cut_init_vector = ciphertext[:16] 
        new_ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, cut_init_vector)
        padded_data = cipher.decrypt(new_ciphertext)
        return self.unpad(padded_data)

    

    # CFB method
    def encryption_cfb(self, text: bytes) -> bytes: # CFB
        init_vector = os.urandom(16)
        cipher = AES.new(self.key, AES.MODE_CFB, init_vector, segment_size=128)
        encrypted_data = cipher.encrypt(text)
        return init_vector + encrypted_data

    def decryption_cfb(self, ciphertext: bytes) -> bytes:
        cut_init_vector = ciphertext[:16]
        new_ciphertext = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_CFB, cut_init_vector, segment_size=128)
        return cipher.decrypt(new_ciphertext)


if __name__ == "__main__":
    my_key = CreateAES.generate_key(128)
    print(f"Ready generated key (bytes): {my_key}")
    cipher_machine = CreateAES(my_key)
    secret_text = "Hi! It is my secret message :)".encode('utf-8')

    print("\nAll results of differents methods: \n")

    ecb_info = cipher_machine.encryption_ecb(secret_text)
    print(f"ECB: {base64.b64encode(ecb_info).decode()}")
    print(f"Decryption of ECB: {cipher_machine.decryption_ecb(ecb_info).decode('utf-8')}")

    cbc_info = cipher_machine.encryption_cbc(secret_text)
    print(f"\nCBC: {base64.b64encode(cbc_info).decode()}")
    print(f"Decryption of CBC: {cipher_machine.decryption_cbc(cbc_info).decode('utf-8')}")

    cfb_info = cipher_machine.encryption_cfb(secret_text)
    print(f"\nCFB: {base64.b64encode(cfb_info).decode()}")
    print(f"Decryption of CFB: {cipher_machine.decryption_cfb(cfb_info).decode('utf-8')}")

    print("\nVerification by NIST") # Now we are going to make verification by NIST official values
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    init_text = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a") # This values from Federal Information Processing Standards
    expected_cipher = "3ad77bb40d7a3660a89ecaf32466ef97"

    test = AES.new(key, AES.MODE_ECB)
    cipher_hex = test.encrypt(init_text).hex()

    print(f"NIST cipher: {expected_cipher}")
    print(f"Results: {cipher_hex}")

    if cipher_hex == expected_cipher:
        print("\nWin :) We did it! Everything is correct")
    else:
        print("ERROR")
