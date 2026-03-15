from aes_cipher import CreateAES 

# Generate a secret key.
secret_key = CreateAES.generate_key(128)
cipher_machine = CreateAES(secret_key)

original_message = b"Sender: Alice | Receiver: Bob | Amount: 00100" 
print(f"Original text: '{original_message.decode()}'")

# Intercept the ciphertext
intercepted_ciphertext = cipher_machine.encryption_cfb(original_message)
hacked_ciphertext = bytearray(intercepted_ciphertext)

# Flip the '1' to a '5'
target_index = 58 
hacked_ciphertext[target_index] = hacked_ciphertext[target_index] ^ ord('1') ^ ord('5') #flip the '1' to a '5'

# Decrypt
decrypted_hacked_message = cipher_machine.decryption_cfb(bytes(hacked_ciphertext))


print(f"Hacked text:   '{decrypted_hacked_message.decode('utf-8', errors='replace')}'") # we have to replace errors cus we use cfb-8