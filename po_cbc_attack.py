from aes_cipher import CreateAES
import sys
import time

# Generate a secret key
secret_key = CreateAES.generate_key(128)
cipher_machine = CreateAES(secret_key)


secret_message = b"top secret 67541"
intercepted_ciphertext = cipher_machine.encryption_cbc(secret_message)

# Split the ciphertext into chunks
block_size = 16
blocks = [intercepted_ciphertext[i:i+block_size] for i in range(0, len(intercepted_ciphertext), block_size)]

full_decrypted_message = []

# The multi block attack
for block_index in range(1, len(blocks)):
    target_block = blocks[block_index]
    previous_block = blocks[block_index - 1] # the initialisation vector
    
    known_plaintext_bytes = []
    
    # Decryption loop
    for pad_value in range(1, 17):
        target_index = 16 - pad_value 
        
        for guess in range(256):
            modified_prev_block = bytearray(previous_block)
            
            # Update previously found bytes
            for i in range(1, pad_value):
                known_idx = 16 - i
                known_byte = known_plaintext_bytes[-i]
                modified_prev_block[known_idx] = previous_block[known_idx] ^ known_byte ^ pad_value
                
            # Insert our guess
            modified_prev_block[target_index] = previous_block[target_index] ^ guess ^ pad_value
            
            # The false positive Fix
            if pad_value == 1 and target_index > 0:
                modified_prev_block[target_index - 1] = modified_prev_block[target_index - 1] ^ 0xFF
                
            # Send modified ciphertext to oracle.
            malicious_ciphertext = bytes(modified_prev_block) + target_block
            is_valid = cipher_machine.verify_oracle(malicious_ciphertext)
            
            if is_valid:
                known_plaintext_bytes.insert(0, guess)
                break
    full_decrypted_message.extend(known_plaintext_bytes)

# Strip the padding from the final message
pad_length = full_decrypted_message[-1]
clean_message = full_decrypted_message[:-pad_length]

final_string = "".join([chr(b) for b in clean_message])
print(f"Stolen plaintext: '{final_string}'")