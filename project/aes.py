# from cryptography.fernet import Fernet
# import os

# # ✅ Load AES Key from Environment (.env)
# AES_KEY = "Vn8ow9JqfPJQdoBqGQhCjSP3NLeiCnt-a-AAndI23JQ="

# if not AES_KEY:
#     raise ValueError("❌ AES_KEY is not set in environment variables.")

# cipher = Fernet(AES_KEY)

# # ✅ Function to Encrypt a Message
# def encrypt_message(message):
#     encrypted = cipher.encrypt(message.encode()).decode()
#     return encrypted

# # ✅ Function to Decrypt a Message
# def decrypt_message(encrypted_message):
#     decrypted = cipher.decrypt(encrypted_message.encode()).decode()
#     return decrypted

# if __name__ == "__main__":
#     while True:
#         choice = input("\n1. Encrypt Message\n2. Decrypt Message\n3. Exit\nChoose an option: ")
        
#         if choice == "1":
#             message = input("Enter message to encrypt: ")
#             encrypted_msg = encrypt_message(message)
#             print(f"\n🔐 Encrypted Message: {encrypted_msg}")
        
#         elif choice == "2":
#             encrypted_message = input("Enter message to decrypt: ")
#             try:
#                 decrypted_msg = decrypt_message(encrypted_message)
#                 print(f"\n🔓 Decrypted Message: {decrypted_msg}")
#             except Exception as e:
#                 print(f"\n❌ Decryption failed: {str(e)}")

#         elif choice == "3":
#             print("Exiting...")
#             break

#         else:
#             print("\n❌ Invalid choice. Please choose again.")

# # import os
# # import base64

# # aes_key = os.urandom(32)  # Generate a 32-byte key
# # base64_key = base64.b64encode(aes_key).decode()  # Convert to Base64
# # print("AES-256 Key:", base64_key)


# import base64
# import json
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import os

# # ✅ AES Key (Must be 32 bytes for AES-256)
# AES_KEY = os.getenv("AES_KEY", "EYYsSaHts7FIgiLWk4huo76Mlf5n2pTmnAGCC0cfzng=")[:32]
# AES_IV = os.getenv("AES_IV", "9786758463902280")  # Must be 16 bytes

# def encrypt_message(message):
#     """Encrypt a JSON message using AES-256-CBC"""
#     cipher = AES.new(AES_KEY.encode(), AES.MODE_CBC, AES_IV.encode())
#     padded_data = pad(json.dumps(message).encode(), AES.block_size)
#     encrypted = cipher.encrypt(padded_data)
#     return base64.b64encode(encrypted).decode()

# def decrypt_message(encrypted_message):
#     """Decrypt an AES-256-CBC encrypted message"""
#     cipher = AES.new(AES_KEY.encode(), AES.MODE_CBC, AES_IV.encode())
#     decrypted_padded = cipher.decrypt(base64.b64decode(encrypted_message))
#     return json.loads(unpad(decrypted_padded, AES.block_size).decode())

# if __name__ == "__main__":
#     while True:
#         choice = input("\n1. Encrypt Message\n2. Decrypt Message\n3. Exit\nChoose an option: ")
        
#         if choice == "1":
#             message = input("Enter message to encrypt: ")
#             encrypted_msg = encrypt_message(message)
#             print(f"\n🔐 Encrypted Message: {encrypted_msg}")
        
#         elif choice == "2":
#             encrypted_message = input("Enter message to decrypt: ")
#             try:
#                 decrypted_msg = decrypt_message(encrypted_message)
#                 print(f"\n🔓 Decrypted Message: {decrypted_msg}")
#             except Exception as e:
#                 print(f"\n❌ Decryption failed: {str(e)}")

#         elif choice == "3":
#             print("Exiting...")
#             break

#         else:
#             print("\n❌ Invalid choice. Please choose again.")


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import json
import re

# Secret key (must match frontend AES_KEY)
SECRET_KEY = "TiSVLTWhb0jadJ8GZ7LCakMaSdu6p/DZrIYR/Mq78lU="

# Convert the SECRET_KEY to a proper 256-bit key (same as CryptoJS)
AES_KEY = hashlib.sha256(SECRET_KEY.encode()).digest()

# Function to decrypt CryptoJS-encrypted data
def decrypt(encrypted_data):
    try:
        # Load the JSON payload
        parsed_data = json.loads(encrypted_data)
        iv = base64.b64decode(parsed_data["iv"])
        ct = base64.b64decode(parsed_data["ct"])

        # Remove "Salted__" header if present
        salted_match = re.match(b"Salted__(.{8})(.*)", ct, re.DOTALL)
        if salted_match:
            salt, ct = salted_match.groups()

        # Decrypt the message
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ct), AES.block_size)
        return decrypted.decode("utf-8")

    except Exception as e:
        return f"Decryption failed: {str(e)}"

# Function to encrypt data (for manual testing)
def encrypt(data):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return json.dumps({"iv": iv, "ct": ct})

# Manual Testing
if __name__ == "__main__":
    print("1. Encrypt Data\n2. Decrypt Data\n3. Exit")
    while True:
        choice = input("Choose an option: ")

        if choice == "1":
            data = input("Enter data to encrypt: ")
            encrypted = encrypt(data)
            print(f"Encrypted Data: {encrypted}")

        elif choice == "2":
            data = input("Enter data to decrypt: ")
            decrypted = decrypt(data)
            print(f"Decrypted Data: {decrypted}")

        elif choice == "3":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please")
