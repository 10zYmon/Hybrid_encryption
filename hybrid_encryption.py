from Crypto.PublicKey import RSA            # RSA asymmetric encryption
from Crypto.Cipher import AES, PKCS1_OAEP   # AES symmetric + RSA padding
from Crypto.Random import get_random_bytes  # Secure random number gen
from Crypto.Util.Padding import pad, unpad  # Block cipher padding
import base64

class HybridCipher:
    # Key Management
    def __init__(self, private_key=None):
        if private_key:
            self.rsa_key = RSA.import_key(private_key)  # Load existing key
        else:
            self.rsa_key = RSA.generate(2048)           # Generate new 2048-bit RSA key
        self.public_key = self.rsa_key.publickey()       # Extract public key
    
    # Encryption
    def encrypt(self, plaintext: str) -> dict:
        aes_key = get_random_bytes(32)  # 256-bit AES key
        iv = get_random_bytes(16)       # Initialization vector for CBC
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)     # AES-CBC cipher
        ciphertext = cipher_aes.encrypt(pad(plaintext.encode(), AES.block_size))    # Pad & encrypt
        cipher_rsa = PKCS1_OAEP.new(self.public_key)        # RSA with OAEP padding
        enc_aes_key = cipher_rsa.encrypt(aes_key)           # Encrypt AES key with RSA
        return {   # Base64 for safe text representation
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'enc_aes_key': base64.b64encode(enc_aes_key).decode(),
            'iv': base64.b64encode(iv).decode()
        }
    
    # Decryption
    def decrypt(self, encrypted_data: dict) -> str:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])     # Decode from base64
        enc_aes_key = base64.b64decode(encrypted_data['enc_aes_key'])
        iv = base64.b64decode(encrypted_data['iv'])
        cipher_rsa = PKCS1_OAEP.new(self.rsa_key)       # RSA cipher with private key
        aes_key = cipher_rsa.decrypt(enc_aes_key)       # Decrypt AES key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
        return plaintext.decode()       # Convert bytes to string
    
    #  Key Persistence
    def save_private_key(self, filename: str):
        with open(filename, 'wb') as f:
            f.write(self.rsa_key.export_key('PEM'))     # Save in PEM format
    
    @staticmethod
    def load_private_key(filename: str) -> 'HybridCipher':
        with open(filename, 'rb') as f:
            return HybridCipher(f.read())       # Load existing key

def main_menu():
    print("\n=== Hybrid Encryption Tool ===")
    print("1. Encrypt Text")
    print("2. Decrypt Text")
    print("3. Exit")
    return input("Choose an option : ")

def encrypt_interaction():
    message = input("\nEnter message to encrypt: ")
    cipher = HybridCipher()
    cipher.save_private_key('private.pem')
    encrypted = cipher.encrypt(message)
    print("\n=== Encryption Results ===")
    print(f"Ciphertext: {encrypted['ciphertext']}")
    print(f"Encrypted AES Key: {encrypted['enc_aes_key']}")
    print(f"IV: {encrypted['iv']}")
    print("\nNote: Private key saved to 'private.pem' - keep this secure!")

def decrypt_interaction():
    try:
        ciphertext = input("\nEnter ciphertext: ")
        enc_aes_key = input("Enter encrypted AES key: ")
        iv = input("Enter IV: ")
        encrypted_data = {
            'ciphertext': ciphertext,
            'enc_aes_key': enc_aes_key,
            'iv': iv
        }
        loaded_cipher = HybridCipher.load_private_key('private.pem')
        decrypted = loaded_cipher.decrypt(encrypted_data)
        print(f"\nDecrypted Message: {decrypted}")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print("Make sure:")
        print("- You have 'private.pem' in this directory")
        print("- All input values are correct and properly formatted")

if __name__ == "__main__":
    while True:
        choice = main_menu()
        if choice == '1':
            encrypt_interaction()
        elif choice == '2':
            decrypt_interaction()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
