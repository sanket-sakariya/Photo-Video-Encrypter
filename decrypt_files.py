import os
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2"""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def decrypt_file(encrypted_path: str, password: str) -> bool:
    """Decrypt a single file"""
    try:
        # Read encrypted file
        with open(encrypted_path, 'rb') as encrypted_file:
            file_content = encrypted_file.read()
        
        # Extract salt (first 16 bytes)
        salt = file_content[:16]
        encrypted_data = file_content[16:]
        
        # Derive key from password
        key = derive_key(password, salt)
        fernet = Fernet(key)
        
        # Decrypt data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Extract original extension and file data
        ext_length = int.from_bytes(decrypted_data[:4], byteorder='big')
        original_ext = decrypted_data[4:4+ext_length].decode('utf-8')
        original_data = decrypted_data[4+ext_length:]
        
        # Create original file path
        base_path = os.path.splitext(encrypted_path)[0]
        original_path = base_path + original_ext
        
        # Write decrypted data to original file
        with open(original_path, 'wb') as original_file:
            original_file.write(original_data)
        
        # Remove encrypted file
        os.remove(encrypted_path)
        
        print(f"✅ Successfully decrypted: {os.path.basename(encrypted_path)} -> {os.path.basename(original_path)}")
        return True
        
    except Exception as e:
        print(f"❌ Error decrypting {encrypted_path}: {str(e)}")
        return False

def decrypt_folder(folder_path: str, password: str):
    """Decrypt all .encrypted files in a folder"""
    encrypted_extension = ".encrypted"
    
    # Find all encrypted files
    encrypted_files = [f for f in os.listdir(folder_path) 
                      if f.endswith(encrypted_extension)]
    
    if not encrypted_files:
        print(f"No encrypted files found in: {folder_path}")
        return
    
    print(f"Found {len(encrypted_files)} encrypted files to decrypt...")
    
    success_count = 0
    for filename in encrypted_files:
        file_path = os.path.join(folder_path, filename)
        if decrypt_file(file_path, password):
            success_count += 1
    
    print(f"\n🎉 Decryption complete! {success_count}/{len(encrypted_files)} files successfully decrypted.")

def main():
    """Main function"""
    print("🔓 Standalone File Decryption Tool")
    print("=" * 40)
    
    # Get folder path
    if len(sys.argv) > 1:
        folder_path = sys.argv[1]
    else:
        folder_path = input("Enter the folder path containing encrypted files: ").strip()
    
    # Validate folder path
    if not os.path.exists(folder_path):
        print("❌ Error: The specified folder does not exist!")
        return
    
    if not os.path.isdir(folder_path):
        print("❌ Error: The specified path is not a folder!")
        return
    
    # Get password
    password = input("Enter the decryption password: ").strip()
    
    if not password:
        print("❌ Error: Password cannot be empty!")
        return
    
    print(f"\nStarting decryption of files in: {folder_path}")
    print("=" * 50)
    
    try:
        decrypt_folder(folder_path, password)
    except KeyboardInterrupt:
        print("\n\n⚠️  Decryption cancelled by user.")
    except Exception as e:
        print(f"\n❌ An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
