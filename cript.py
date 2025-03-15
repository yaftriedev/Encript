import os
import getpass
import hashlib
import base64
from cryptography.fernet import Fernet

name_file_path = "./paths.txt"

def path():
    if not os.path.exists(name_file_path):
        print(f"File {name_file_path} not found.\nCreating file.")
        open(name_file_path, "a").close()
        return None

    with open(name_file_path, "r") as f:
        paths = f.readlines()

    paths = [path.strip() for path in paths]

    for path in paths:
        if os.path.exists(path):
            return path
    
    print("No valid path found.")
    return None

def list_files(folder):
    files = os.listdir(folder)
    if files:
        print(f"Available files: ({folder})")
        for i in range(len(files)):
            print(f"{i}. {files[i]} {'*' if files[i].endswith('.enc') else ''}")
    else:
        print(f"No files found in {folder}")
        return None

    print()
    return files

def select_file(_files, folder):
    file_number = input("Enter file number: ")

    if not file_number.isdigit() or int(file_number) >= len(_files) or int(file_number) < 0:
        print("Invalid file number.")
        return
    
    return folder + "/" + _files[int(file_number)]

def derive_key(password: str, salt: bytes = b'static_salt') -> bytes:
    return base64.urlsafe_b64encode( hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000 ) )

def encrypt_file(file_path, key):

    with open(file_path, 'rb') as f:
        data = f.read()
    
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data)
    
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)
    
    with open(file_path, 'rb') as f:
        verification_data = f.read()

    if verification_data == encrypted_data:
        print(f"\nFile encrypted successfully: {file_path}")
        enc_file_path = file_path + ".enc"
        os.rename(file_path, enc_file_path)
    else:
        print(f"\nError: File encryption verification failed.")

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    cipher = Fernet(key)
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"\nFile decrypted successfully: {file_path}")
        dec_file_path = file_path[:-4]
        os.rename(file_path, dec_file_path)
    except Exception as e:
        print(f"\nDecryption error. {str(e)}")

def main():
    files_folder_path = path()

    if files_folder_path == None:
        return

    _files = list_files(files_folder_path)

    if _files == None:
        return
    
    file_path = select_file(_files, files_folder_path)
    if not file_path:
        print("No file selected.")
        return

    option = file_path.endswith(".enc")
    
    if input(f"Selected file: {file_path}\nDo you want to {'decrypt' if option else 'encrypt'} this file? (y/n): ").strip().lower() != 'y':
        return

    print()

    if option:
        decrypt_file(file_path, derive_key(getpass.getpass("Enter password: ")))
    else:
        password = getpass.getpass("Enter password: ")
        compare_password = getpass.getpass("Confirm password: ")

        if password != compare_password:
            print("Passwords do not match.")
            return

        encrypt_file(file_path, derive_key(password))

if __name__ == "__main__":
    main()
