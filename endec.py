# Name: endec
# Description: A program that encrypts and decrypts files using the Fernet symmetric encryption algorithm.
# Version: 1.1

import os, subprocess, getpass, hashlib, base64
from cryptography.fernet import Fernet

name_file_path = "./paths.txt"

# command = [win, linux]
command = [["explorer"], ["gnome-terminal", "--working-directory"]]

def path():
    if not os.path.exists(name_file_path):
        print(f"File {name_file_path} not found.\nCreating file.")
        open(name_file_path, "a").close()
        return None

    with open(name_file_path, "r") as f:
        paths = f.readlines()

    paths = [path.strip() for path in paths]

    for path in paths:
        if not os.path.exists(path):
            paths.remove(path)

    if len(paths) == 0:
        print("No valid path found.")
        return None
    
    print("Available paths:")
    for path in paths:
        print(f"{paths.index(path)}. {path}")

    return paths

def list_files(folder):
    files = os.listdir(folder)
    
    if files:
        for file in files:
            if os.path.isdir(folder + "/" + file):
                files.remove(file)

        print(f"\nAvailable files: ({folder})")
        for file in files:
            print(f"{files.index(file)}. {file}")
    
    else:
        print(f"\nNo files found in {folder}")
        return None

    print()
    return files

def derive_key(password: str, salt: bytes = b'static_salt') -> bytes:
    return base64.urlsafe_b64encode( hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000 ) )

def encrypt_file(file_path, key, enc_file_name):

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

        if enc_file_name == "":
            enc_file_path = file_path
        else:
            enc_file_path = os.path.join(os.path.dirname(file_path), enc_file_name)

        os.rename(file_path, enc_file_path)
    else:
        print(f"\nError: File encryption verification failed.")

def decrypt_file(file_path, key, dec_file_name):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    cipher = Fernet(key)
    try:
        decrypted_data = cipher.decrypt(encrypted_data)
        
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"\nFile decrypted successfully: {file_path}")

        if dec_file_name == "":
            dec_file_path = file_path
        else:
            dec_file_path = os.path.join(os.path.dirname(file_path), dec_file_name)

        os.rename(file_path, dec_file_path)
    except Exception as e:
        print(f"\nDecryption error. {str(e)}")

def main():

    print("File encryption/decryption tool\n")

    # Select folder ---------------------------------------------------------------------------------------------------------
    folders = path()

    if folders == None:
        return
    
    if len(folders) == 1:
        folder_number = 0
        
    else:
        folder_number = input("\nEnter folder number: ")
        if not folder_number.isdigit() or int(folder_number) >= len(folders) or int(folder_number) < 0:
            print("Invalid folder number.")
            return
    
    files_folder_path = folders[int(folder_number)]
    # Select folder ---------------------------------------------------------------------------------------------------------

    # List files in folder --------------------------------------------------------------------------------------------------
    _files = list_files(files_folder_path)

    if _files == None:
        return
    # List files in folder --------------------------------------------------------------------------------------------------

    # Select file -----------------------------------------------------------------------------------------------------------
    file_number = input("Enter file number: ")
    if not file_number.isdigit() or int(file_number) >= len(_files) or int(file_number) < 0:
        print("Invalid file number.")
        return

    file_path = files_folder_path + "/" + _files[int(file_number)]
    # Select file -----------------------------------------------------------------------------------------------------------

    # Option choose ---------------------------------------------------------------------------------------------------------
    option = input(f"Selected file: {file_path}\nDo you want to encrypt or decrypt this file? (e/d): ").strip().lower()
    
    if option != 'd' and option != 'e':
        print(f"{option} is not a valid option (e/d).")
        return
    
    option = option == "e"
    # Option choose ---------------------------------------------------------------------------------------------------------

    print()

    if option:
        print(f"Encrypt: {file_path}")
        password = getpass.getpass("Enter password: ")
        compare_password = getpass.getpass("Confirm password: ")

        if password != compare_password:
            print("Passwords do not match.")
            return

        new_name = input(f"Enter the new name of the file: ")

        if input("Do you want to encrypt this file (y/n): ").strip().lower() != 'y':
            return
        
        encrypt_file(file_path, derive_key(password), new_name)
    else:
        print(f"Decrypt: {file_path}")

        password = derive_key(getpass.getpass("Enter password: "))
        new_name = input("Enter the new name of the file: ")

        if input("Do you want to encrypt this file (y/n): ").strip().lower() != 'y':
            return

        decrypt_file(file_path, password, new_name )

    if input("\nDo you want to open the folder? (y/n): ").strip().lower() == 'y':
        subprocess.Popen(command[0 if os.name == "nt" else 1] + [os.path.abspath(files_folder_path)] )
        return 1

if __name__ == "__main__":
    if main() != 1 and os.name == "nt":
        input()
    
