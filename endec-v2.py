# Name: endec
# Description: A program that encrypts and decrypts files using the Fernet symmetric encryption algorithm.
# Version: 2.0

import os, subprocess, getpass, hashlib, base64
from cryptography.fernet import Fernet

name_file_config = "./config.txt"

# Config Variables
default = ['./', ["explorer"]]

config_path = default[0]
config_command = default[1]

# Check if config file exists and read it
if (os.path.exists(name_file_config)):
    with open(name_file_config, "r") as f:
        lines = f.readlines()
        print(f"Config file found: {name_file_config}")

    if len(lines) >= 1:
        config_path = lines[0].strip()
    
    if len(lines) >= 2:
        config_command = lines[1].strip()

def list_files(folder):
    files = os.listdir(folder)

    if files:
        for i in range(0, len(files)):
            if os.path.isdir(folder + "/" + files[i]):
                files[i] += "/"

        print(f"Available files: ({folder})")
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

    # Select file and List -------------------------------------------------------------------------------------------------
    is_file = False
    aux_path = ""

    while not is_file:
        _files = list_files(config_path + aux_path)

        if _files == None:
            return

        file_number = input("Enter file number: ") 
        if not file_number.isdigit() or int(file_number) >= len(_files) or int(file_number) < 0:
            print("Invalid file number.")
            
        if _files[int(file_number)].endswith("/"):
            aux_path += _files[int(file_number)]
        else:
            is_file = True
            

    file_path = config_path + aux_path + _files[int(file_number)]
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
        subprocess.Popen(config_command + [os.path.abspath(config_path)] )
        return

if __name__ == "__main__":
    main()