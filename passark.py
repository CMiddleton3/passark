import argparse
import os
import json
import uuid
import hashlib
import base64
import random
import string
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

PASSWORD_LENGTH = 64
UNIQUE_ID_LENGTH = 6
VAULT_DIR = '.vault'
VAULT_FILE = 'passvault.json'
KEY_FILE = '.vault_key.json'

def generate_unique_id():
    """Generates a Unique ID

    Returns:
        string: Unique ID String in the format of 123-456
    """
    unique_id = '{:03d}-{:03d}'.format(random.randint(0, 999), random.randint(0, 999))
    # return str(uuid.uuid4().int)[:UNIQUE_ID_LENGTH].replace('-', '')
    return unique_id

def generate_password(length):
    """Generates a Random Password or any length

    Args:
        length (int): length of password

    Returns:
        string: Password of desired length
    """
    password_chars = string.ascii_letters + string.digits
    password = ''.join(random.choice(password_chars) for i in range(length))
    return password

def remove_vault_file():
    """Remove the encrypted password VAULT_FILE
    """
    if os.path.exists(get_vault_path(VAULT_FILE)):
        os.remove(get_vault_path(VAULT_FILE))
        print("Vault file removed.")
    else:
        print("Vault file does not exist.")

def encrypt_data(key, data):
    """Encrypts JSON Data

    Args:
        key (string): AES Key
        data (string): Data to encrypt

    Returns:
        base64 (string): String representation of base64 encrypted byte object
    """
    key = hashlib.sha256(key.encode()).digest()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()

def decrypt_data(key, encrypted_data):
    """Decrypt JSON Data

    Args:
        key (string): AES Encryption Key
        encrypted_data (base64 string): String representation of base64 encrypted byte object

    Returns:
        string: Decrypted Data
    """
    key = hashlib.sha256(key.encode()).digest()
    encrypted_data = base64.b64decode(encrypted_data.encode())
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def get_vault_path(file):
    """Return full path of a file in relationship to this programs

    Args:
        file (string): filename

    Returns:
        string: full file path including file
    """
    return os.path.join(VAULT_DIR, file)

def create_vault_dir():
    """Create the vault directory if it doesn't already exist
    """
    if not os.path.exists(VAULT_DIR):
        os.makedirs(VAULT_DIR)

def generate_key():
    """Generate a Unique ID based on the Processor ID of the System

    Returns:
        string: Unique for the computer the script is ran on
    """
    return str(uuid.uuid4().int) + str(os.getpid())

def load_key():
    """Load the AES encryption key from the Keyfile. If one doesn't exist, generate a new key and create the file.

    Returns:
        string: String of the AES Encryption Key.
    """
    if not os.path.exists(get_vault_path(KEY_FILE)):
        key = generate_key()
        with open(get_vault_path(KEY_FILE), 'w') as f:
            f.write(key)
    else:
        with open(get_vault_path(KEY_FILE), 'r') as f:
            key = f.read()
    return key

def get_password(unique_id):
    """Get the Encrypted password from the vault and decrypts it.

    Args:
        unique_id (string): Passwords UUID

    Returns:
        string: The decrypted password
    """
    create_vault_dir()
    key = load_key()
    with open(get_vault_path(VAULT_FILE), 'r') as f:
        data = json.load(f)
    encrypted_password = data[unique_id]
    password = decrypt_data(key, encrypted_password).decode()
    return password

def show_passwords():
    """Shows the UUID of all Generated Passwords

    Returns:
        dict: Dictionary of all Password UUIDs
    """
    key = load_key()
    with open(get_vault_path(VAULT_FILE), 'r') as f:
        data = json.load(f)
    passwords = data.keys()
    return passwords

def generate_password_with_id():
    """Generate a Random Password with a Unique UUID, the encrypted password and save to vault file.

    Returns:
        tuple string:string : Tuple of String for UUID and String for password.
    """
    create_vault_dir()
    key = load_key()
    unique_id = generate_unique_id()
    password = generate_password(PASSWORD_LENGTH)
    encrypted_password = encrypt_data(key, password)
    if os.path.exists(get_vault_path(VAULT_FILE)):
        with open(get_vault_path(VAULT_FILE), 'r') as f:
            data = json.load(f)
    else:
        data = {}
    data[unique_id] = encrypted_password
    with open(get_vault_path(VAULT_FILE), 'w') as f:
        json.dump(data, f)
    return unique_id, password

if __name__ == '__main__':

    # Handle command line arguments
    parser = argparse.ArgumentParser(description='Password Vault')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--generate-password', action='store_true', help='Generate a password')
    group.add_argument('-g', '--get-password', type=str, help='Get password by unique id')
    group.add_argument('-s','--show-passwords',type=str,help='Display all Password Unique Keys Available',const=True,nargs='?',default=None)
    parser.add_argument('-j','--json',type=str,help='Display password in JSON format',const=True,nargs='?',default=None)
    parser.add_argument('-c','--csv',type=str,help='Display password in CSV format',const=True,nargs='?',default=None)

    group.add_argument('-r', '--reset', type=str, help='Reset Password Value', const=True, nargs='?', default=None)

    args = parser.parse_args()

    # Generate a Random Password
    if args.generate_password:
        unique_id, password = generate_password_with_id()
        if args.json:
            json_out = {'uuid': unique_id, 'password':password}
            print(json_out)
        elif args.csv:
            print(f'{unique_id},{password}')
        else:
            print(f'Password generated. Unique ID: {unique_id} Password: {password}')
    
    # Get a Password using it's UUID
    if args.get_password:
        password = get_password(args.get_password)
        print(f'Password retrieved: {password}')

    # Show all Passwords UUID    
    if args.show_passwords:
        all_passwords = show_passwords()
        out_list =  []
        json_out = dict()

        # Output JSON
        if args.json:
            for passwd in all_passwords:
                out_list.append(passwd)
            
            json_out["Passwords"] = out_list
            print(json_out)
        # Output CSV    
        elif args.csv:
            out_csv = ""
            for passwd in all_passwords:
                out_csv += passwd + ","
            print(out_csv.rstrip(','))
        else:
            print(f'{len(all_passwords)} Passwords')
            for passwd in all_passwords:
                print(f'Password UUID: {passwd}')

    # Reset and clear all passwords
    if args.reset:
        print('All Password will be DELETED!')
        confirm = input("Are you sure you want to proceed? (Y/N): ")
        if confirm.upper() == 'Y':
            print("Proceeding...")
            remove_vault_file()
            print('Removed Passwords')
        else:
            print("Aborting.")