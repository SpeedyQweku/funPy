#!/usr/bin/pthon3

# By Mr.Gentleman #

import argparse

from cryptography.fernet import Fernet


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt data.")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt data.")
    parser.add_argument("-p", "--path", dest="path", metavar='', help="The path of the file to be encrypted or decrypted.")
    parser.add_argument("-m", "--message", dest="message", nargs="+", metavar='', help="Message to be encrypted or decrypted.")
    parser.add_argument("-k", "--key", dest="key", metavar='', help="Key to decrypt data.")
    options = parser.parse_args()
    if not options.encrypt and not options.decrypt:
        parser.error("[->] Use --help for more info.")
    elif not options.path and not options.message:
        parser.error("[->] Please specify the MESSAGE or PATH, Use --help for more info.")
    return options

def encrypt(options):
    if options.encrypt:
        if options.path:
            with open(f"{options.path}", 'rb') as file:
                open_file = file.read()
            key = Fernet.generate_key()
            saved_key = Fernet(key)
            encrypted_data = saved_key.encrypt(open_file)
        elif options.message:
            data = str(options.message).encode('utf-8')
            key = Fernet.generate_key()
            saved_key = Fernet(key)
            encrypted_data = saved_key.encrypt(data)
        with open("encrypted.txt", 'w') as encrypt_file:
            encrypt_file.write(str(encrypted_data, 'utf-8'))    
            print("[->] Your file is now encrypted and saved as encrypted.txt")
        with open("key.txt", 'w') as store_Key:
            store_Key.write(str(key, 'utf-8'))
            print("[->] Your key has been saved as key.txt")

def decrypt(options):
    if options.decrypt:
        if options.path:
            if options.key:
                with open(f"{options.path}", "rb") as file:
                    open_file = file.read()
                key = Fernet(options.key)
                dencrypted_data = key.decrypt(open_file)
        elif options.message:
            if options.key:
                data = str(options.message).encode('utf-8')
                key = Fernet(options.key)
                dencrypted_data = key.decrypt(data)
        with open("decrypted.txt", "w") as decrypt_file:
            decrypt_file.write(str(dencrypted_data, 'utf-8'))
            print("[->] Your file is now decrypted and saved as decrypted.txt")

if __name__ == '__main__':
    options = get_arguments()
    encrypt(options)
    decrypt(options)

# By Mr.Gentleman #