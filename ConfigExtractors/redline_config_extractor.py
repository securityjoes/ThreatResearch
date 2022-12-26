#-------------------------------------------------------------------------------
# Sha256:      9b838df19999f417961e05a4af98f5cfb5c4dd4a255e03cc937cda384d6e7955
#
# Author:      Charles Lomboni
# Created:     26/12/2022
# Company:     Security Joes
#-------------------------------------------------------------------------------

import re
from dotnetfile import DotNetPE
import base64
import argparse

# https://arpitbhayani.me/blogs/decipher-repeated-key-xor
def repeating_key_xor(text: bytes, key: bytes) -> bytes:
    """Given a plain text `text` as bytes and an encryption key `key`
    as bytes, the function encrypts the text by performing
    XOR of all the bytes and the `key` (in repeated manner) and returns
    the resultant XORed byte stream.
    """

    # we update the encryption key by repeating it such that it
    # matches the length of the text to be processed.
    repetitions = 1 + (len(text) // len(key))
    key = key * repetitions
    key = key[:len(text)]

    # XOR text and key generated above and return the raw bytes
    return bytes([b ^ k for b, k in zip(text, key)])

def config_extractor(file_name, str_key):

    dotnet_file = DotNetPE(file_name)
    us_stream_strings = dotnet_file.get_user_stream_strings()

    print("[+] Decrypting data")
    for string in us_stream_strings:

        # base64 regex
        x = re.search("^(?:[a-zA-Z0-9+\/]{4})*(?:|(?:[a-zA-Z0-9+\/]{3}=)|(?:[a-zA-Z0-9+\/]{2}==)|(?:[a-zA-Z0-9+\/]{1}===))$", string)

        if x:
            try:
                extracted = base64.b64decode(repeating_key_xor(base64.b64decode(string), str_key.encode())).decode()
                if extracted:
                    print(f"[>] {extracted}")
            except:
                try:
                    print(f"[>] {base64.b64decode(string).decode('ascii')}")
                except UnicodeDecodeError:
                    pass                
                pass

def get_args():

    parser = argparse.ArgumentParser(description='Redline Config Extractor.')
    parser.add_argument("-f", "--file_path", type=str, help='File path of the Redline binary')

    args = parser.parse_args()

    return args

def main():

    args = get_args()

    print(f"[+] Reading the file: {args.file_path}")
    config_extractor(args.file_path, str_key="Repoint")

    print("[+] Done!")


if __name__ == '__main__':
    main()