# coding: utf-8

#-------------------------------------------------------------------------------
# Name:        decrypt_templateX
# Purpose:     Decrypt templateX payload used by APT-Q-27
#
# Author:      Charles Lomboni
# Created:     10/08/2022
# Company:     Security Joes
#-------------------------------------------------------------------------------

import argparse
import lznt1

def getargs():
    parser = argparse.ArgumentParser("decrypt_templateX")
    parser.add_argument("path", help="Path to encrypted file.")
    return parser.parse_args()


def decryptExe(fileName):
    print("[+] Reading templateX ...")
    byteToModify = bytearray(open(fileName, 'rb').read())
    result = bytes([])

    bytesLen = len(byteToModify)

    print("[+] Decrypting templateX ...")
    # main logic to decrypt
    for i in range(bytesLen):
        result += bytes([(((byteToModify[i]) - 0x7A) & 0xFF) ^ 0x19])

    print("[+] Decompressing ...")
    for j in range(512, 2048):
        pe_hdr = result[j:j + 2]

        if pe_hdr == b'MZ':
            break
    
    bytesDecompressed = lznt1.decompress(result[j - 3:])
    savedFilename = fileName + '_decrypted.dll'
    print("[+] Saving file ", savedFilename)
    open(savedFilename, 'wb').write(bytesDecompressed)

    
def main():

    args = getargs()

    print ("[+] Started...")
    decryptExe(args.path) 
    print ("[+] Finished!")
    pass

if __name__ == '__main__':
    main()