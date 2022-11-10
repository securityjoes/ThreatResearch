from arc4 import ARC4
import binascii
import pefile
import argparse

def rc4_decrypt(key, data):
    cipher = ARC4(key)
    decrypted = cipher.decrypt(data)

    print("[+] Config extracted!")
    return decrypted.decode("latin-1")

def read_resource_in_hex(pe_name, resource_name):
    
    pe = pefile.PE(pe_name)

    settings_resource = "" 
    offset = 0x0
    size = 0x0

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                if entry.name.__str__() == resource_name:
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size

    if offset != 0x0 and size != 0x0:
        print(f"[+] Reading the resource: {resource_name}")
        settings_resource = pe.get_memory_mapped_image()[offset:offset+size]
        return settings_resource.hex()
    else:
        print("[-] Error while trying to read the resource")

def get_args():

    parser = argparse.ArgumentParser(description='Remcos Config Extractor.')
    parser.add_argument("-f", "--file_path", type=str, help='File path of the Remcos binary')
    parser.add_argument("-r", "--res_name", type=str, help='Name of the resource file inside the Remcos binary')

    args = parser.parse_args()

    return args

def main():

    args = get_args()

    print(f"[+] Reading the file: {args.file_path}")
    settings_resource = read_resource_in_hex(args.file_path, args.res_name)

    print("[+] Getting the key")
    key = binascii.unhexlify(settings_resource[2:194])
    
    print("[+] Getting the data")
    data = binascii.unhexlify(settings_resource[194:])

    print("[+] Decrypting data")
    print(rc4_decrypt(key, data))

if __name__ == '__main__':
    main()