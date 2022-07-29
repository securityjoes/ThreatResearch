import argparse
import re
import struct

import lznt1


def read_file(file_path):
    """
    Return given a file path return a buffer with the data

    :param file_path:
    :return:
    """
    with open(file_path, 'rb') as f:
        data = f.read()
    return data


def xor_decrypt(data):
    """
    Decrypt PlugX payload and config

    :param data:
    :return:
    """
    key = struct.unpack('<I', data[0:4])[0]
    key_a, key_b, key_c = key, key, key
    result = bytes([])

    for char in data:
        key = (key + (key >> 3) - 0x11111111) & 0xFFFFFFFF
        key_a = (key_a + (key_a >> 5) - 0x22222222) & 0xFFFFFFFF
        key_b = (key_b - (key_b << 7) + 0x33333333) & 0xFFFFFFFF
        key_c = (key_c - (key_c << 9) + 0x44444444) & 0xFFFFFFFF

        result += bytes([char ^ ((key + key_a + key_b + key_c) & 0x000000FF)])

    return result


def main(file_path):
    """
    Main logic of the script

    :return:
    """
    print(f'[+] Analyzing shellcode at "{file_path}"')
    sc = read_file(file_path)

    # Find main shellcode function
    print('[+] Finding main shellcode function')
    main_index = sc.index(b'\xe8\x05', 0, 96)

    # Find DLL pointer in shellcode
    print('[+] Extracting address of the encrypted DLL')
    dll_index = main_index - 30
    dll_ptr = struct.unpack('<I', sc[dll_index:dll_index + 4])[0]

    # Find DLL size
    size_index = main_index - 24
    size = struct.unpack('<I', sc[size_index:size_index + 4])[0]
    print('[+] Extracting size of the encrypted DLL')

    # Extract DLL
    print('[+] Decrypting PlugX DLL')
    dll_data = lznt1.decompress(xor_decrypt(sc[dll_ptr:dll_ptr + size])[16:])

    # Saving config
    print('[+] Saving PlugX DLL')
    with open('plug_x_dll.bin', 'wb') as f:
        f.write(dll_data)

    # Extract config
    print('[+] Decrypting attack configuration')
    config = xor_decrypt(sc[dll_ptr + size:])
    servers = re.finditer(b'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', config)

    # Saving config
    print('[+] Saving attack configuration')
    with open('config.bin', 'wb') as f:
        f.write(config)

    print('[+] C2 servers:')
    for server in servers:
        port = struct.unpack("<I", config[server.start() - 2:server.start()] + b"\x00\x00")[0]
        print(f'\t[-] {config[server.start():server.end()].decode()}:{port}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PlugX Payload and Config Extractor.')
    parser.add_argument('file_path', type=str, help='File path of the PlugX Shellcode')

    args = parser.parse_args()
    main(args.file_path)
