import argparse
import re
import struct

import lznt1
import pefile


def read_file(file_path):
    """
    Given a file path return a buffer with the data

    :param file_path:
    :return:
    """
    with open(file_path, 'rb') as f:
        buffer = f.read()
    return buffer


def save_file(file_path, buffer):
    """
    Given a file path and a buffer creates a file in disk

    :param file_path:
    :param buffer:
    :return:
    """
    with open(file_path, 'wb') as f:
        f.write(buffer)


def brute_force_location(buffer, target, window=512):
    """
    Given an encrypted buffer, the window and the target word return the starting address of the encrypted data

    :param buffer:
    :param target:
    :param window:
    :return:
    """
    index = 0

    while True:
        tmp = xor_decrypt(buffer[index:index + window])

        if target in tmp:
            break

        index += 1
    return index


def brute_force_pe_location(buffer):
    """
    Given an encrypted buffer containing a PE, returns the starting address of the encrypted PE

    :param buffer:
    :return:
    """
    return brute_force_location(buffer, b'This')


def brute_force_pe_extraction(buffer, address):
    """
    Given a buffer and the PE start address returns the decrypted PE

    :param buffer:
	:param address:
    :return:
    """
    stop = 2500

    while True:
        try:
            return lznt1.decompress(xor_decrypt(buffer[address:address + stop])[16:])
        except ValueError:
            stop += 1


def xor_decrypt(buffer):
    """
    Decrypt PlugX payload and config

    :param buffer:
    :return:
    """
    key = struct.unpack('<I', buffer[0:4])[0]
    key_a, key_b, key_c = key, key, key
    result = bytes([])

    for char in buffer:
        key = (key + (key >> 3) - 0x11111111) & 0xFFFFFFFF
        key_a = (key_a + (key_a >> 5) - 0x22222222) & 0xFFFFFFFF
        key_b = (key_b - (key_b << 7) + 0x33333333) & 0xFFFFFFFF
        key_c = (key_c - (key_c << 9) + 0x44444444) & 0xFFFFFFFF

        result += bytes([char ^ ((key + key_a + key_b + key_c) & 0x000000FF)])

    return result


def get_data_section(file_path):
    """
    Locate configuration section

    :param file_path:
    :return:
    """
    return pefile.PE(file_path).sections[2].get_data()


def x64_analysis(sc):
    """
    Run analysis logic for x64 binaries

    :param sc:
    :return:
    """
    # Find main shellcode function
    print('[+] Finding main shellcode function')
    main_index = sc.index(b'\xe8\x05', 0, 96)

    # Find DLL pointer in shellcode
    print('[+] Extracting address of the encrypted DLL')
    dll_index = main_index - 30
    dll_ptr = struct.unpack('<I', sc[dll_index:dll_index + 4])[0]

    # Find DLL size
    print('[+] Extracting size of the encrypted DLL')
    size_index = main_index - 24
    size = struct.unpack('<I', sc[size_index:size_index + 4])[0]

    # Extract DLL
    print('[+] Decrypting PlugX DLL')
    dll_data = lznt1.decompress(xor_decrypt(sc[dll_ptr:dll_ptr + size])[16:])

    # Saving DLL
    print('[+] Saving PlugX DLL')
    save_file('plug_x_dll.bin', dll_data)

    # Extracting embedded DLL
    print('[+] Extracting embedded DLL (Privilege Escalation)')
    section_data = get_data_section('plug_x_dll.bin')
    embedded_dll_data = brute_force_pe_extraction(section_data, brute_force_pe_location(section_data))
    save_file('plug_x_embedded_dll.bin', embedded_dll_data)

    # Extract config
    print('[+] Decrypting attack configuration')
    config_data = xor_decrypt(sc[dll_ptr + size:])
    save_file('config.bin', config_data)

    servers = re.finditer(b'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', config_data)

    print('[+] C2 servers:')
    for server in servers:
        port = struct.unpack("<I", config_data[server.start() - 2:server.start()] + b"\x00\x00")[0]
        print(f'\t[-] {config_data[server.start():server.end()].decode()}:{port}')


def x32_analysis(sc):
    """
    Run analysis logic for x32 binaries

    :param sc:
    :return:
    """
    # Find DLL pointer in shellcode
    print('[+] Extracting address of the encrypted DLL')
    dll_ptr = brute_force_pe_location(sc)

    # Find DLL size
    print('[+] Extracting size of the encrypted DLL')
    size_index = dll_ptr - 9
    size = struct.unpack('<I', sc[size_index:size_index + 4])[0]

    # Extract DLL
    print('[+] Decrypting PlugX DLL')
    dll_data = lznt1.decompress(xor_decrypt(sc[dll_ptr:dll_ptr + size])[16:])

    # Saving DLL
    print('[+] Saving PlugX DLL')
    save_file('plug_x_dll.bin', dll_data)

    # Extracting embedded DLL
    print('[+] Extracting embedded DLL (Privilege Escalation)')
    section_data = get_data_section('plug_x_dll.bin')
    embedded_dll_data = brute_force_pe_extraction(section_data, brute_force_pe_location(section_data))
    save_file('plug_x_embedded_dll.bin', embedded_dll_data)

    # Extract config
    print('[+] Decrypting attack configuration')
    config_size = 5388
    confid_ptr = brute_force_location(sc, b'HTTP', config_size)
    config_data = xor_decrypt(sc[confid_ptr:confid_ptr + config_size])
    save_file('config.bin', config_data)

    servers = re.finditer(b'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', config_data)

    print('[+] C2 servers:')
    for server in servers:
        port = struct.unpack("<I", config_data[server.start() - 2:server.start()] + b"\x00\x00")[0]
        print(f'\t[-] {config_data[server.start():server.end()].decode()}:{port}')


def main(file_path):
    """
    Main logic of the script

    :return:
    """
    print(f'[+] Analyzing shellcode at "{file_path}"')
    sc = read_file(file_path)
    try:
        x64_analysis(sc)
    except:
        x32_analysis(sc)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PlugX Payload and Config Extractor.')
    parser.add_argument('file_path', type=str, help='File path of the PlugX Shellcode')
    parser.add_argument('--mode', type=str, default='sc', help='Shellcode analysis')

    args = parser.parse_args()

    if args.mode != 'config':
        main(args.file_path)
    else:
        print(f'[+] Analyzing config file at "{args.file_path}"')
        data = read_file(args.file_path)

        with open('config.bin', 'wb') as f:
            f.write(xor_decrypt(data))
