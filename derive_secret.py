import sys
import struct


def derive_secret(keybox):
    magic_table = []
    cur = 0
    for line in range(2):
        magic_table.append([])
        for x in range(5):
            magic_table[-1].append(struct.unpack("<I", keybox[cur:cur+4])[0])
            cur += 4

    line = 0
    xored_buffer = b""
    for idx in range(5):
        if idx == 3 or idx == 4:
            x = magic_table[line][idx]
        else:
            x = magic_table[line + 1][idx]

        xored_buffer += struct.pack("<I", (~x) & 0xFFFFFFFF)

    return xored_buffer


def main():
    print(derive_secret(bytes.fromhex(sys.argv[1])).hex())


if __name__ == "__main__":
    main()
