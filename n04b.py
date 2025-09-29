import usb.core
import usb.util
import struct
import random
import sys
import time

dev = None
devices = [
    (0x0409, 0x0144), # FOMA N901iS
    (0x0409, 0x0244), # FOMA N906imyu
    (0x0a3c, 0x000d),
    (0x409, 0x14c),
    (0xfce, 0xd082),
    (0x0409, 0x0294),
    (0x0409, 0x02c0),
    (0x0409, 0x025c),
    (0x0409, 0x02f8),
    (0x0409, 0x047a),
    (0x0409, 0x0418),
]

for vid, pid in devices:
    dev = usb.core.find(idVendor=vid, idProduct=pid)
    if dev is not None:
        break

if dev is None:
    raise ValueError("Device not found")


def mask_packet(pkt):
    out = [0xFF]
    ck = 0
    for b in pkt:
        if b in [0xFD, 0xFE, 0xFF]:
            out.append(0xFD)
            out.append(b ^ 0x10)
        else:
            out.append(b)
        ck += b
    ck = (-ck) & 0xFF
    if ck in [0xFD, 0xFE, 0xFF]:
        out.append(0xFD)
        out.append(ck ^ 0x10)
    else:
        out.append(ck)
    out.append(0xFE)

    return bytearray(out)


def make_packet(cmd, subcmd, variable_payload=None):
    if variable_payload is None:
        variable_payload = b""
    packet = struct.pack("<BBBHBBBB", 0xE9, 0xE3, 0x42, 6 + len(variable_payload), 0, 0, cmd, subcmd) + variable_payload
    return mask_packet(packet)


def comm_oneway(cmd, subcmd=0, variable_payload=None):
    pkt = make_packet(cmd, subcmd, variable_payload)
    ret = dev.write(0x8, pkt)


def unmask_resp(resp):
    assert resp[0] == 0xFF
    assert resp[-1] == 0xFE
    resp = resp[1:-1]
    out = []
    x = 0
    while x < len(resp):
        if resp[x] == 0xFD:
            out.append(resp[x+1] ^ 0x10)
            x += 2
        else:
            out.append(resp[x])
            x += 1
    return bytearray(out)


def recv_resp():
    resp = b""
    while True:
        resp += dev.read(0x87, 64)
        if resp.endswith(b"\xFE"):
            break
    return unmask_resp(resp)


def comm(cmd, subcmd=0, variable_payload=None, slow=False):
    comm_oneway(cmd, subcmd, variable_payload)
    if slow:
        time.sleep(1)
    return recv_resp()


def read_addr(addr, sz):
    data = comm(6, 0, variable_payload=struct.pack("<IH", addr, sz))
    assert len(data) == sz + 10
    return data[9:-1]


def cmd_write(addr, data):
    comm_oneway(4, variable_payload=struct.pack("<IH", addr, len(data)) + data)


def comm2(cmd, variable_payload=None):
    if variable_payload is None:
        variable_payload = b""
    packet = struct.pack("<BBBHBBBB", 0xE0, 0xE0, 0x40, 6 + len(variable_payload), 0, 0, 0x5F, cmd) + variable_payload
    packet = mask_packet(packet)
    ret = dev.write(0x8, packet)
    return recv_resp()

def comm3(cmd, variable_payload=None):
    if variable_payload is None:
        variable_payload = b""
    packet = struct.pack("<BBBHBBBB", 0xE0, 0xE0, 0x40, 6 + len(variable_payload), 0, 0, 0x01, cmd) + variable_payload
    packet = mask_packet(packet)
    ret = dev.write(0x8, packet)
    return recv_resp()


def leak_2b(start, end=None):
    if end is None:
        end = start
    data = comm2(0x0B, variable_payload=struct.pack("<IIH", start, end, 0x0000))
    return data[-2:]


def leak_2b_cmp(addr, chk):
    data = comm2(0x0B, variable_payload=struct.pack("<IIH", addr, addr, chk))
    return data[-4:-2] == b"\x00\x00"


def read_page(addr):
    data = comm3(0x01, variable_payload=b"\x00\x00" + struct.pack("<IBBB", addr, 0, 0, 0x10))
    assert len(data) == 0x100B
    return data[0xB:]


def main():
    global dev

    # go into serial comms mode => turns green led on for some, display on
    print(dev.ctrl_transfer(0x41, 0x60, 0x60, 2))
    print(bytearray(dev.read(0x86, 64)).hex())

    time.sleep(3)
    dev = usb.core.find(idVendor=dev.idVendor, idProduct=dev.idProduct)

    # enter IPLMTS mode
    print(comm(3, variable_payload=b"\x20", slow=True).hex())
    print(comm2(0x00).hex())

    with open("dump.bin", "wb") as outf:
        for addr in range(0, 128 * 1024 * 1024, 0x1000):
            try:
                outf.write(read_page(addr))
            except Exception:
                print("error addr 0x{:X}".format(addr))


if __name__ == "__main__":
    main()
