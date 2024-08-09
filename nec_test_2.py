import usb.core
import argparse
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--vid', type=lambda x: int(x, 16), required=True)
    parser.add_argument('--pid', type=lambda x: int(x, 16), required=True)

    args = parser.parse_args()
    dev = usb.core.find(idVendor=args.vid, idProduct=args.pid)
    if dev is None:
        raise RuntimeError("cannot find device with VID={:04X} PID={:04X}".format(args.vid, args.pid))

    # go into serial comms mode => turns green led on for some, display on
    dev.ctrl_transfer(0x41, 0x60, 0x60, 2)
    dev.read(0x86, 64)

    time.sleep(3)
    dev = usb.core.find(idVendor=args.vid, idProduct=args.pid)

    print("This should NOT corrupt the display area. Run the script for longer than nec_test_1")

    while True:
        dev.write(8, b"\x00" * 64)


if __name__ == "__main__":
    main()
