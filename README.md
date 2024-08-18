# necslowtoolbox

A slow (~40MB) USB buffer overflow exploit.

## Typical usage for recovering the device secret

First, run the overflow script with correct arguments (for N-05C and above/similar you can use the following verbatim):

```
python nec_overflow.py --vid 0409 --pid 02f8 --stage1 0x27400 --stage1_mask 0xFD000000 --stage2 0x2800000 --stage4 0x762000 --stage4_spam 0xe3a0f102
```

When successful, it will display a bunch of hex dump on the screen. See below for example. If the bytes don't look sufficiently random then it's probably not dumping it from the right address and you would have to adjust the payload.


Now write down all these bytes without spaces and execute derive_secret.py:

```
python derive_secret.py 4e7b9953281fe2024f253fbce7522b8884ecdbc0c1cc6f9bc683a90a170ed7bd8578021c0f585789
```

It will print out a single line, this is your `secret="xxx"` argument to put into ktdumper.

## General theory of operation

E.g. N-05C and later (strategy: code overwrite)

```
python nec_overflow.py --vid 0409 --pid 02f8 --stage1 0x27400 --stage1_mask 0xFD000000 --stage2 0x2800000 --stage4 0x762000 --stage4_spam 0xe3a0f102
```

strategy: iplmts

```
python nec_overflow.py --iplmts --vid 0409 --pid 02f8 --stage1 0x270c4 --stage1_mask 0xFD000000 --stage2 0x20da97c --stage4 0x2080 --stage4_spam 0xe3a0f102
```

persistence testing

```
python persist_1.py --vid 0409 --pid 02f8 --secret 3e339064397c56f5e8f1284218add4777b13243f
```
