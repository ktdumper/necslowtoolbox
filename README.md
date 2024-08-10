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
