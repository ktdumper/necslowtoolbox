#include <inttypes.h>

#include "printf.c"

/* font, print functions are from PSPSDK */
/*
 * PSP Software Development Kit - https://github.com/pspdev
 * -----------------------------------------------------------------------
 * Licensed under the BSD license, see LICENSE in PSPSDK root for details.
 *
 * scr_printf.c - Debug screen functions.
 *
 * Copyright (c) 2005 Marcus R. Brown <mrbrown@ocgnet.org>
 * Copyright (c) 2005 James Forshaw <tyranid@gmail.com>
 * Copyright (c) 2005 John Kelley <ps2dev@kelley.ca>
 *
 */

typedef uint8_t u8;
typedef uint16_t u16;

#include "font.c"
#define DISPLAY_W 240
#define VRAM_ADDR 0x80c9d000

static void debug_put_char_16(int x, int y, u16 color, u16 bgc, u8 ch) {
    int 	i,j, l;
    u8	*font;
    u16 *vram_ptr;
    u16 *vram;

    vram = (void*)VRAM_ADDR;
    vram += x;
    vram += (y * DISPLAY_W);

    font = &msx[ (int)ch * 8];
    for (i=l=0; i < 8; i++, l+= 8, font++) {
        vram_ptr  = vram;
        for (j=0; j < 8; j++) {
            if ((*font & (128 >> j)))
                *vram_ptr = color;
            else
                *vram_ptr = bgc;

            vram_ptr++;
        }
        vram += DISPLAY_W;
    }
}

int g_x = 0;
int g_y = 0;

void _putchar(char ch) {
    if (ch == '\n') {
        g_x = 0;
        g_y++;
    } else {
        debug_put_char_16(g_x * 8, g_y * 8, 0xFFFF, 0x0000, ch);
        g_x++;
        if (g_x * 8 >= DISPLAY_W) {
            g_y++;
            g_x = 0;
        }
    }
    if (g_y * 8 >= 400) {
        g_x = g_y = 0;
    }
}

void hexdump(void *data, size_t sz) {
    uint8_t *cbuf = data;
    for (size_t i = 0; i < sz; ++i) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02X ", cbuf[i]);
    }
    printf("\n");
}

uint8_t desc[] = { %desc% };
uint8_t *ptrs[16];

uint8_t *dump_addr = (void*)%dump_addr%;
#define CHUNK 32
uint8_t sync = 0x42;

int main() {
    static int once;

    if (!once) {
        once = 1;

        uint32_t *fb = (void*)0x80c9d000;
        for (int i = 0; i < 0x10000; ++i)
            fb[i] = 0x42424242;

        printf("nec dumper\n");

        /* patch out the smc #0 instruction, so we can re-enter the payload */
        for (uint32_t *addr = (uint32_t*)0x80010000; addr < (uint32_t*)0x81000000; ++addr) {
            if (*addr == 0xe1600070) {
                /* clean dcache */
                __asm__ volatile("mcr p15, 0, %0, c7, c10, 1" :: "r"(addr));
                *addr = 0x00000000;
            }
        }

        /* invalidate icache */
        __asm__ volatile("mcr p15, 0, %0, c7, c5, 0" :: "r"(0));

        int num = 0;
        for (uint8_t *ptr = (uint8_t*)0x80010000; ptr < (uint8_t*)0x81000000; ++ptr) {
            int found = 1;
            for (int i = 2; i < sizeof(desc); ++i)
                if (ptr[i - 2] != desc[i]) {
                    found = 0;
                    break;
                }
            if (found) {
                printf("found at %p\n", ptr);
                ptrs[num++] = ptr;
            }
        }

        printf("scan complete!\n");
    } else {
        for (int i = 0; i < sizeof(ptrs)/sizeof(*ptrs); ++i) {
            if (!ptrs[i])
                break;
            for (int j = 0; j < CHUNK; ++j)
                ptrs[i][j] = dump_addr[j];
            ptrs[i][CHUNK] = sync;
        }

        if ((uint32_t)dump_addr % 0x1000 == 0)
            printf("read 0x%08X\n", dump_addr);

        dump_addr += CHUNK;
        ++sync;
    }
}

__asm__(
    ".section .text.start\n"
    ".global start\n"
    "start:\n"
    /* disable mmu which got enabled by the jumper */
    // "mrc p15, 0, r0, c1, c0, 0\n"
    // "bic r0, r0, #0x1\n"
    // "mcr p15, 0, r0, c1, c0, 0\n"

    "b main\n"
);
