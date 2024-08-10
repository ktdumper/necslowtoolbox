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
#define VRAM_ADDR (*(uint32_t*)0x480504bc)

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

int main() {
    uint32_t *fb = (void*)VRAM_ADDR;
    for (int i = 0; i < 0x10000; ++i)
        fb[i] = 0x42424242;

    printf("nec persistence tester\n");

    printf("previous data:\n");
    hexdump(0x80010000, 0x100);

    uint8_t *addr = (void*)0x80010000;
    for (int i = 0; i < 0x100; ++i) {
        addr[i] = i;
        /* clean dcache */
        __asm__ volatile("mcr p15, 0, %0, c7, c10, 1" :: "r"(addr + i));
    }

    for (volatile int i = 0; i < 0x10000000; ++i) {}

    /* trigger reset */
    volatile uint32_t *PRM_RSTCTRL = (void*)0x48307250;
    *PRM_RSTCTRL = 4;

    while (1) {}
}

__asm__(
    ".section .text.start\n"
    ".global start\n"
    "start:\n"
    "b main\n"
);
