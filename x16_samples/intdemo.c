#include <dos.h>
#include <conio.h>

struct sample_info {
    unsigned dos_version;
    unsigned bios_kb;
    unsigned video_mode;
    unsigned cursor_shape;
    unsigned int21_segment;
    unsigned int21_offset;
};

static struct sample_info g_info;

static unsigned fold_values(unsigned a, unsigned b) {
    unsigned c;
    c = (a << 1) + b;
    if (c > 1000) {
        c -= 123;
    } else {
        c += 7;
    }
    return c;
}

static void query_interrupts(void) {
    union REGS inregs;
    union REGS outregs;
    struct SREGS sregs;

    inregs.h.ah = 0x30;
    int86(0x21, &inregs, &outregs);
    g_info.dos_version = ((unsigned)outregs.h.ah << 8) | outregs.h.al;

    inregs.h.ah = 0x0F;
    int86(0x10, &inregs, &outregs);
    g_info.video_mode = outregs.h.al;

    int86(0x12, &inregs, &outregs);
    g_info.bios_kb = outregs.x.ax;

    inregs.h.ah = 0x03;
    inregs.h.bh = 0;
    int86(0x10, &inregs, &outregs);
    g_info.cursor_shape = outregs.x.cx;

    inregs.h.ah = 0x35;
    inregs.h.al = 0x21;
    int86x(0x21, &inregs, &outregs, &sregs);
    g_info.int21_segment = sregs.es;
    g_info.int21_offset = outregs.x.bx;
}

static void show_summary(void) {
    cprintf("dos=%u bios=%u mode=%u\r\n",
        g_info.dos_version,
        g_info.bios_kb,
        g_info.video_mode);
}

int main(void) {
    query_interrupts();
    show_summary();
    return fold_values(g_info.video_mode, g_info.bios_kb & 0xFF);
}
