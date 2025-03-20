/*------------------------------------------------------------------------
 *    SNOW_3G.c
 *------------------------------------------------------------------------*/
#include "SNOW_3G.h"

/* LFSR */
u32 LFSR_S0 = 0x00;
u32 LFSR_S1 = 0x00;
u32 LFSR_S2 = 0x00;
u32 LFSR_S3 = 0x00;
u32 LFSR_S4 = 0x00;
u32 LFSR_S5 = 0x00;
u32 LFSR_S6 = 0x00;
u32 LFSR_S7 = 0x00;
u32 LFSR_S8 = 0x00;
u32 LFSR_S9 = 0x00;
u32 LFSR_S10 = 0x00;
u32 LFSR_S11 = 0x00;
u32 LFSR_S12 = 0x00;
u32 LFSR_S13 = 0x00;
u32 LFSR_S14 = 0x00;
u32 LFSR_S15 = 0x00;

/* FSM */
u32 FSM_R1 = 0x00;
u32 FSM_R2 = 0x00;
u32 FSM_R3 = 0x00;

/* Rijndael S-box SR */
u8 SR[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    /* Remaining values omitted for brevity */
};

/* S-box SQ */
u8 SQ[256] = {
    0x25, 0x24, 0x73, 0x67, 0xD7, 0xAE, 0x5C, 0x30, 0xA4, 0xEE, 0x6E, 0xCB, 0x7D, 0xB5, 0x82, 0xDB,
    /* Remaining values omitted for brevity */
};

/* MULx */
u8 MULx(u8 V, u8 c) {
    if (V & 0x80)
        return ((V << 1) ^ c);
    else
        return (V << 1);
}

/* MULxPOW */
u8 MULxPOW(u8 V, u8 i, u8 c) {
    if (i == 0)
        return V;
    else
        return MULx(MULxPOW(V, i - 1, c), c);
}

/* MULalpha */
u32 MULalpha(u8 c) {
    return (((u32)MULxPOW(c, 23, 0xa9) << 24) |
            ((u32)MULxPOW(c, 245, 0xa9) << 16) |
            ((u32)MULxPOW(c, 48, 0xa9) << 8) |
            ((u32)MULxPOW(c, 239, 0xa9)));
}

/* DIValpha */
u32 DIValpha(u8 c) {
    return (((u32)MULxPOW(c, 16, 0xa9) << 24) |
            ((u32)MULxPOW(c, 39, 0xa9) << 16) |
            ((u32)MULxPOW(c, 6, 0xa9) << 8) |
            ((u32)MULxPOW(c, 64, 0xa9)));
}

/* S1 S-Box */
u32 S1(u32 w) {
    u8 srw0 = SR[(u8)((w >> 24) & 0xff)];
    u8 srw1 = SR[(u8)((w >> 16) & 0xff)];
    u8 srw2 = SR[(u8)((w >> 8) & 0xff)];
    u8 srw3 = SR[(u8)(w & 0xff)];

    u8 r0 = (MULx(srw0, 0x1b) ^ srw1 ^ srw2 ^ (MULx(srw3, 0x1b) ^ srw3));
    u8 r1 = (MULx(srw0, 0x1b) ^ srw0 ^ MULx(srw1, 0x1b) ^ srw2 ^ srw3);
    u8 r2 = (srw0 ^ MULx(srw1, 0x1b) ^ srw1 ^ MULx(srw2, 0x1b) ^ srw3);
    u8 r3 = (srw0 ^ srw1 ^ MULx(srw2, 0x1b) ^ srw2 ^ MULx(srw3, 0x1b));

    return ((r0 << 24) | (r1 << 16) | (r2 << 8) | r3);
}

/* S2 S-Box */
u32 S2(u32 w) {
    u8 sqw0 = SQ[(u8)((w >> 24) & 0xff)];
    u8 sqw1 = SQ[(u8)((w >> 16) & 0xff)];
    u8 sqw2 = SQ[(u8)((w >> 8) & 0xff)];
    u8 sqw3 = SQ[(u8)(w & 0xff)];

    u8 r0 = (MULx(sqw0, 0x69) ^ sqw1 ^ sqw2 ^ (MULx(sqw3, 0x69) ^ sqw3));
    u8 r1 = (MULx(sqw0, 0x69) ^ sqw0 ^ MULx(sqw1, 0x69) ^ sqw2 ^ sqw3);
    u8 r2 = (sqw0 ^ MULx(sqw1, 0x69) ^ sqw1 ^ MULx(sqw2, 0x69) ^ sqw3);
    u8 r3 = (sqw0 ^ sqw1 ^ MULx(sqw2, 0x69) ^ sqw2 ^ MULx(sqw3, 0x69));

    return ((r0 << 24) | (r1 << 16) | (r2 << 8) | r3);
}

/* FSM Clocking */
u32 ClockFSM() {
    u32 F = ((LFSR_S15 + FSM_R1) & 0xffffffff) ^ FSM_R2;
    u32 r = (FSM_R2 + (FSM_R3 ^ LFSR_S5)) & 0xffffffff;

    FSM_R3 = S2(FSM_R2);
    FSM_R2 = S1(FSM_R1);
    FSM_R1 = r;

    return F;
}

/* Initialize */
void Initialize(u32 k[4], u32 IV[4]) {
    int i;
    u32 F = 0x0;

    LFSR_S15 = k[3] ^ IV[0];
    LFSR_S14 = k[2];
    LFSR_S13 = k[1];
    LFSR_S12 = k[0] ^ IV[1];
    LFSR_S11 = k[3] ^ 0xffffffff;
    LFSR_S10 = k[2] ^ 0xffffffff ^ IV[2];
    LFSR_S9 = k[1] ^ 0xffffffff ^ IV[3];
    LFSR_S8 = k[0] ^ 0xffffffff;

    FSM_R1 = 0x0;
    FSM_R2 = 0x0;
    FSM_R3 = 0x0;

    for (i = 0; i < 32; i++) {
        F = ClockFSM();
    }
}

/* Generate Keystream */
void GenerateKeystream(u32 n, u32 *ks) {
    u32 t, F;
    
    ClockFSM();
    
    for (t = 0; t < n; t++) {
        F = ClockFSM();
        ks[t] = F ^ LFSR_S0;
    }
}
