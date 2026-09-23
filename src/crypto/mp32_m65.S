; A Montgomery row of any length over 32-bit limbs on the 45GS02's math
; unit, in the Q register, for mp.c's mont32 (REQUIREMENTS.md 5.12):
; RSA on the machine.
;
;   for k in 0..cnt-1:
;       acc    = in[k] + a * p[k] + carry        (at most 2^64 - 1)
;       out[k] = acc mod 2^32
;       carry  = acc >> 32
;
; a is MULTINA ($D770) for the whole row, p[k] MULTINB ($D774) per limb,
; the 64-bit product read from $D778 (low) and $D77C (high). The limbs'
; addresses are patched into the three instructions that touch them and
; stepped by four each limb (a Q instruction on a symbol assembles in
; zero-page form, ssh 5.11, and the Q ops clobber X, Y and Z, so nothing
; indexes): any length, cnt at most 255. out may be in itself, or one
; limb below it (the reduction row's shift). Nothing reads the
; multiplier's output into its input (5.6). No zero page; Z zero on
; return; short branches, a jmp for the loop (PLATFORM.md trap 3).

        .macro LDQA sym
        .byte 0x42, 0x42
        lda \sym
        .endm
        .macro STQA sym
        .byte 0x42, 0x42
        sta \sym
        .endm
        .macro ADCQ sym
        .byte 0x42, 0x42
        adc \sym
        .endm

        .section .bss,"aw",@nobits
        .global mp32_a, mp32_cy, mp32_in, mp32_p, mp32_out, mp32_cnt
mp32_a:   .skip 4                 ; the row's multiplier
mp32_cy:  .skip 4                 ; the carry in, and out
mp32_in:  .skip 2                 ; the three arrays' addresses
mp32_p:   .skip 2
mp32_out: .skip 2
mp32_cnt: .skip 1                 ; limbs, 1 to 255
lo4:      .skip 4
hi4:      .skip 4
zero4:    .skip 4

        .text
        .global mp_row32_m65
mp_row32_m65:
        lda mp32_a              ; MULTINA = a, a byte at a time as mp256_m65.S writes the registers
        sta 0xd770
        lda mp32_a+1
        sta 0xd771
        lda mp32_a+2
        sta 0xd772
        lda mp32_a+3
        sta 0xd773
        lda #0
        sta zero4
        sta zero4+1
        sta zero4+2
        sta zero4+3
        lda mp32_in             ; the first limb's addresses into the instructions
        sta ld_in+3
        lda mp32_in+1
        sta ld_in+4
        lda mp32_p
        sta ld_p+3
        lda mp32_p+1
        sta ld_p+4
        lda mp32_out
        sta st_out+3
        lda mp32_out+1
        sta st_out+4
limb:
ld_p:   LDQA 0x2000             ; p[k] -> MULTINB (the address patched), a byte at a time
        sta 0xd774
        stx 0xd775
        sty 0xd776
        stz 0xd777              ; the Z register (PLATFORM.md trap 2), the fourth byte
        clc                     ; the next p[k], while the product forms
        lda ld_p+3
        adc #4
        sta ld_p+3
        bcc p_ok
        inc ld_p+4
p_ok:
        ; lo = product.lo32 + in[k], C1; hi = product.hi32 + C1 (no overflow: the high half is at most 2^32 - 2)
        LDQA 0xd778
        clc
ld_in:  ADCQ 0x2000             ; in[k] (patched)
        STQA lo4
        LDQA 0xd77c
        ADCQ zero4
        STQA hi4
        ; out[k] = lo + carry, C2; carry = hi + C2
        LDQA lo4
        clc
        ADCQ mp32_cy
st_out: STQA 0x2000             ; out[k] (patched)
        LDQA hi4
        ADCQ zero4
        STQA mp32_cy
        clc                     ; the next in[k] and out[k]
        lda ld_in+3
        adc #4
        sta ld_in+3
        bcc in_ok
        inc ld_in+4
in_ok:
        clc
        lda st_out+3
        adc #4
        sta st_out+3
        bcc out_ok
        inc st_out+4
out_ok:
        dec mp32_cnt
        beq done
        jmp limb
done:
        ldz #0
        rts
