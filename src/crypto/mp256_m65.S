; A 256-bit Montgomery multiplication on the 45GS02's math unit, for
; P-256 (REQUIREMENTS.md 5.6): the SSH client's fe_mul_m65 (mulacc_m65.S)
; makes the 512-bit product of fe_mul_in_a and fe_mul_in_b into
; fe_mul_out, eight 32-bit limbs each, and this reduces that product in
; place: eight rounds of
;
;     mu          = t[i] * n0   (mod 2^32; computed by mp.c)
;     t[i..i+8]  += mu * m       (a row of eight 64-bit products, the carry
;                                 carried on into t[i+9..15] and mp_asm_top)
;
; after which t[8..15] (plus the top bit) is a*b/R mod m, up to one
; subtraction of m, which mp.c does. mp.c drives the eight rounds. The row's arithmetic is in the Q
; register (A/X/Y/Z as one 32-bit word, the 0x42 0x42 prefix on an
; absolute instruction: the assembler would give a symbol the zero-page
; form, ssh 5.11), so the loop's indices live in memory and the limb's
; address is patched into the three instructions that touch it; no
; zero page, Z zero on return, every branch short, jmp for the loops.

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
        .global mp_asm_m, mp_asm_top, mp_asm_mu, mp_asm_i
mp_asm_m:   .skip 32                ; the modulus, eight 32-bit limbs
mp_asm_mu:  .skip 4                 ; this round's mu, from C
mp_asm_i:   .skip 1                 ; this round
mp_asm_top: .skip 1                 ; the carry out of t[15], summed over the rounds
lo4:        .skip 4
hi4:        .skip 4
cy4:        .skip 4                 ; the row's carry
zero4:      .skip 4
jj:         .skip 1
kk:         .skip 1

        .text
; One round i (mp_asm_i) of the reduction: t[i..i+8] += mu * m, the carry
; on into t[i+9..15] and mp_asm_top. mu is computed by mp.c, so nothing
; here reads the multiplier soon after writing it (5.6).
        .global mp_round256_m65
mp_round256_m65:
        lda #0
        sta zero4
        sta zero4+1
        sta zero4+2
        sta zero4+3
        sta cy4
        sta cy4+1
        sta cy4+2
        sta cy4+3
        sta jj
        lda mp_asm_mu
        sta 0xd770
        lda mp_asm_mu+1
        sta 0xd771
        lda mp_asm_mu+2
        sta 0xd772
        lda mp_asm_mu+3
        sta 0xd773
limb:
        ; MULTINB = m[j]
        lda jj
        asl
        asl
        tax
        lda mp_asm_m,x
        sta 0xd774
        lda mp_asm_m+1,x
        sta 0xd775
        lda mp_asm_m+2,x
        sta 0xd776
        lda mp_asm_m+3,x
        sta 0xd777
        ; the limb's address, fe_mul_out + 4*(i+j), into the Q instructions
        lda mp_asm_i
        clc
        adc jj
        asl
        asl
        clc
        adc #mos16lo(fe_mul_out)
        sta ld_t+3
        sta st_t+3
        lda #mos16hi(fe_mul_out)
        adc #0
        sta ld_t+4
        sta st_t+4
        ; lo = product.lo32 + t[i+j], C1; hi = product.hi32 + C1 (no overflow: the high half is at most 2^32 - 2)
        LDQA 0xd778
        clc
ld_t:   ADCQ fe_mul_out
        STQA lo4
        LDQA 0xd77c
        ADCQ zero4
        STQA hi4
        ; t[i+j] = lo + carry, C2; carry = hi + C2
        LDQA lo4
        clc
        ADCQ cy4
st_t:   STQA fe_mul_out
        LDQA hi4
        ADCQ zero4
        STQA cy4
        inc jj
        lda jj
        cmp #8
        bcs row_done
        jmp limb
row_done:
        ; t[i+8] += carry, then the carry bit on through t[i+9..15] and into the top
        lda mp_asm_i
        clc
        adc #8
        sta kk
propagate:
        lda kk
        cmp #16
        bcs into_top
        asl
        asl
        clc
        adc #mos16lo(fe_mul_out)
        sta ld_k+3
        sta st_k+3
        lda #mos16hi(fe_mul_out)
        adc #0
        sta ld_k+4
        sta st_k+4
        clc
ld_k:   LDQA fe_mul_out
        ADCQ cy4
st_k:   STQA fe_mul_out
        bcc done                ; no carry out: this round is done
        lda #0
        sta cy4
        sta cy4+1
        sta cy4+2
        sta cy4+3
        inc cy4                 ; from here on only the carry bit is added
        inc kk
        jmp propagate
into_top:
        inc mp_asm_top
done:
        ldz #0
        rts
