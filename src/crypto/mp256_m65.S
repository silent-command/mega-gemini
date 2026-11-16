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
; mp_redp256_m65, at the end, does all eight rounds for P-256's p.

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
        .macro SBCQ sym
        .byte 0x42, 0x42
        sbc \sym
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
rp_neg:     .skip 1                 ; mp_redp256_m65: 0 adds mu at t[kk], 1 subtracts it

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

; ---- mp_redp256_m65: the eight rounds at once, for P-256's p alone ----
;
; p = 2^256 - 2^224 + 2^192 + 2^96 - 1, and its n0 is 1, so mu = t[i]
; and the row mu * p is no products at all: adding it at limb i cancels
; t[i] and adds mu at t[i+3], t[i+6] and t[i+8] and takes it from
; t[i+7] (the additions first, so the number never goes below zero). The
; same integer as mp_round256_m65's rows, so the same result, bit for
; bit; mp.c does the final subtraction as before. Each limb operation
; runs on the Q register at a patched address, its carry or borrow
; carried on through t[15] into mp_asm_top.
        .global mp_redp256_m65
mp_redp256_m65:
        lda #0
        sta mp_asm_top
        sta mp_asm_i
        sta zero4
        sta zero4+1
        sta zero4+2
        sta zero4+3
rp_round:
        lda mp_asm_i            ; mu = t[i]
        asl
        asl
        tax
        lda fe_mul_out,x
        sta mp_asm_mu
        lda fe_mul_out+1,x
        sta mp_asm_mu+1
        lda fe_mul_out+2,x
        sta mp_asm_mu+2
        lda fe_mul_out+3,x
        sta mp_asm_mu+3
        lda #0
        sta rp_neg
        lda mp_asm_i
        clc
        adc #3
        jsr rp_op               ; t[i+3] += mu
        lda mp_asm_i
        clc
        adc #6
        jsr rp_op               ; t[i+6] += mu
        lda mp_asm_i
        clc
        adc #8
        jsr rp_op               ; t[i+8] += mu
        inc rp_neg
        lda mp_asm_i
        clc
        adc #7
        jsr rp_op               ; t[i+7] -= mu
        inc mp_asm_i
        lda mp_asm_i
        cmp #8
        bcs rp_done
        jmp rp_round
rp_done:
        ldz #0
        rts

; t[A] += mu (rp_neg 0) or -= mu (rp_neg 1), carried on to the top
rp_op:
        sta kk
        jsr rp_at
        lda rp_neg
        bne rp_minus
        clc
rp_l1:  LDQA fe_mul_out
        ADCQ mp_asm_mu
rp_s1:  STQA fe_mul_out
        bcc rp_ret
rp_up:
        inc kk                  ; a carry: 1 into the next limb
        lda kk
        cmp #16
        bcs rp_top
        jsr rp_at
        sec
rp_l2:  LDQA fe_mul_out
        ADCQ zero4
rp_s2:  STQA fe_mul_out
        bcs rp_up
rp_ret:
        rts
rp_top:
        inc mp_asm_top
        rts
rp_minus:
        sec
rp_l3:  LDQA fe_mul_out
        SBCQ mp_asm_mu
rp_s3:  STQA fe_mul_out
        bcs rp_ret
rp_down:
        inc kk                  ; a borrow: 1 from the next limb
        lda kk
        cmp #16
        bcs rp_bottom
        jsr rp_at
        clc
rp_l4:  LDQA fe_mul_out
        SBCQ zero4
rp_s4:  STQA fe_mul_out
        bcc rp_down
        rts
rp_bottom:
        dec mp_asm_top
        rts

; the address of t[kk] into the eight Q instructions that touch it
rp_at:
        lda kk
        asl
        asl
        clc
        adc #mos16lo(fe_mul_out)
        sta rp_l1+3
        sta rp_s1+3
        sta rp_l2+3
        sta rp_s2+3
        sta rp_l3+3
        sta rp_s3+3
        sta rp_l4+3
        sta rp_s4+3
        lda #mos16hi(fe_mul_out)
        adc #0
        sta rp_l1+4
        sta rp_s1+4
        sta rp_l2+4
        sta rp_s2+4
        sta rp_l3+4
        sta rp_s3+4
        sta rp_l4+4
        sta rp_s4+4
        rts
