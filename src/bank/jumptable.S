; The TLS bank's jump table and entry prologue: the SSH client's bank
; (its src/bank/jumptable.S), with this client's entries; mega-net's shape
; (its src/abi/jumptable.S), with the bank's own zero page $70-$FF
; swapped in on entry and the caller's back on exit ($68-$FF here), and the bank's
; own soft stack at $BC00-$BFFF while the caller's memory is hidden.
        .section .jumptable,"ax",@progbits
        .global ck_jumptable
ck_jumptable:
        jmp     ck_entry_init             ; $2000  A=0 ok
        jmp     ck_entry_version          ; $2003  A=major X=minor
        jmp     ck_entry_random_seed      ; $2006  A/X/Y -> {ptr28, len16}: entropy into the pool
        jmp     ck_entry_random           ; $2009  A/X/Y -> {out28, n u8}
        jmp     ck_entry_transcript_init  ; $200C
        jmp     ck_entry_transcript_update ; $200F A/X/Y -> {ptr28, len16}
        jmp     ck_entry_transcript_hash  ; $2012  A/X/Y -> {out28}: the hash so far, the transcript kept open
        jmp     ck_entry_keyshare         ; $2015  A/X/Y -> {out28}: a fresh X25519 public key
        jmp     ck_entry_keys_handshake   ; $2018  A/X/Y -> {peer28, hash28}
        jmp     ck_entry_keys_master      ; $201B  A/X/Y -> {hash28}
        jmp     ck_entry_write_switch     ; $201E
        jmp     ck_entry_read_switch      ; $2021
        jmp     ck_entry_finished         ; $2024  A/X/Y -> {server u8, hash28, out28}
        jmp     ck_entry_seal             ; $2027  A/X/Y -> {rec28, len16}: in place, the tag appended
        jmp     ck_entry_open_start       ; $202A  A/X/Y -> {hdr28}
        jmp     ck_entry_open_data        ; $202D  A/X/Y -> {ptr28, len16}: in place
        jmp     ck_entry_open_check       ; $2030  A/X/Y -> {tag28}; A=1 if it matched
        jmp     ck_entry_cert_reset       ; $2033
        jmp     ck_entry_cert_append      ; $2036  A/X/Y -> {ptr28, len16}
        jmp     ck_entry_cert_len         ; $2039  A/X = the length
        jmp     ck_entry_verify           ; $203C  A/X/Y -> {scheme16, hash28, sig28, siglen16}; A = 0 wrong, 1 verified, 2 unchecked
        jmp     ck_entry_pin              ; $203F  A/X/Y -> {out28}; A=1 if the certificate could be read
        jmp     ck_entry_selftest         ; $2042  A=1 if P-256 verifies RFC 6979's vector here
        jmp     ck_entry_render           ; $2045  A/X/Y -> {from u32, len u32, plain u8; out rows u16, links u16, truncated u8}

        ; the registers and the swapped zero page live in the top window
        ; ($E000, crypto.ld), reached as any absolute address: the room
        ; below the bank's stack ran out (5.8)
        .section .noinit,"aw",@nobits
        .global ck_api_a, ck_api_x, ck_api_y, ck_api_z
        .global ck_api_ra, ck_api_rx, ck_api_ry, ck_api_rz
ck_api_a:  .skip 1
ck_api_x:  .skip 1
ck_api_y:  .skip 1
ck_api_z:  .skip 1
ck_api_ra: .skip 1
ck_api_rx: .skip 1
ck_api_ry: .skip 1
ck_api_rz: .skip 1
ck_zp_caller: .skip 0x98        ; the caller's $68-$FF while we run
ck_zp_ours:   .skip 0x98        ; our $68-$FF between calls

        .section .text,"ax",@progbits
        .macro ENTRY name, cfunc
        .global \name
\name:
        sta     ck_api_a
        stx     ck_api_x
        sty     ck_api_y
        stz     ck_api_z
        ldz     #0              ; our C stores zero with STZ: Z must be 0
        php
        sei
        jsr     ck_prologue
        jsr     \cfunc
        jmp     ck_epilogue
        .endm
        ENTRY ck_entry_init,             ck_api_init
        ENTRY ck_entry_version,          ck_api_version
        ENTRY ck_entry_random_seed,      ck_api_random_seed
        ENTRY ck_entry_random,           ck_api_random
        ENTRY ck_entry_transcript_init,  ck_api_transcript_init
        ENTRY ck_entry_transcript_update, ck_api_transcript_update
        ENTRY ck_entry_transcript_hash,  ck_api_transcript_hash
        ENTRY ck_entry_keyshare,         ck_api_keyshare
        ENTRY ck_entry_keys_handshake,   ck_api_keys_handshake
        ENTRY ck_entry_keys_master,      ck_api_keys_master
        ENTRY ck_entry_write_switch,     ck_api_write_switch
        ENTRY ck_entry_read_switch,      ck_api_read_switch
        ENTRY ck_entry_finished,         ck_api_finished
        ENTRY ck_entry_seal,             ck_api_seal
        ENTRY ck_entry_open_start,       ck_api_open_start
        ENTRY ck_entry_open_data,        ck_api_open_data
        ENTRY ck_entry_open_check,       ck_api_open_check
        ENTRY ck_entry_cert_reset,       ck_api_cert_reset
        ENTRY ck_entry_cert_append,      ck_api_cert_append
        ENTRY ck_entry_cert_len,         ck_api_cert_len
        ENTRY ck_entry_verify,           ck_api_verify
        ENTRY ck_entry_pin,              ck_api_pin
        ENTRY ck_entry_selftest,         ck_api_selftest
        ENTRY ck_entry_render,           ck_api_render

ck_prologue:
        lda     #0x47           ; the MEGA65 I/O personality, every time
        sta     0xD02F
        lda     #0x53
        sta     0xD02F
        ldx     #0
swap_in:
        lda     $68,x
        sta     ck_zp_caller,x
        lda     ck_zp_ours,x
        sta     $68,x
        inx
        cpx     #0x98
        bne     swap_in
        lda     #0x00
        sta     __rc0
        lda     #0xC0           ; soft stack: $BC00-$BFFF, grows down
        sta     __rc1
        rts
ck_epilogue:
        ldx     #0
swap_out:
        lda     $68,x
        sta     ck_zp_ours,x
        lda     ck_zp_caller,x
        sta     $68,x
        inx
        cpx     #0x98
        bne     swap_out
        lda     ck_api_ra
        ldx     ck_api_rx
        ldy     ck_api_ry
        ldz     ck_api_rz
        plp                     ; the caller's I flag back
        rts
