extern printf
extern strcmp
extern fflush

global _start

section .rodata
; Argument parsing
exclude_flag:
db  "-x", 0
include_flag:
db  "-i", 0

; Status
status_template_str:
db  0x09, "[", 0x1b, "[1;%dm%s", 0x1b, "[0;39m] %s", 0x0a, 0
unavailable_str:
db  "X Unavailable", 0     
available_str: 
db  " ✓ Available ", 0

section_prefixes_str:
db  "-------- PREFIXES --------", 0x0a, 0
    rex_str:
;    db  "REX:", 0x0a, 0
;        rexw_str:
;        db  "Use 64-bit operand size", 0
;        rexr_str:
;        db  "Extension to the MODRM.reg field", 0
;        rexx_str:
;        db  "Extension to the SIB.index field", 0
;        rexb_str:
;        db  "Extension to the MODRM.rm field or the SIB.base field", 0
    sizes_str:
    db  "Sizes:", 0x0a, 0
        operand_size_override_16_32_str:
        db  "Change operand size from 32 bit to 16 bit, or the contrary (D bit)", 0
        address_size_override_16_32_str:
        db  "Change address size from 64 bit to 32 bit, or 32 to 16, or 16 to 32", 0
    reps_str:
    db  "Repetitions:", 0x0a, 0
        rep_str:
        db  "REP, REPE/REPZ", 0
        repne_str:
        db  "REPNE/REPNZ", 0
    segments_str:
    db  "Segments:", 0x0a, 0
        cs_str:
        db  "CS", 0
        ss_str:
        db  "SS", 0
        ds_str:
        db  "DS", 0
        es_str:
        db  "ES", 0
        fs_str:
        db  "FS", 0
        gs_str:
        db  "GS", 0

; Errors
bad_args:
db  "Usage: ./shellcode-filter [-ix] bytes", 0x0a, 0
invalid_byte:
db  "Error : Given bytes are not valid hex", 0x0a, 0

section .bss
available:
resb    32

section .text
print_status:
    xor     rax, rax
    mov     rcx, rdi 
    lea     rdi, [status_template_str]
    add     rsi, 31
    cmp     rsi, 32
    je      print_available
    lea     rdx, [unavailable_str]
    call    printf
    ret
print_available:
    lea     rdx, [available_str]
    call    printf
    ret


_start:
    ; Parsing CLI arguments
    mov     rax, QWORD [rsp]
    cmp     rax, 0x3
    jne     err_bad_args

    mov     rdi, QWORD [rsp + 8*2]  ; First arg : Flag
    lea     rsi, [include_flag]
    call    strcmp
    jz      parse_bytes

    mov     rdi, QWORD [rsp + 8*2]
    lea     rsi, [exclude_flag]
    call    strcmp
    jnz     err_bad_args

    xor     rcx, rcx
loop0:
    mov     BYTE [available + rcx], 0xff 
    inc     rcx
    cmp     rcx, 32
    jb      loop0

parse_bytes:
    mov     r11, QWORD [rsp + 8*3]  ; Second arg : Given bytes      
    xor     rdi, rdi
    xor     rsi, rsi
    mov     dil, BYTE [r11]

loop1:
    cmp     rdi, 0x30
    jl     err_invalid_byte
    cmp     rdi, 0x39
    jg      not_a_number0          
    sub     rdi, 0x30
    jmp     other_digit
not_a_number0:
    cmp     rdi, 0x41
    jl     err_invalid_byte
    cmp     rdi, 0x46
    jg      not_a_lowercase0
    sub     rdi, 0x37
    jmp     other_digit
not_a_lowercase0:
    cmp     rdi, 0x61
    jl     err_invalid_byte
    cmp     rdi, 0x66
    jg      err_invalid_byte
    sub     rdi, 0x57

other_digit:
    inc     r11
    mov     sil, BYTE [r11]
    cmp     rsi, 0x30
    jl     err_invalid_byte
    cmp     rsi, 0x39
    jg      not_a_number1          
    sub     rsi, 0x30
    jmp     process_byte
not_a_number1:
    cmp     rsi, 0x41
    jl     err_invalid_byte
    cmp     rsi, 0x46
    jg      not_a_lowercase1
    sub     rsi, 0x37
    jmp     process_byte
not_a_lowercase1:
    cmp     rsi, 0x61
    jl     err_invalid_byte
    cmp     rsi, 0x66
    jg      err_invalid_byte
    sub     rsi, 0x57

process_byte:
    mov     rax, rsi
    shr     rax, 3
    lea     rdi, [rdi*2 + rax]

    and     rsi, 0b111
    mov     cl, sil
    mov     rax, 0b1000_0000
    sar     rax, cl

    xor     BYTE [available  + rdi], al

    inc     r11
    mov     dil, BYTE [r11]
    test    rdi, rdi
    jnz     loop1

    ; Prefixes
    lea     rdi, [section_prefixes_str]
    xor     rax, rax
    call    printf

        lea     rdi, [sizes_str]
        xor     rax, rax
        call    printf

            ; 0x66
            lea     rdi, [operand_size_override_16_32_str]
            xor     rsi, rsi
            mov     rbx, [available + 12]
            bt      rbx, 1
            setc    sil
            call    print_status

            ; 0x67
            lea     rdi, [address_size_override_16_32_str]
            xor     rsi, rsi
            mov     rbx, [available + 12]
            bt      rbx, 0
            setc    sil
            call    print_status

        lea     rdi, [reps_str]
        xor     rax, rax
        call    printf
            
            ; 0xf2
            lea     rdi, [repne_str]
            xor     rsi, rsi
            mov     rbx, [available + 30]
            bt      rbx, 5
            setc    sil
            call    print_status

            ; 0xf3
            lea     rdi, [rep_str]
            xor     rsi, rsi
            mov     rbx, [available + 30]
            bt      rbx, 4
            setc    sil
            call    print_status

        lea     rdi, [segments_str]
        xor     rax, rax
        call    printf

            ;0x2e
            lea     rdi, [cs_str]
            xor     rsi, rsi
            mov     rbx, [available + 5]
            bt      rbx, 1
            setc    sil
            call    print_status

            ;0x36
            lea     rdi, [ss_str]
            xor     rsi, rsi
            mov     rbx, [available + 6]
            bt      rbx, 1
            setc    sil
            call    print_status

            ;0x3e
            lea     rdi, [ds_str]
            xor     rsi, rsi
            mov     rbx, [available + 7]
            bt      rbx, 1
            setc    sil
            call    print_status

            ;0x26
            lea     rdi, [es_str]
            xor     rsi, rsi
            mov     rbx, [available + 4]
            bt      rbx, 1
            setc    sil
            call    print_status

            ;0x64
            lea     rdi, [fs_str]
            xor     rsi, rsi
            mov     rbx, [available + 12]
            bt      rbx, 3
            setc    sil
            call    print_status

            ;0x65
            lea     rdi, [gs_str]
            xor     rsi, rsi
            mov     rbx, [available + 12]
            bt      rbx, 2
            setc    sil
            call    print_status

    ; Others coming later...

    xor     rdi, rdi
    call    exit

err_bad_args:
    lea     rdi, [bad_args]
    xor     rax, rax
    call    printf

    mov     rdi, 0x1
    call    exit

err_invalid_byte:
    lea     rdi, [invalid_byte]
    xor     rax, rax
    call    printf

    mov     rdi, 0x2
    call    exit

exit:
    mov     rbx, rdi
    xor     rdi, rdi
    call    fflush
    mov     rdi, rbx
    mov     rax, 0x3c               ; exit syscall
    syscall