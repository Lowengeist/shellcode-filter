extern printf
extern strcmp

global _start

section .rodata
exclude_flag:
    db      "-x", 0
include_flag:
    db      "-i", 0
status_template_str:
    db      0x09, "[", 0x1b, "[1;%dm%s", 0x1b, "[0;39m] %s", 0x0a, 0
unavailable_str:
    db      "X Unavailable", 0     
available_str: 
    db      "✓ Available", 0
prefixes_section_str:
    db      "-------- PREFIXES --------", 0x0a, 0
sizes_str:
    db      "Operand size override:", 0x0a, 0
operand_size_override_16_32_str:
    db      "Change operand size from 32 bit to 16 bit, or the contrary (D bit)", 0x0a, 0
bad_args:
    db      "Usage: ./shellcode-filter [-ix] bytes", 0x0a, 0
invalid_byte:
    db      "Error : Given bytes are not valid hex", 0x0a, 0

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
    lea     rdi, [prefixes_section_str]
    xor     rax, rax
    call    printf

    lea     rdi, [sizes_str]
    xor     rax, rax
    call    printf

    ; 0x66
    lea     rdi, [operand_size_override_16_32_str]
    
    xor     rsi, rsi
    mov     rbx, [available + 12]
    bt      rbx, 0x1
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
    mov     rax, 0x3c               ; exit syscall
    syscall