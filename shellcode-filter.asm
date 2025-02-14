extern printf
extern strcmp

global _start

section .rodata
exclude_flag:
    db      "-x", 0
include_flag:
    db      "-i", 0
exclude_str:
    db      "We are about to exclude the given bytes", 0x0a, 0
include_str:
    db      "We are about to include the given bytes", 0x0a, 0
bad_args:
    db      "Usage: ./shellcode-filter [-xi] bytes", 0x0a, 0

section .text
_start:
    ; Parsing CLI arguments
    mov     rax, QWORD [rsp]
    cmp     rax, 0x03
    jne     err_bad_args

    xor     rbx, rbx
    mov     rdi, QWORD [rsp + 16]
    lea     rsi, [exclude_flag]
    call    strcmp
    jz      parse_file

    mov     rdi, QWORD [rsp + 16]
    lea     rsi, [include_flag]
    call    strcmp
    jnz     err_bad_args

    inc     rbx

parse_file:
    test    rbx, rbx
    jz      oui

    lea     rdi, [include_str]
    xor     rax, rax
    call    printf
    
    xor     rdi, rdi
    call    exit

oui:
    lea     rdi, [exclude_str]
    xor     rax, rax
    call    printf

    xor     rdi, rdi
    call    exit

err_bad_args:
    lea     rdi, [bad_args]
    xor     rax, rax
    call    printf

    mov     rdi, 0x01
    call    exit

exit:
    mov     rax, 0x3c   ; exit syscall
    syscall