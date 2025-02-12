extern printf

global _start

section .rodata:
hello:
    db      "hello", 0Ah, 0

section .text
exit:
    mov     rax, 3Ch
    syscall

_start:
    mov     rdi, hello
    xor     rax, rax
    call    printf

    mov     rdi, 0x70
    call    exit