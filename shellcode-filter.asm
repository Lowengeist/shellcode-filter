extern printf

global main

section .rodata:
hidecursor:
    db      1Bh, '[?25l', 0
showcursor:
    db      1Bh, '[?25h', 0

section .text
init:
    push    rbp
    mov     rbp, rsp
    mov     rdi, hidecursor
    call    printf

exit:
    mov     rdi, showcursor
    call    printf
    mov     rax, 3Ch
    syscall

main:
    call    init