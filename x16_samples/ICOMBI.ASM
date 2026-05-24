.8086
.MODEL TINY
.CODE
ORG 100h
start:
    mov ah, 0Fh
    int 10h
    mov ah, 00h
    int 1Ah
    mov ah, 03h
    xor bh, bh
    int 10h
    mov ax, 4C01h
    int 21h
END start
