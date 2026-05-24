.8086
.MODEL TINY
.CODE
ORG 100h
start:
    mov ah, 30h
    int 21h
    mov ah, 09h
    mov dx, OFFSET msg
    int 21h
    mov ax, 4C00h
    int 21h
msg db 'DOS sample$'
END start
