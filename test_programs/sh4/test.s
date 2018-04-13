	.file	"test.c"
	.text
	.little
	.section	.rodata
	.align 2
.LC0:
	.string	"Hello world!"
	.text
	.align 1
	.global	main
	.type	main, @function
main:
	mov.l	r14,@-r15
	sts.l	pr,@-r15
	mov	r15,r14
	mov.l	.L3,r1
	mov	r1,r4
	mov.l	.L4,r1
	jsr	@r1
	nop
	mov	#0,r1
	mov	r1,r0
	mov	r14,r15
	lds.l	@r15+,pr
	mov.l	@r15+,r14
	rts	
	nop
.L5:
	.align 2
.L3:
	.long	.LC0
.L4:
	.long	puts
	.size	main, .-main
	.ident	"GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609"
	.section	.note.GNU-stack,"",@progbits
