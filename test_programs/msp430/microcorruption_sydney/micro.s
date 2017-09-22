0010 <__trap_interrupt>
0010:  3041           ret
4400 <__init_stack>
4400:  3140 0044      mov	#0x4400, sp
4404 <__low_level_init>
4404:  1542 5c01      mov	&0x015c, r5
4408:  75f3           and.b	#-0x1, r5
440a:  35d0 085a      bis	#0x5a08, r5
440e <__do_copy_data>
440e:  3f40 0000      clr	r15
4412:  0f93           tst	r15
4414:  0724           jz	#0x4424 <__do_clear_bss+0x0>
4416:  8245 5c01      mov	r5, &0x015c
441a:  2f83           decd	r15
441c:  9f4f 9445 0024 mov	0x4594(r15), 0x2400(r15)
4422:  f923           jnz	#0x4416 <__do_copy_data+0x8>
4424 <__do_clear_bss>
4424:  3f40 0000      clr	r15
4428:  0f93           tst	r15
442a:  0624           jz	#0x4438 <main+0x0>
442c:  8245 5c01      mov	r5, &0x015c
4430:  1f83           dec	r15
4432:  cf43 0024      mov.b	#0x0, 0x2400(r15)
4436:  fa23           jnz	#0x442c <__do_clear_bss+0x8>
4438 <main>
4438:  3150 9cff      add	#0xff9c, sp
443c:  3f40 b444      mov	#0x44b4 "Enter the password to continue.", r15
4440:  b012 6645      call	#0x4566 <puts>
4444:  0f41           mov	sp, r15
4446:  b012 8044      call	#0x4480 <get_password>
444a:  0f41           mov	sp, r15
444c:  b012 8a44      call	#0x448a <check_password>
4450:  0f93           tst	r15
4452:  0520           jnz	#0x445e <main+0x26>
4454:  3f40 d444      mov	#0x44d4 "Invalid password; try again.", r15
4458:  b012 6645      call	#0x4566 <puts>
445c:  093c           jmp	#0x4470 <main+0x38>
445e:  3f40 f144      mov	#0x44f1 "Access Granted!", r15
4462:  b012 6645      call	#0x4566 <puts>
4466:  3012 7f00      push	#0x7f
446a:  b012 0245      call	#0x4502 <INT>
446e:  2153           incd	sp
4470:  0f43           clr	r15
4472:  3150 6400      add	#0x64, sp
4476 <__stop_progExec__>
4476:  32d0 f000      bis	#0xf0, sr
447a:  fd3f           jmp	#0x4476 <__stop_progExec__+0x0>
447c <__ctors_end>
447c:  3040 9245      br	#0x4592 <_unexpected_>
4480 <get_password>
4480:  3e40 6400      mov	#0x64, r14
4484:  b012 5645      call	#0x4556 <getsn>
4488:  3041           ret
448a <check_password>
448a:  bf90 4754 0000 cmp	#0x5447, 0x0(r15)
4490:  0d20           jnz	$+0x1c
4492:  bf90 4e6b 0200 cmp	#0x6b4e, 0x2(r15)
4498:  0920           jnz	$+0x14
449a:  bf90 7b5f 0400 cmp	#0x5f7b, 0x4(r15)
44a0:  0520           jne	#0x44ac <check_password+0x22>
44a2:  1e43           mov	#0x1, r14
44a4:  bf90 443a 0600 cmp	#0x3a44, 0x6(r15)
44aa:  0124           jeq	#0x44ae <check_password+0x24>
44ac:  0e43           clr	r14
44ae:  0f4e           mov	r14, r15
44b0:  3041           ret
44b2 <__do_nothing>
44b2:  3041           ret
44b4 .strings:
44b4: "Enter the password to continue."
44d4: "Invalid password; try again."
44f1: "Access Granted!"
4501: ""
4502 <INT>
4502:  1e41 0200      mov	0x2(sp), r14
4506:  0212           push	sr
4508:  0f4e           mov	r14, r15
450a:  8f10           swpb	r15
450c:  024f           mov	r15, sr
450e:  32d0 0080      bis	#0x8000, sr
4512:  b012 1000      call	#0x10
4516:  3241           pop	sr
4518:  3041           ret
451a <putchar>
451a:  2183           decd	sp
451c:  0f12           push	r15
451e:  0312           push	#0x0
4520:  814f 0400      mov	r15, 0x4(sp)
4524:  b012 0245      call	#0x4502 <INT>
4528:  1f41 0400      mov	0x4(sp), r15
452c:  3150 0600      add	#0x6, sp
4530:  3041           ret
4532 <getchar>
4532:  0412           push	r4
4534:  0441           mov	sp, r4
4536:  2453           incd	r4
4538:  2183           decd	sp
453a:  3f40 fcff      mov	#0xfffc, r15
453e:  0f54           add	r4, r15
4540:  0f12           push	r15
4542:  1312           push	#0x1
4544:  b012 0245      call	#0x4502 <INT>
4548:  5f44 fcff      mov.b	-0x4(r4), r15
454c:  8f11           sxt	r15
454e:  3150 0600      add	#0x6, sp
4552:  3441           pop	r4
4554:  3041           ret
4556 <getsn>
4556:  0e12           push	r14
4558:  0f12           push	r15
455a:  2312           push	#0x2
455c:  b012 0245      call	#0x4502 <INT>
4560:  3150 0600      add	#0x6, sp
4564:  3041           ret
4566 <puts>
4566:  0b12           push	r11
4568:  0b4f           mov	r15, r11
456a:  073c           jmp	#0x457a <puts+0x14>
456c:  1b53           inc	r11
456e:  8f11           sxt	r15
4570:  0f12           push	r15
4572:  0312           push	#0x0
4574:  b012 0245      call	#0x4502 <INT>
4578:  2152           add	#0x4, sp
457a:  6f4b           mov.b	@r11, r15
457c:  4f93           tst.b	r15
457e:  f623           jnz	#0x456c <puts+0x6>
4580:  3012 0a00      push	#0xa
4584:  0312           push	#0x0
4586:  b012 0245      call	#0x4502 <INT>
458a:  2152           add	#0x4, sp
458c:  0f43           clr	r15
458e:  3b41           pop	r11
4590:  3041           ret
4592 <_unexpected_>
4592:  0013           reti	pc
