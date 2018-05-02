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
441c:  9f4f d445 0024 mov	0x45d4(r15), 0x2400(r15)
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
4438:  b012 0045      call	#0x4500 <login>
443c <__stop_progExec__>
443c:  32d0 f000      bis	#0xf0, sr
4440:  fd3f           jmp	#0x443c <__stop_progExec__+0x0>
4442 <__ctors_end>
4442:  3040 d245      br	#0x45d2 <_unexpected_>
4446 <unlock_door>
4446:  3012 7f00      push	#0x7f
444a:  b012 4245      call	#0x4542 <INT>
444e:  2153           incd	sp
4450:  3041           ret
4452 <test_password_valid>
4452:  0412           push	r4
4454:  0441           mov	sp, r4
4456:  2453           incd	r4
4458:  2183           decd	sp
445a:  c443 fcff      mov.b	#0x0, -0x4(r4)
445e:  3e40 fcff      mov	#0xfffc, r14
4462:  0e54           add	r4, r14
4464:  0e12           push	r14
4466:  0f12           push	r15
4468:  3012 7d00      push	#0x7d
446c:  b012 4245      call	#0x4542 <INT>
4470:  5f44 fcff      mov.b	-0x4(r4), r15
4474:  8f11           sxt	r15
4476:  3152           add	#0x8, sp
4478:  3441           pop	r4
447a:  3041           ret
447c .strings:
447c: "Enter the password to continue."
449c: "Remember: passwords are between 8 and 16 characters."
44d1: "Access granted."
44e1: "That password is not correct."
44ff: ""
4500 <login>
4500:  3150 f0ff      add	#0xfff0, sp
4504:  3f40 7c44      mov	#0x447c "Enter the password to continue.", r15
4508:  b012 a645      call	#0x45a6 <puts>
450c:  3f40 9c44      mov	#0x449c "Remember: passwords are between 8 and 16 characters.", r15
4510:  b012 a645      call	#0x45a6 <puts>
4514:  3e40 3000      mov	#0x30, r14
4518:  0f41           mov	sp, r15
451a:  b012 9645      call	#0x4596 <getsn>
451e:  0f41           mov	sp, r15
4520:  b012 5244      call	#0x4452 <test_password_valid>
4524:  0f93           tst	r15
4526:  0524           jz	#0x4532 <login+0x32>
4528:  b012 4644      call	#0x4446 <unlock_door>
452c:  3f40 d144      mov	#0x44d1 "Access granted.", r15
4530:  023c           jmp	#0x4536 <login+0x36>
4532:  3f40 e144      mov	#0x44e1 "That password is not correct.", r15
4536:  b012 a645      call	#0x45a6 <puts>
453a:  3150 1000      add	#0x10, sp
453e:  3041           ret
4540 <__do_nothing>
4540:  3041           ret
4542 <INT>
4542:  1e41 0200      mov	0x2(sp), r14
4546:  0212           push	sr
4548:  0f4e           mov	r14, r15
454a:  8f10           swpb	r15
454c:  024f           mov	r15, sr
454e:  32d0 0080      bis	#0x8000, sr
4552:  b012 1000      call	#0x10
4556:  3241           pop	sr
4558:  3041           ret
455a <putchar>
455a:  2183           decd	sp
455c:  0f12           push	r15
455e:  0312           push	#0x0
4560:  814f 0400      mov	r15, 0x4(sp)
4564:  b012 4245      call	#0x4542 <INT>
4568:  1f41 0400      mov	0x4(sp), r15
456c:  3150 0600      add	#0x6, sp
4570:  3041           ret
4572 <getchar>
4572:  0412           push	r4
4574:  0441           mov	sp, r4
4576:  2453           incd	r4
4578:  2183           decd	sp
457a:  3f40 fcff      mov	#0xfffc, r15
457e:  0f54           add	r4, r15
4580:  0f12           push	r15
4582:  1312           push	#0x1
4584:  b012 4245      call	#0x4542 <INT>
4588:  5f44 fcff      mov.b	-0x4(r4), r15
458c:  8f11           sxt	r15
458e:  3150 0600      add	#0x6, sp
4592:  3441           pop	r4
4594:  3041           ret
4596 <getsn>
4596:  0e12           push	r14
4598:  0f12           push	r15
459a:  2312           push	#0x2
459c:  b012 4245      call	#0x4542 <INT>
45a0:  3150 0600      add	#0x6, sp
45a4:  3041           ret
45a6 <puts>
45a6:  0b12           push	r11
45a8:  0b4f           mov	r15, r11
45aa:  073c           jmp	#0x45ba <puts+0x14>
45ac:  1b53           inc	r11
45ae:  8f11           sxt	r15
45b0:  0f12           push	r15
45b2:  0312           push	#0x0
45b4:  b012 4245      call	#0x4542 <INT>
45b8:  2152           add	#0x4, sp
45ba:  6f4b           mov.b	@r11, r15
45bc:  4f93           tst.b	r15
45be:  f623           jnz	#0x45ac <puts+0x6>
45c0:  3012 0a00      push	#0xa
45c4:  0312           push	#0x0
45c6:  b012 4245      call	#0x4542 <INT>
45ca:  2152           add	#0x4, sp
45cc:  0f43           clr	r15
45ce:  3b41           pop	r11
45d0:  3041           ret
45d2 <_unexpected_>
45d2:  0013           reti	pc
