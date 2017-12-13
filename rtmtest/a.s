	.file	"a.c"
	.section	.rodata
.LC0:
	.string	"+++"
.LC1:
	.string	"salam"
	.text
	.globl	main
	.type	main, @function
main:
.LFB3448:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	call	fork
	movl	%eax, -4(%rbp)
	cmpl	$0, -4(%rbp)
	jne	.L2
.L3:
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
	jmp	.L3
.L2:
#APP
# 25 "a.c" 1
	XBEGIN foo

# 0 "" 2
#NO_APP
	movl	$.LC1, %edi
	movl	$0, %eax
	call	printf
	movl	$100, %edi
	call	sleep
#APP
# 28 "a.c" 1
	XEND
foo:

# 0 "" 2
#NO_APP
	movl	-4(%rbp), %eax
	movl	$9, %esi
	movl	%eax, %edi
	call	kill
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3448:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.5) 5.4.0 20160609"
	.section	.note.GNU-stack,"",@progbits
