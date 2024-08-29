#在hook点patch上跳板,跳转到我们的shellcode
.global _trampoline_
#shellcode所在的地址,跳板需要跳转到shellcode
.global _shellcode_addr_
#shellcode的起始地址和结束地址,用来定位shellcode的大小以及字节
.global _shellcode_start_
.global _shellcode_end_
#被跳板覆盖的16字节指令,这些指令我们需要在hook完成之后再次执行,才不会影响到原本的逻辑
.global _origin_patched_code_
#跳转到hook的核心功能函数的地址去执行读取寄存器/修改寄存器等操作
.global _hook_main_func_addr_
#当所有的hook逻辑执行完毕之后,需要返回到hook点后16字节的位置去执行后续的指令
.global _hook_finish_return_addr_
_trampoline_:
    LDR X16, SHELLCODE_ADDR
    BR x16
#这里需要先声明SHELLCODE_ADDR的地址,否则会出现ld: error: relocation R_AARCH64_LD_PREL_LO19 cannot be used against symbol '_shellcode_addr_'
#就是说不能用已经声明过全局的符号来作重定位
SHELLCODE_ADDR:
_shellcode_addr_:
    .dword 0x1234567812345678
_shellcode_start_:
    #本来想参考https://github.com/zzyccs/inlineHook/blob/master/app/src/main/cpp/inline_shellcode.S
    #手动通过STP寄存器的大小一个一个算出存入堆栈的地址的
    #但是看了一下frida,直接用STP Xt1, Xt2, [Xn|SP, #imm]! ; 64-bit
    #这种预索引的方式修改SP的值,这样就不需要size*0,size*1...的方式去计算寄存器存储的位置
    #可以达到持续入栈的效果,太厉害啦
    STP             Q30, Q31, [SP,#-0x20]!
    STP             Q28, Q29, [SP,#-0x20]!
    STP             Q26, Q27, [SP,#-0x20]!
    STP             Q24, Q25, [SP,#-0x20]!
    STP             Q22, Q23, [SP,#-0x20]!
    STP             Q20, Q21, [SP,#-0x20]!
    STP             Q18, Q19, [SP,#-0x20]!
    STP             Q16, Q17, [SP,#-0x20]!
    STP             Q14, Q15, [SP,#-0x20]!
    STP             Q12, Q13, [SP,#-0x20]!
    STP             Q10, Q11, [SP,#-0x20]!
    STP             Q8, Q9, [SP,#-0x20]!
    STP             Q6, Q7, [SP,#-0x20]!
    STP             Q4, Q5, [SP,#-0x20]!
    STP             Q2, Q3, [SP,#-0x20]!
    STP             Q0, Q1, [SP,#-0x20]!
    STP             X30, X31, [SP,#-0x10]!
    STP             X28, X29, [SP,#-0x10]!
    STP             X26, X27, [SP,#-0x10]!
    STP             X24, X25, [SP,#-0x10]!
    STP             X22, X23, [SP,#-0x10]!
    STP             X20, X21, [SP,#-0x10]!
    STP             X18, X19, [SP,#-0x10]!
    STP             X16, X17, [SP,#-0x10]!
    STP             X14, X15, [SP,#-0x10]!
    STP             X12, X13, [SP,#-0x10]!
    STP             X10, X11, [SP,#-0x10]!
    STP             X8, X9, [SP,#-0x10]!
    STP             X6, X7, [SP,#-0x10]!
    STP             X4, X5, [SP,#-0x10]!
    STP             X2, X3, [SP,#-0x10]!
    STP             X0, X1, [SP,#-0x10]!
    #特别注意,CPSR寄存器也要保存,不然只能打印一次值然后就崩溃了-m-
    #aarch64不能和aarch32一样,直接访问CPSR得到所有的值,所以得分开来访问
    #看frida的hook之后的样子,看上去只需要保存NZCV寄存器就足够了
    MRS             X1, NZCV
    #MRS             X0, DAIF
    STP             X0, X1,[SP,#-0x10]!

    MOV             X0, SP
    LDR             X16, HOOK_MAIN_FUNC_ADDR
    BLR             X16

    #恢复CPSR寄存器
    LDP             X0, X1, [SP],#0x10
    MSR             NZCV, X1
    #MSR             DAIF, X0
    #恢复X0-X31,Q0-Q31寄存器
    LDP             X0, X1, [SP],#0x10
    LDP             X2, X3, [SP],#0x10
    LDP             X4, X5, [SP],#0x10
    LDP             X6, X7, [SP],#0x10
    LDP             X8, X9, [SP],#0x10
    LDP             X10, X11, [SP],#0x10
    LDP             X12, X13, [SP],#0x10
    LDP             X14, X15, [SP],#0x10
    LDP             X16, X17, [SP],#0x10
    LDP             X18, X19, [SP],#0x10
    LDP             X20, X21, [SP],#0x10
    LDP             X22, X23, [SP],#0x10
    LDP             X24, X25, [SP],#0x10
    LDP             X26, X27, [SP],#0x10
    LDP             X28, X29, [SP],#0x10
    LDP             X30, X31, [SP],#0x10
    LDP             Q0, Q1, [SP],#0x20
    LDP             Q2, Q3, [SP],#0x20
    LDP             Q4, Q5, [SP],#0x20
    LDP             Q6, Q7, [SP],#0x20
    LDP             Q8, Q9, [SP],#0x20
    LDP             Q10, Q11, [SP],#0x20
    LDP             Q12, Q13, [SP],#0x20
    LDP             Q14, Q15, [SP],#0x20
    LDP             Q16, Q17, [SP],#0x20
    LDP             Q18, Q19, [SP],#0x20
    LDP             Q20, Q21, [SP],#0x20
    LDP             Q22, Q23, [SP],#0x20
    LDP             Q24, Q25, [SP],#0x20
    LDP             Q26, Q27, [SP],#0x20
    LDP             Q28, Q29, [SP],#0x20
    LDP             Q30, Q31, [SP],#0x20
_origin_patched_code_:
    .dword 0x1234567812345678
    .dword 0x1234567812345678
    LDR             X16, HOOK_FINISH_RETURN_ADDR
    BR              X16
HOOK_MAIN_FUNC_ADDR:
_hook_main_func_addr_:
    .dword 0x1234567812345678
HOOK_FINISH_RETURN_ADDR:
_hook_finish_return_addr_:
    .dword 0x1234567812345678
_shellcode_end_: