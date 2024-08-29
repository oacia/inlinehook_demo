#include <sys/wait.h>
#include "sys/ptrace.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "unistd.h"
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>

#define MAX_PATH 512
void ptraceAttach(pid_t pid){
    if(ptrace(PTRACE_ATTACH,pid,NULL,NULL)==-1){
        printf("[ptrace] Failed to attach:%d\n",pid);
    }
    else{
        printf("[ptrace] Attach to pid %d\n",pid);
    }
    int stat=0;
    /*  在用ptrace去attach一个进程之后，那个被attach的进程某种意义上说可以算作那个attach
     *  进程的子进程，这种情况下，就可以通过waitpid这个函数来知道被调试的进程何时停止运行
     *
     *  @param option->WUNTRACED: 如果子进程进入暂停状态，则马上返回。*/
    waitpid(pid,&stat,WUNTRACED);
}

void ptraceDetach(pid_t pid){
    ptrace(PTRACE_DETACH,pid,NULL,NULL);
}

void ptraceReadData(pid_t pid,void* addr,char*data,size_t len){
    size_t i=0;
    long rdata;
    for(;i<len;i+=sizeof(long)){
        rdata=ptrace(PTRACE_PEEKTEXT,pid,(long)addr+i,NULL);
        *(long*)&data[i]=rdata;
    }
}

void ptraceWriteData(pid_t pid,void*addr,char*data,size_t len,int start){
    for(size_t i=0;i<len;i++){
        ptrace(PTRACE_POKETEXT,pid,addr+i,data[start+i]);
    }
}

void ptraceGetRegs(pid_t pid,struct user_pt_regs *regs_addr){
    struct iovec io;
    io.iov_base = regs_addr;
    io.iov_len = sizeof(struct user_pt_regs);
    //NT_PRSTATUS: general-purpose registers, 定义在elf.h中
    /**
     * PTRACE_GETREGSET
     * 读取被追踪者寄存器。addr参数决定读取寄存器的类型。
     * 如果addr是NT_PRSTATUS，则读取通用寄存器。
     * 如果addr是NT_foo，则读取浮点或向量寄存器（如果有的话)。data参数指向iovec类型：
     */
    if(ptrace(PTRACE_GETREGSET,pid,NT_PRSTATUS,&io)==-1){
        printf("Get regs failed");
    }
}

void ptraceSetRegs(pid_t pid,struct user_pt_regs *regs_addr){
    struct iovec io;
    io.iov_base = regs_addr;
    io.iov_len = sizeof(struct user_pt_regs);
    if(ptrace(PTRACE_SETREGSET,pid,NT_PRSTATUS,&io)==-1){
        printf("Set regs failed");
    }
}

void ptraceContinue(pid_t pid){
    //PTRACE_CONT: 让被追踪进程开始运行
    if(ptrace(PTRACE_CONT,pid,NULL,NULL)==-1){
        printf("ptrace continue error");
    }
}

void* findModuleByName(pid_t pid,const char* libname){
    //获取hook-server的pid,这样可以通过本地libc库函数地址-本地libc基址+远程libc基址 得到远程libc库函数地址
    if(pid==-1){
        pid=getpid();
    }
    char maps[MAX_PATH];
    void* base_addr = 0;
    snprintf(maps,MAX_PATH,"/proc/%d/maps",pid);
    FILE *f = fopen(maps,"r");
    char line[MAX_PATH],name[MAX_PATH];
    char *base;
    while(!feof(f)){
        memset(line,0,MAX_PATH);
        fgets(line,MAX_PATH,f);
        //printf("%s\n",line);
        //查找指定模块是否在某行出现
        if(strstr(line,libname)){
            //maps形式: base-end [rwxsp] offset dev inode pathname
            //eg. 6f1305e000-6f13060000 r-xp 00000000 fe:2e 90655 /lib/arm64/liboacia.so

            /*
             * https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html
             * The [offset] field is the offset into the file/whatever;
             * [dev] is the device (major:minor);
             * [inode] is the inode on that device.  0 indicates that no inode is associated with the memory
             * region, as would be the case with BSS (uninitialized data).
             * If  the [pathname] field is blank, this is an anonymous mapping as obtained
             * via the mmap(2) function.  There is no easy way to coordinate this back to
             * a process's source, short of running it through gdb(1), strace(1), or similar.*/
            base = strtok(line, "-");//以`-`为分隔符,读取基址
            base_addr = (void*)strtoul(base, NULL, 16);
            //printf("find module [%s] base at 0x%08lx\n",libname,base_addr);
            break;
        }
    }
    fclose(f);
    return base_addr;
}

void* findModuleByAddress(pid_t pid,const void* funcaddr){
    //获取hook-server的pid,这样可以通过本地libc库函数地址-本地libc基址+远程libc基址 得到远程libc库函数地址
    if(pid==-1){
        pid=getpid();
    }
    char maps[MAX_PATH];
    void* base_addr = 0, *end_addr = 0;
    snprintf(maps,MAX_PATH,"/proc/%d/maps",pid);
    FILE *f = fopen(maps,"r");
    char line[MAX_PATH],name[MAX_PATH];
    char *base,*end;
    while(!feof(f)){
        memset(line,0,MAX_PATH);
        fgets(line,MAX_PATH,f);
        printf("%s\n",line);
        base = strtok(line, "-");//以`-`为分隔符,读取基址
        base_addr = (void*)strtoul(base, NULL, 16);
        end = strtok(NULL, "-");
        end_addr = (void*)strtoul(end, NULL, 16);
        printf("funcaddr: 0x%08lx, base: 0x%08lx, end: 0x%08lx\n",funcaddr,base_addr,end_addr);
        //查找指定模块是否在某行出现
        if(funcaddr>base_addr && funcaddr<end_addr){
            //maps形式: base-end [rwxsp] offset dev inode pathname
            //eg. 6f1305e000-6f13060000 r-xp 00000000 fe:2e 90655 /lib/arm64/liboacia.so
            printf("find funcaddr-> %s",line);
            break;
        }
    }
    fclose(f);
    return base_addr;
}

void* getFunctionAddress(char* funcName)
{
    void* self = dlopen("libc.so.6", RTLD_LAZY);
    void* funcAddr = dlsym(self, funcName);
    return funcAddr;
}

void* getRemoteLibFuncEx(pid_t pid,const char* libname,char* funcname){
    void *LocalLibBase,*RemoteLibBase,*RemoteFuncAddr,*LocalFuncAddr;
    LocalLibBase = findModuleByName(-1,libname);//-1表示在当前hook-server的maps中寻找库的基址
    RemoteLibBase = findModuleByName(pid,libname);
    LocalFuncAddr = getFunctionAddress(funcname);
    RemoteFuncAddr = LocalFuncAddr-LocalLibBase+RemoteLibBase;
    printf("LocalLibBase: 0x%08lx, LocalFuncAddr: 0x%08lx\nRemoteLibBase: 0x%08lx, func offset: 0x%08lx\n",LocalLibBase,LocalFuncAddr,RemoteLibBase,LocalFuncAddr-LocalLibBase);
    return RemoteFuncAddr;
}

void* getRemoteLibFunc(pid_t pid,const char* libname,void* LocalFuncAddr){
    void *LocalLibBase,*RemoteLibBase,*RemoteFuncAddr;
    LocalLibBase = findModuleByName(-1,libname);//-1表示在当前hook-server的maps中寻找库的基址
    RemoteLibBase = findModuleByName(pid,libname);
    RemoteFuncAddr = LocalFuncAddr-LocalLibBase+RemoteLibBase;
    printf("LocalLibBase: 0x%08lx, LocalFuncAddr: 0x%08lx\nRemoteLibBase: 0x%08lx, func offset: 0x%08lx\n",LocalLibBase,LocalFuncAddr,RemoteLibBase,LocalFuncAddr-LocalLibBase);
    return RemoteFuncAddr;
}


#define CPSR_T_MASK (1u<<5)
#define ARM_lr regs[30]
void ptraceCall(pid_t pid,void* funcaddr,int argc,long* argv,struct user_pt_regs *regs){
    //比八个参数多的话,多出的参数通过栈去传参
    if(argc>8){
        regs->sp =regs->sp - (argc-8)*(sizeof(long));//申请8个寄存器的栈空间
        ptraceWriteData(pid,(void*)regs->sp,(char*)&argv[8],sizeof(long)*(argc-8),0);
    }
    //少于8个参数,就通过x0~x7寄存器去传参
    for(size_t i=0;i<8;i++){
        regs->regs[i] = argv[i];
    }

    regs->pc = (__u64) funcaddr;//将pc寄存器的值修改为函数地址,这样我们就可以跳转到函数的目标地址去执行arm64指令了
    //printf("[ptraceCall] funcaddr: 0x%08lx\n",regs->pc);
    if(regs->pc&1){
        //thumb模式
        //当pc的最后一位为1,即pc为奇数时,设置pstate CPSR的T标志位为1,表示接下来的指令以thumb模式执行
        regs->pc&=~1;
        //pstate,这是arm64v8a的叫法,在armv7a中叫CPSR寄存器
        //more-> https://blog.csdn.net/longwang155069/article/details/105204547
        regs->pstate|=CPSR_T_MASK;
    }else{
        //arm模式
        //当pc的最后一位为0,即pc为偶数时,清除pstate CPSR的T标志位,表示接下来的指令以arm模式执行
        regs->pstate&=~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;//设置lr寄存器为0,要是函数执行完毕之后返回0地址会抛出异常,这个异常在后面是有用的
    ptraceSetRegs(pid,regs);//设置寄存器的值,把函数的参数和地址传进寄存器里面
    int stat = 0;
    /**
     * 对于使用ptrace_cont重新运行的进程，它会在3种情况下进入暂停状态
     * 1. 下一次系统调用
     * 2. 子进程退出
     * 3. 子进程的执行发生错误
     * 这里的0xb7f我们可以拆分成两部分来看,后2字节0x7f,表示进程进入了暂停的状态
     * (如果后两字节是0x00则表示子进程退出状态),而前两字节0xb,表示进程发送的错误信号为11(SIGSEGV),
     * 即内存访问异常,因为我们之前将lr寄存器的值设为了0,所以当远程函数调用完毕之后会抛出异常,
     * 当ptrace收到这个异常信号时,就知道远程函数调用以及完成了~
     */
    while(stat!=0xb7f){
        ptraceContinue(pid);//让被ptrace的线程开始运行
        waitpid(pid,&stat,WUNTRACED);
        //printf("[ptraceCall] stat: 0x%04x\n",stat);
    }

    ptraceGetRegs(pid,regs);//当远程函数调用完成之后,读取寄存器获取返回值
}

void write_trampoline_stage1(pid_t pid,void* target,char* libname,int offset,char* save_code,struct user_pt_regs *regs){
    void* RemoteLibBase = findModuleByName(pid,libname);
    long hook_addr = (long)RemoteLibBase+offset;

    //生成跳板函数
    unsigned char trampoline[16] = {
            0x50,0x00,0x00,0x58,//LDR X16,#0x8
            0x00,0x02,0x1f,0xD6,//BR X16
    };
    for(int i=0;i<8;i++){
        trampoline[i+8] = *((char*)target+i);
    }

    //读取即将被覆盖的指令
    ptraceReadData(pid, (void *) hook_addr, save_code, 0x10);

    //获取 mprotect 在远程进程中的地址
    void* RemoteMprotectAddr = getRemoteLibFunc(pid,"libc.so",(void*) mprotect);
    printf("[libc] find remote mprotect addr at 0x%08lx\n",(long)RemoteMprotectAddr);
    //调用mmap函数
    long paras[6];
    paras[0]= hook_addr-hook_addr%0x1000;
    paras[1]=0x1000;
    paras[2]=PROT_READ|PROT_WRITE|PROT_EXEC;
    ptraceCall(pid,RemoteMprotectAddr,3,paras,regs);
    printf("mprotect change address 0x%08lx prot to rwx",hook_addr);

    //写入跳板
    ptraceWriteData(pid, (void *) hook_addr, (char*)trampoline, 16,0);
}

void write_trampoline_stage2(pid_t pid,void* patch_addr,char* libname,int offset,const char* save_code,void* hook_agent_func_addr){
    void* RemoteLibBase = findModuleByName(pid,libname);
    long hook_addr = (long)RemoteLibBase+offset;
    long ret_addr = hook_addr+16;
    //生成跳板函数
    char trampoline[360] = {
            //保存寄存器环境
            0xff,0x43,0x00,0xd1,
            0xfe,0x7f,0xbf,0xad,
            0xfc,0x77,0xbf,0xad,
            0xfa,0x6f,0xbf,0xad,
            0xf8,0x67,0xbf,0xad,
            0xf6,0x5f,0xbf,0xad,
            0xf4,0x57,0xbf,0xad,
            0xf2,0x4f,0xbf,0xad,
            0xf0,0x47,0xbf,0xad,
            0xee,0x3f,0xbf,0xad,
            0xec,0x37,0xbf,0xad,
            0xea,0x2f,0xbf,0xad,
            0xe8,0x27,0xbf,0xad,
            0xe6,0x1f,0xbf,0xad,
            0xe4,0x17,0xbf,0xad,
            0xe2,0x0f,0xbf,0xad,
            0xe0,0x07,0xbf,0xad,
            0xfd,0x7b,0xbf,0xa9,
            0xfb,0x73,0xbf,0xa9,
            0xf9,0x6b,0xbf,0xa9,
            0xf7,0x63,0xbf,0xa9,
            0xf5,0x5b,0xbf,0xa9,
            0xf3,0x53,0xbf,0xa9,
            0xf1,0x4b,0xbf,0xa9,
            0xef,0x43,0xbf,0xa9,
            0xed,0x3b,0xbf,0xa9,
            0xeb,0x33,0xbf,0xa9,
            0xe9,0x2b,0xbf,0xa9,
            0xe7,0x23,0xbf,0xa9,
            0xe5,0x1b,0xbf,0xa9,
            0xe3,0x13,0xbf,0xa9,
            0xe1,0x0b,0xbf,0xa9,
            0x01,0x42,0x3b,0xd5,
            0xe1,0x03,0xbf,0xa9,
            0xe0,0x43,0x0c,0x91,
            0xff,0x03,0xbf,0xa9,
            0xfe,0x8f,0x01,0xf9,
            0xfd,0x8b,0x01,0xf9,
            0xfd,0x43,0x0c,0x91,
            0xe1,0x03,0x00,0x91,
            0xe2,0x23,0x04,0x91,
            0xe3,0x43,0x0c,0x91,

            //跳转到核心代码
            0xe0,0x03,0x11,0xaa,
            0x64,0x05,0x00,0x58,
            0x80,0x00,0x3f,0xd6,

            //还原寄存器环境
            0xff,0x43,0x00,0x91,
            0xe1,0x03,0xc1,0xa8,
            0x01,0x42,0x1b,0xd5,
            0xe1,0x0b,0xc1,0xa8,
            0xe3,0x13,0xc1,0xa8,
            0xe5,0x1b,0xc1,0xa8,
            0xe7,0x23,0xc1,0xa8,
            0xe9,0x2b,0xc1,0xa8,
            0xeb,0x33,0xc1,0xa8,
            0xed,0x3b,0xc1,0xa8,
            0xef,0x43,0xc1,0xa8,
            0xf1,0x4b,0xc1,0xa8,
            0xf3,0x53,0xc1,0xa8,
            0xf5,0x5b,0xc1,0xa8,
            0xf7,0x63,0xc1,0xa8,
            0xf9,0x6b,0xc1,0xa8,
            0xfb,0x73,0xc1,0xa8,
            0xfd,0x7b,0xc1,0xa8,
            0xe0,0x07,0xc1,0xac,
            0xe2,0x0f,0xc1,0xac,
            0xe4,0x17,0xc1,0xac,
            0xe6,0x1f,0xc1,0xac,
            0xe8,0x27,0xc1,0xac,
            0xea,0x2f,0xc1,0xac,
            0xec,0x37,0xc1,0xac,
            0xee,0x3f,0xc1,0xac,
            0xf0,0x47,0xc1,0xac,
            0xf2,0x4f,0xc1,0xac,
            0xf4,0x57,0xc1,0xac,
            0xf6,0x5f,0xc1,0xac,
            0xf8,0x67,0xc1,0xac,
            0xfa,0x6f,0xc1,0xac,
            0xfc,0x77,0xc1,0xac,
            0xfe,0x7f,0xc1,0xac,
            0xf0,0x47,0xc1,0xa8,

            //执行先前因patch跳板被覆盖的代码,16字节占位
            0xaa,0xaa,0xaa,0xaa,
            0xaa,0xaa,0xaa,0xaa,
            0xaa,0xaa,0xaa,0xaa,
            0xaa,0xaa,0xaa,0xaa,

            //返回hook点之后的位置继续执行逻辑
            0x50,0x00,0x00,0x58,
            0x00,0x02,0x1f,0xD6,

            //8字节占位,存储功能函数的地址
            0xbb,0xbb,0xbb,0xbb,
            0xbb,0xbb,0xbb,0xbb,

            //8字节占位,存储功能hook完成后返回到原来程序的地址
            0xcc,0xcc,0xcc,0xcc,
            0xcc,0xcc,0xcc,0xcc,

    };
    for(int i=0;i<16;i++){
        trampoline[i+320] = save_code[i];
    }
    for(int i=0;i<8;i++){
        trampoline[i+344] = *((char*)hook_agent_func_addr+i);
    }

    for(int i=0;i<8;i++){
        trampoline[i+352] = *((char*)ret_addr+i);
    }
    //很奇怪,每一次写入的字节最多只能是0x49,在多就要崩溃了
    // 第一次最多写入0x49,后面最多都只能写入0x39字节...这么诡异???

    ptraceWriteData(pid, (void *) patch_addr+0x39*0, trampoline, 0x39,0x39*0);
    ptraceWriteData(pid, (void *) patch_addr+0x39*1, trampoline, 0x39,0x39*1);
    ptraceWriteData(pid, (void *) patch_addr+0x39*2, trampoline, 0x39,0x39*2);
    ptraceWriteData(pid, (void *) patch_addr+0x39*3, trampoline, 0x39,0x39*3);
    ptraceWriteData(pid, (void *) patch_addr+0x39*4, trampoline, 0x39,0x39*4);
    ptraceWriteData(pid, (void *) patch_addr+0x39*5, trampoline, 0x39,0x39*5);
    ptraceWriteData(pid, (void *) patch_addr+0x39*6, trampoline, 360-0x39*6,0x39*6);


}

void inject(pid_t pid){
    //附加到进程上
    ptraceAttach(pid);
    //找到lib所对应的基址
    void* base = findModuleByName(pid,"liboacia.so");

    //尝试读取hook点的汇编
    char buf[MAX_PATH];
    memset(buf,0,MAX_PATH);
    ptraceReadData(pid,base+0x10B0,buf,0x20);
    printf("[ptrace] read data at 0x%08lx, off:0x10B0, len: 0x20\n",base+0x10B0);
    for(int i=0;i<0x20;i++){
        if(i%4==0 && i!=0){
            printf("\n");
        }
        printf("%02x, ",buf[i]);
    }
    printf("\n");

    struct user_pt_regs oldRegs;
    struct user_pt_regs regs;
    //保存寄存器环境
    ptraceGetRegs(pid,&oldRegs);
    memcpy(&regs,&oldRegs, sizeof(struct user_pt_regs));

    //获取mmap在远程进程中的地址
    void* RemoteMmapAddr = getRemoteLibFunc(pid,"libc.so",(void*)mmap);
    printf("[libc] find remote mmap addr at 0x%08lx\n",(long)RemoteMmapAddr);
    //调用mmap函数
    long paras[6];
    paras[0]= 0;
    paras[1]=0x1000;
    paras[2]=PROT_READ|PROT_WRITE|PROT_EXEC;
    paras[3]=MAP_ANONYMOUS|MAP_PRIVATE;
    paras[4]=0;
    paras[5]=0;
    ptraceCall(pid,RemoteMmapAddr,6,paras,&regs);
    void *RemoteMemAddr = (void *)regs.regs[0];//mmap返回值存储在x0中,从x0获取远程的mmap函数分配的内存
    printf("[libc] mmap alloc memory at 0x%08lx\n\n",(long)RemoteMemAddr);

    //获取dlopen在远程进程中的地址
    void* RemoteDlopenAddr = getRemoteLibFunc(pid,"libdl.so",(void*)dlopen);
    printf("[libdl] find remote dlopen addr at 0x%08lx\n",(long)RemoteDlopenAddr);

    /**
     * 将要加载的so的绝对地址写入mmap分配的内存中,可以把so放在app的私有目录下面,
     * 要是放在/data/local/tmp目录下面,会遇到avc denied,
     * 这个时候需要使用setenforce 0临时禁用掉selinux才可以
     */
    ptraceWriteData(pid,RemoteMemAddr,"/data/local/tmp/libhook-agent.so",strlen("/data/local/tmp/libhook-agent.so")+1,0);

    //调用dlopen函数
    paras[0] = (long) RemoteMemAddr;
    paras[1]=RTLD_NOW|RTLD_GLOBAL;
    ptraceCall(pid,RemoteDlopenAddr,2,paras,&regs);
    void *HookAgentHandle = (void *)regs.regs[0];//dlopen返回值存储在x0中,从x0获取远程的dlopen返回的handle
    printf("[libdl] dlopen libhook-agent.so addr: 0x%08lx\n\n",(long)HookAgentHandle);

    //使用dlerror来排查dlopen失败对应的情况
    if ((long)HookAgentHandle == 0x0){
        void* RemoteDlerrorAddr = getRemoteLibFunc(pid,"libdl.so",(void*)dlerror);
        printf("[libdl] find remote dlerror addr at 0x%08lx\n",(long)RemoteDlerrorAddr);
        ptraceCall(pid, RemoteDlerrorAddr, 2, paras, &regs);
        char *Error = (void *)regs.regs[0];
        char LocalErrorInfo[1024] = {0};
        ptraceReadData(pid, Error, LocalErrorInfo, 1024);
        printf("dlopen error:%s", LocalErrorInfo);
    }

//    //dlsym获取调用函数的地址
//    void* RemoteDlsymAddr = getRemoteLibFunc(pid,"libdl.so",(void*)dlsym);
//    printf("[libdl] find remote dlsym addr at 0x%08lx\n",(long)RemoteDlsymAddr);
//    //将被调用函数的函数名写入mmap分配的内存中
//    ptraceWriteData(pid,RemoteMemAddr,"work_func",strlen("work_func")+1,0);
//    paras[0] = (long) HookAgentHandle;
//    paras[1]= (long) RemoteMemAddr;
//    ptraceCall(pid,RemoteDlsymAddr,2,paras,&regs);
//    void* remoteFuncAddr = (void *)regs.regs[0];
//    printf("[libdl] dlsym find hook-agent function addr at 0x%08lx\n",(long)remoteFuncAddr);
//    ptraceCall(pid,remoteFuncAddr,0,paras,&regs);//主动调用hook-agent中的work_func
//    int checkOK = (int)regs.regs[0];
//    printf("call wrok_func in libhook-agent.so, ret -> %d\n",checkOK);

//    //使用keystone生成16字节的跳板函数
//    unsigned char trampoline[16];
//    gen_trampoline(RemoteMemAddr,trampoline,16);


    //写入一级跳板汇编
    //char save_code[16];//保存被跳板覆盖的指令,在完成hook之后这4行汇编需要被执行
    //memset(save_code,0,16);
    //write_trampoline_stage1(pid,RemoteMemAddr,"liboacia.so",0x10B0,save_code,&regs);

    //write_trampoline_stage2(pid,RemoteMemAddr,"liboacia.so",0x10B0,save_code,remoteFuncAddr);

    // 恢复寄存器环境
    ptraceSetRegs(pid,&oldRegs);
    ptraceDetach(pid);
    printf("hook-server end");
}

int main(int argc,char **argv){
    pid_t pid = 3854;
    inject(pid);
    //printf("hello world!");
    return 0;
}