#include "stdio.h"
#include <android/log.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#define LOG_TAG "hook-agent"
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG  , LOG_TAG, __VA_ARGS__))
#define MAX_PATH 512
void* findModuleByName(pid_t pid,const char* libname){
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
        //查找指定模块是否在某行出现
        if(strstr(line,libname)){base = strtok(line, "-");//以`-`为分隔符,读取基址
            base_addr = (void*)strtoul(base, NULL, 16);
            LOGD("find %s addr at 0x%08lx",libname,base_addr);
            break;
        }
    }
    fclose(f);
    return base_addr;
}

int work_func(){
    LOGD("call work_func ok!");
    return 777;
}

void hook_main(u_long sp){
    LOGD("enter hook main!");
    //sp -- sp+0x10存储的是NZCV寄存器,从sp+0x10开始才是x0-x31的位置
    u_long strlen_ret_value = *(u_long*)(sp+0x10);
    LOGD("hook done! target function strlen return value is 0x%08lx",strlen_ret_value);
}
/**
 * 完成一次完整的hook,需要先由hook点的一级跳板跳转到二级跳板的位置,
 * 一级跳板通过BR X16跳往二级跳板,二级跳板保存寄存器的环境,跳转到hook的
 * 功能函数位置,随后还原寄存器环境,并执行先前被覆盖的四条汇编
 * ,随后通过BR X16寄存器,跳往hook点之后的位置,完成一次完整的hook
 *
 */
static __attribute__((constructor)) void ctor()
{
    //0x10B0开始的四条指令涉及相对寻址呐,所以把原来的16字节完整的复制过来
    //进程是会崩溃的,后续再看看能不能用keystone去修复一下相对寻址相关指令?
    //现在先暂时找这一处没有相对寻址指令的hook点好了
    u_long hook_addr = (u_long)findModuleByName(-1,"liboacia.so")+0x10B8;
    LOGD("hook-agent init!");
    extern u_long _trampoline_,_shellcode_addr_,_shellcode_start_,_shellcode_end_,_origin_patched_code_,_hook_main_func_addr_,_hook_finish_return_addr_;
    u_long total_len = (u_long)&_shellcode_end_ - (u_long)&_shellcode_start_;
    LOGD("shellcode len: %lu, hook_addr: 0x%08lx,offset: 0x%04x",total_len,hook_addr,0x10B8);

    //为shellcode分配内存
    u_long page_size = getpagesize();
    u_long shellcode_mem_start = (u_long)mmap(0, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    memset((void *)shellcode_mem_start, 0, page_size);
    memcpy((void *)shellcode_mem_start, (void *)&_shellcode_start_, total_len);
    LOGD("_shellcode_addr_: 0x%08lx,shellcode_mem_start: 0x%08lx",*(u_long*)&_shellcode_addr_, shellcode_mem_start);

    //尝试了一下好像没有办法给_shellcode_addr_赋值(很奇怪)
    //所以索性直接这样赋值了*(u_long*)(hook_addr + 8) = shellcode_mem_start;
    //*(u_long*)&_shellcode_addr_ = (u_long)shellcode_mem_start;

    //通过相对偏移的方式,定位到需要替换的地址在mmap分配的内存中的地址
    u_long mem_hook_main_func_addr_ = (u_long)&_hook_main_func_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_origin_patched_code_ = (u_long)&_origin_patched_code_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    u_long mem_hook_finish_return_addr_ = (u_long)&_hook_finish_return_addr_ - (u_long)&_shellcode_start_ + shellcode_mem_start;
    //hook的功能函数的地址
    *(u_long*)mem_hook_main_func_addr_ = (u_long)hook_main;
    //被跳板覆盖前,hook点的16字节
    *(u_long*)mem_origin_patched_code_ = *(u_long*)hook_addr;
    *(u_long*)(mem_origin_patched_code_ + 8) = *(u_long*)(hook_addr + 8);

    //hook执行完毕后的返回地址
    *(u_long*)mem_hook_finish_return_addr_ = (u_long)hook_addr + 0x10;
    //patch上我们的跳板
    u_long entry_page_start = (u_long)(hook_addr) & (~(page_size-1));
    mprotect((u_long*)entry_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    *(u_long*)hook_addr = *(u_long*)&_trampoline_;
    *(u_long*)(hook_addr + 8) = shellcode_mem_start;
}




