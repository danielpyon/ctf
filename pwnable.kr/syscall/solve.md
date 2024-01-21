# pwnable.kr: syscall

We can do `lsmod` to list the inserted kernel modules.
Looks like there's a module called `m` that represents the new syscall implementation.

Additionally, we can do `cat /proc/kallsyms | grep commit_creds` to find the address of `commit_creds`.

I tried jumping to userspace mmapped shellcode but this did not work.

Instead, I overwrote syscall table entries with `commit_creds` and `prepare_kernel_cred` and called them. Needed to write slightly before the actual address of `commit_creds` since it contained a lowercase ASCII character. Then, I did a nopslide into the `commit_creds` by padding the instructions with `mov r1,r1`.

Solution is at `solve.c`.
