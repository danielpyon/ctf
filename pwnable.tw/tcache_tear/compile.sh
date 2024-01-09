gcc test.c
patchelf --set-interpreter ./ld-2.27.so ./a.out
patchelf --set-rpath . ./a.out
