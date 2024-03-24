---
layout: post
title: "Heap Notes"
---

## basic heap layout
Every heap block contains a header, containing metadata like the size in bytes of the block, and some pointers. The pointer returned by ```malloc``` is always at the start of the data (past the header).

## heap overflow
Just like stack-based buffer overflows, there are heap-based overflows. If you can smash the heap and overwrite, for example, a function pointer in a struct somewhere, you could potentially get code execution.

## free and allocate
Due to the internals of most dynamic allocators, calling ```free``` then ```malloc``` with the same number of bytes as the ```free```'d block will usually give you back the same pointer.

This fact is useful in conjunction with a use-after-free vulnerability (below), where you could allocate malicious data that is being pointed at somewhere in the program.

## UAF
Use-after-free is a type of bug where dynamic memory is allocated, then freed, but the pointer is still being used. This can lead to code execution or other exploits. 

As a sort of silly example, say there's an array of pointers to structs:
```

typedef struct some_struct {
    int other_stuff;
    void (*do_stuff)(int);
} some_struct;

typedef struct other_struct {
    char buf[8];
    long long id;
} other_struct;

some_struct* arr[100];

...

void delete_object() {
    free(arr[num_objects--]);
    // they didn't NULL out arr[num_objects]!
}

void make_other_struct() {
    other_struct* thing = (other_struct*)malloc(sizeof(other_struct));
    fgets(thing->buf, 8, stdin);
    fgets(thing->id, 8, stdin);
}

```

The pointer to ```some_struct``` is still in ```arr``` even after "deleting" it. And since ```sizeof(some_struct) == sizeof(other_struct)```, we can use ```make_other_struct``` to set the function pointer to whatever we want.

## type confusion
Kind of similar to above, you can trick the program into thinking that a piece of memory is one type when really it is another. This involves carefully setting values to confuse the type system.

## infoleaks
Because free blocks have pointers as part of their metadata, it is possible to leak them by allocating a struct and then printing certain parts out.

## uninitialized memory
If a function allocates a struct but does not initialize certain fields, you could utilize a UAF to set the memory to desired values.


