---
layout: post
title: "Race Conditions Notes"
---

## basics
Multithreaded programs are susceptible to race conditions when proper locking is not implemented. Because threads share the same address space, having multiple threads read/write to memory could result in unexpected bugs.

### create and join threads
```
pthread_t t1;
pthread_t t2;

...

void* func1(void* x) {
    // do some stuff

    pthread_exit(NULL);
}

void* func2(void* x) {
    // do other stuff

    pthread_exit(NULL);
}

pthread_create(&t1, NULL, func1, (void *)1);
pthread_create(&t2, NULL, func2, (void *)2);

...

pthread_join(t1, NULL);
pthread_join(t2, NULL);
```

## exploitation
Here is an example of a race condition:
```
while (1) 
{
    printf("Setting 0...\n");
    shared = 0;
    printf("Checking for 0...\n");
    if (shared != 0) 
    {
        printf("Race won!\n");
        system("/bin/sh");
    }
}
```
There is no locking here, so if another thread has access to ```shared```, you could win the race and pop a shell. Specifically, what might happen is that thread A may read/write to shared, but then immediately after, thread B may read/write to shared (before the comparison). Another example is a shared global counter: suppose 1) thread A reads the counter value into a register, 2) thread B reads the counter into a register, 3) thread A increments the register and then writes it to memory, 4) thread B increments the register and then writes it to memory. The counter would only increment once, when we want it to increment twice. Of course, there are other possible orderings for execution order.

These kinds of bugs may require multiple tries to get right, because they are non-deterministic (the threads' execution depends on the OS scheduler, which does not guarantee anything about execution order).
