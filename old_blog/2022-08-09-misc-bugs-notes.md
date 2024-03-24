---
layout: post
title: "Miscellaneous Bugs Notes"
---

## uninitialized memory
Often, programmers will forget to initialize memory in a struct. If you can allocate memory there with ```malloc``` or some other function, you can potentially "poison" the memory so that desired values fill the struct.

You can also "spray" the heap with lots of values so that subsequent calls to ```malloc``` are likely to return pointers in a poisoned area.

## integer edge cases
### underflow / overflow
Since numbers are fixed width, if you (over|under)flow a number, it will wrap around. For example, if ```x``` is an ```unsigned short```, ```x = 0xffff + 1;``` will set ```x``` to zero.

### truncation
When an ```n``` bit type is compared with an ```m``` bit type, where ```n > m```, the former will get some of its bits truncated in the comparison. This could lead to bypassing conditionals that are not supposed to be bypassed.

### signed / unsigned ints
When signed and unsigned numbers are mixed in comparisons or arithmetic, there's a good chance of a bug. This is because signed representation is vastly different from unsigned. For example, ```0xff == 0b11111111``` for a ```byte``` is ```-1``` for signed, and ```255``` for unsigned.

## TOCTOU / double fetch vulns
TOCTOU stands for "time of check vs time of use", and it refers to a bug where values can be modified between a conditional and the value's usage. These are common in race conditions.

The basic bug is as follows:
```
if (array.length > 32) {
    // fail
}

// vulnerable function that allows us to change array.length
// note: this could also be a race condition with another thread (that has access to array)
vuln(array);

if (index >= array.length) {
    array.items[index] = value; // this gives us arbitrary write into array struct
}
```
