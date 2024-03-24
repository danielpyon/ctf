---
layout: post
title: "Error Correction and Detection"
---

## Parity
Imagine that you have 4 bits of data (```1011```) stored somewhere in memory. How do you check that the bits haven't been flipped? This is important for both storing data, and sending data over wire. Imagine if data over wire were modified during transmission. Detecting errors would allow one computer to request the data again. A simple approach is to add an extra bit at the end of the data that makes the entire data have an even or odd number of ones (the actual parity doesn't matter as long as, in the case of networked devices, both computers have a common protocol). So for example, if two computers decide on even parity, the data will become ```10111```. This approach will only work when the number of errors is an odd number though, and will fail if the parity bit gets flipped.

## Hamming Code
Hamming codes use the idea of parity bits to achieve SECDEC (single error correction, double error detection). Here's how it works: for the example bits above, the data stored is ```1011```. Assign ```1```, ```1```, ```0```, and ```1``` to ```d1```, ```d2```, ```d3``` and ```d4```, respectively (these are the "data" bits). Then, instead of just one parity bit, there are three, each representing a group of data bits. For example, ```p1``` is the parity bit for ```d1```, ```d2```, and ```d4``` (see image below).

![Hamming(7,4)](/assets/hamming74.png)

Now, let's assume that we want the parity of groups to be even. How do we compute the parity bits? Turns out, we can use ```XOR``` gates: ```p1 = d1 XOR d2 XOR d4``` (the same applies to ```p2``` and ```p3```), because the ```XOR``` gate outputs one when the number of ones in its input is odd. This has the effect of setting the parity bit appropriately: if the data is odd, then the parity becomes one, making the whole group even; if the data is even, then the parity is zero, keeping the group even.

When another computer receives the data (or if your computer retrieves the data from memory), it will use the data bits to compute new parity bits and compare them to the original parity bits. If the parity bits match up, then there was no error. What's interesting is that if there was exactly one bit flip, this method finds it and corrects it. How does it work? There are two cases: either a parity bit was flipped, or a data bit was. If a parity bit was flipped, then there should only be one group whose computed parity doesn't match the original parity, since if a data bit was flipped, it would change the parity of at least two groups (we specifically made every data bit belong to at least two groups). So for example, if ```p1``` got flipped in our example from ```1``` to ```0```, then the computed parity for that group would still be ```1```, so there would be exactly one mismatch between the original and computed parity bits, and we would know that ```p1``` was the bit that changed. If a data bit was flipped, it makes the computed parity bits different for at least two groups. If ```d4``` was flipped, then all three computed parity bits wouldn't match, and only ```d4``` could've caused that. If ```d2``` was flipped, then exactly two parity groups wouldn't match, and only ```d2``` is shared between those two groups.

Double error detection requires just adding an extra global parity bit. If after attempting a correction, the global parity bit doesn't make all the bits even, then there's been two errors.

You can extend this idea for more data bits with the error syndrome, where ```s_n = p_n XOR p_n'```, where ```p_n'``` is the nth computed parity bit and ```p_n``` is the nth original parity bit. Each syndrome bit represents whether there was a difference between the original and computed parity bits. 

| S4 | S3 | S2 | S1 | Error    |
| -- | -- | -- | -- | -------- |
| 0  | 0  | 0  | 0  | No error |
| 0  | 0  | 0  | 1  | P1 |
| 0  | 0  | 1  | 0  | P2 |
| 0  | 0  | 1  | 1  | D1 |
| 0  | 1  | 0  | 0  | P3 |
| 0  | 1  | 0  | 1  | D2 |
| 0  | 1  | 1  | 0  | D3 |
| 0  | 1  | 1  | 1  | D4 |
| 1  | 0  | 0  | 0  | P4 |
| 1  | 0  | 0  | 1  | D5 |
| 1  | 0  | 1  | 0  | D6 |
| 1  | 0  | 1  | 1  | D7 |
| 1  | 1  | 0  | 0  | D8 |
| 1  | 1  | 0  | 1  |  |
| 1  | 1  | 1  | 0  |  |
| 1  | 1  | 1  | 1  |  |

All rows with exactly one ```1``` means that a single parity bit was flipped (a single mismatch between the original/computed parity bits), rows with all zeros means no error (no difference between original/computed parity bits), and the first 8 patterns that aren't either of those represent a single error in a data bit (from ```D1``` to ```D8```). Notice that all syndrome patterns for data bit errors contain at least two ones, so they are a part of at least two groups. The rest of the bits are not used.

I've just described Hamming(12, 8), where 12 = 8 data bits + 4 parity bits. In the table above, there are a total of 13 types of errors that need to be represented (8 data bits, 4 parity bits, and no error), and 16 possible combinations of syndrome bits. The number of possible combinations of syndrome bits needs to be greater than or equal to the number of types of errors in order to represent them, so ```n + m + 1 <= 2^m``` where ```n``` is the number of data bits, and ```m``` is the number of parity bits. So for example, if you have 26 bits of data, you need at least 5 parity bits for this to work.

## Checksums
A  simpler way to do error detection is to simply sum the data, so that any bit flips result in a different sum. Let's say you're transmitting ```"morning"```, encoded as ASCII, to another computer. ```"morning"``` is ```6d 6f 72 6e 69 6e 67``` in hex. Adding all the bytes together (whenever there's a carry, just add it back in), you get ```fc```, which is an extra byte you add to the end of your message. Then the other computer calculates the sum the same way, and if it's not ```fc```, there's been an error and a request is sent for the data again.

There is an alternative version of this called 1's complement checksum where the last byte is inverted, so that adding all the data bytes to the last byte results in ```-1``` assuming signed integer representation. There's also 2's complement, where the last byte is the negative version of the sum, so that adding all the data bytes to it results in zero.

## Cyclic Redundancy Check

Notice that with checksums, it's easy for the data to be changed so that the sum is the same. For example, the first byte of the string ```"morning"```, might go from ```01101101``` to ```11101100``` (the first and last bits flipped), and the checksum would be the same since one was added and subtracted.

CRCs are similar to checksums, but instead of just adding the data, the data is hashed using the something similar to the modulo operator. It's not exactly the modulo operator, it's a simpler operation that is close enough to produce a good hash (repeated XORs, which is similar to repeated subtraction, which is what the modulo operator does).