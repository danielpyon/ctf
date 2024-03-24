---
layout: post
title: "Information Representation"
---

Computers store mainly two types of data: numbers and characters. Numbers can be categorized into integers (whole numbers) and floats (decimal numbers). Integers have two main representations: unsigned or signed. Floating point numbers can be single or double precision. Characters, on the other hand, are encoded with either ASCII or Unicode.

## Numbers
### Integers
Unsigned integers are the simplest: each bit in an unsigned integer represents a power of 2, just like how each digit in a base 10 number represents a power of 10. So if you have ```1011```, that's equal to ```1*2^3 + 0*2^2 + 1*2^1 + 1*2^0 = 11``` in base 10. Note that adding two ```n``` bit numbers wraps around to zero when you exceed the max value that ```n``` bits can represent (```2^n - 1```).

Another possible representation for unsigned integers is BCD (binary coded decimal), where each base 10 digit is turned into a 4 bit number. So for example, ```42``` would be encoded as ```0100 0010```. The first nibble is a ```4``` in decimal, and the second is a ```2```. This isn't very common though, because the circuitry is more complicated to do arithmetic. It's still used in clocks and date/time representation.

Signed integers are slightly more complicated. In 2's complement representation, the most significant bit represents the sign (```0 = positive, 1 = negative```), and the rest of the bits represent the number. If the number in question is positive, it's basically the same as unsigned representation except the MSB is a zero. So ```11``` base 10 would be encoded as ```0000 1011``` in base 2. However, if the number is negative, the MSB is a one, and the rest of the bits are the 2's complement of the number. So ```-11``` in base 10 would be encoded as ```1111 0101``` in base 2 (invert the bits, add one). This makes it easier to do subtraction because you can use an adder circuit.

There are other ways to do signed integer representation, like 1's complement and sign-magnitude, but they make the arithmetic circuitry more complicated so they aren't as common.

### Floats
The IEEE-754 standard specifies how floats are stored. They're stored in scientific notation, which includes a sign bit, mantissa, and exponent. It's just like decimal scientific notation (ex: ```1.2345 * 10^42```) except the mantissa and exponent are in base 2. The exponent is biased such that you can represent negative exponents and positive exponents. In other words, the range of the exponent is shifted down by half of the values it can represent (so if it went from ```0``` to ```2^8 - 1``` it would go from ```-2^4``` to ```2^4 - 1```).

Single precision uses 32 bits (1 sign bit, 8 exponent bits, 23 mantissa bits) with a biased-127 exponent, and double precision uses 64 bits (1 sign bit, 11 exponent bits, 52 mantissa bits) with a biased-1023 exponent.

There are a few special values: zero, +infinity, -infinity, and NaN. Zero is when the mantissa and exponent are all zeros (the sign bit can be zero or one, meaning that there's positive and negative zero). Positive infinity is when the exponent is all ones, mantissa is all zeros, and the sign bit is zero. Negative infinity is when the exponent is all ones, mantissa is all zeros, and the sign bit is one. NaN (not a number) is when the exponent is all ones, but the mantissa is not all zeros. This might happen if you try to divide by zero.

Another way you could do it is to use fixed point notation. But certain fractions can't be represented very precisely as a binary fraction, and the range of values you could represent would be much smaller.

## Characters
### ASCII and Extended ASCII
A long time ago, some Americans came up with a character encoding called ASCII. This was before networking, so they didn't think of representing non-English characters.

Each character in ASCII is 8 bits. The MSB doesn't matter, but the rest of the 7 bits do. Every possible 7 bit number maps to a unique character specified in the ASCII standard.

There's also extended ASCII, where the MSB is used to represent more characters.

### Unicode
Unicode can represent all sorts of characters, including non-English ones. Every character in Unicode has a codepoint, which is just a number that identifies what character it is. They're usually written as ```U+[hex value]```, so for example ```U+0041```.

Those codepoints are encoded using UTF-8, which is a variable-length encoding. Variable length, because some codepoints require more than 8 bits to represent. For example, there's 1-byte UTF-8, 2-byte UTF-8, 3-byte UTF-8, and 4-byte UTF-8. With just 1-byte UTF-8, it's the same as ASCII. But with more than 1 byte, there's a unique identifier in the most significant byte so that computers can decode the characters. For example, all 2-byte UTF-8 characters have a most significant byte that starts with ```110```, and all subsequent bytes start with ```10```.