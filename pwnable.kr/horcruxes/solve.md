# pwnable.kr: horcruxes

## approach 1
Tried to jump to 80a00d2 the address contains 0a (newline) so it doesn't work.

## approach 2
Can we modify the sum variable instead?

Maybe we can call read(0, &sum, 4), then return to ropme.

Payload: `'A'*(0x74+4) + p32(READ_PLT) + p32(0) + ... + ` (might need some `ret`s for alignment).

- This may not work because of the null bytes passed to `read`.

Could we instead call `scanf("%d", &sum)`?

## approach 3

What if we leak sum?

`'A'*(0x74+4) + p32(PUTS_PLT) + p32(&sum) + ... + `

## approach 4

Oops, that was all wrong, I didn't notice we're literally given `a`, `b`, etc inside of the relevant functions. So we can just jump to `A`, then `B`, then `C`, etc then restart the binary or jump to `ropme`.
