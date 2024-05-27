# pwnable.kr: leg

Answer: 0x00008ce4 + 0x00008d80 + 0x00008d0c = 108400

Explanation: key1 stores r3==pc in r0, which is current instruction (0x00008cdc) plus 8.

key2 stores r3, which is current instruction (0x00008d04) plus 4 (cuz thumb mode), plus another 4 (due to `adds	r3, #4`). this equals `0x00008d0c`.

key3 just stores `lr`, which is the address after the branch, aka: `0x00008d80`

