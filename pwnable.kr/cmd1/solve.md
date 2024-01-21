# pwnable.kr: cmd1

The challenge is to read `flag` without using `flag`, `tmp`, or `sh`.

We can bypass the filter by using an environment variable, as such: `x=flag ./cmd1 /bin/cat\<\$x`.
