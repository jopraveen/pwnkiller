# pwnkiller (beta v1)

- Pwnkiller is an automated tool for solving pwn challenges
- It isn't capable of solving all pwn challenges, but it can handle plenty of warmup and easy stack challenges

### currently it can do
```
- find leaks (PIE LEAK, CANARY LEAK, LIBC LEAK, STACK LEAK)
- find offsets to RIP (with and without canary)
- ret2win
- ret2plt
- ret2shellcode
- rop (sigrop/exploit with syscalls)
- remote exploit
```

### usage
```js
➜  pwnkiller  ./pwnkiller.py -h

           ██████╗ ██╗    ██╗███╗   ██╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗ 
           ██╔══██╗██║    ██║████╗  ██║██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
           ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╔╝ ██║██║     ██║     █████╗  ██████╔╝
           ██╔═══╝ ██║███╗██║██║╚██╗██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
           ██║     ╚███╔███╔╝██║ ╚████║██║  ██╗██║███████╗███████╗███████╗██║  ██║
           ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝ 
                             Jopraveen{w31c0M3_70_PwN_4nD_P41n}

usage: pwnkiller.py [-h] -b  [-of] [-ip] [-p] [-exp] [-win]

Pwnkiller goes bruhhhhh...

optional arguments:
  -h, --help          show this help message and exit
  -b , --binary       binary file
  -of , --offset      manually specify offset to the return address
  -ip , --IPaddress   IP of the remote server
  -p , --port         Port of the remote server
  -exp , --exploit    Specify the exploitation technique
  -win , --winaddr    Win address
```

### challenges solved/tested by pwnkiller
- **[See here](https://github.com/jopraveen/pwnkiller/blob/main/challenges/README.md)**
