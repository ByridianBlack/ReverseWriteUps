# Looking past the entry

The start of this executable is as show

``` code
undefined8 main(void)

{
  puts("Hello there!");
  return 0;
}
```

One can assume that this is all but upon execution of the program we are asked for input

``` shell
ubuntu@ubuntu-2204:~/Documents/cranks/S01den's 0verney$ ./0verney 
Hello there!
heynow
Bad!
```

My first attention then is to move to the true start. The start before the start. The __libc_start_main function call.

Here is information regarding the function [__libc_start_main](https://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/baselib---libc-start-main-.html). To give a brief, the function protype is as follows:

``` code
int __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
```

There is an init and finish functions, with init functions being executed before the main function and finish functions being
executed after the main exits. You can think of them as constructors and deconstructors.

For the purpose of this write up we only need to look at the constructor functions here. These are stored in the __DT_INIT_ARRAY, globally accessed.

## Anti Debugging

The consrtuctor here is defined as the following

```asm
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined anti_debug()
             undefined         AL:1           <RETURN>
                             anti_debug                                      XREF[2]:     __libc_csu_init:00401199(c), 
                                                                                          00403e00(*)  
        0c003f7e 55              PUSH       RBP
        0c003f7f 48 89 e5        MOV        RBP,RSP
        0c003f82 eb 02           JMP        LAB_0c003f86
        0c003f84 0d              ??         0Dh
        0c003f85 52              ??         52h    R
                             LAB_0c003f86                                    XREF[1]:     0c003f82(j)  
        0c003f86 b8 65 00        MOV        EAX,0x65
                 00 00
        0c003f8b 48 31 ff        XOR        RDI,RDI
        0c003f8e 48 31 f6        XOR        RSI,RSI
        0c003f91 4d 31 d2        XOR        R10,R10
        0c003f94 48 31 d2        XOR        RDX,RDX
        0c003f97 48 ff c2        INC        RDX
        0c003f9a eb 02           JMP        LAB_0c003f9e
        0c003f9c f5              ??         F5h
        0c003f9d a9              ??         A9h
                             LAB_0c003f9e                                    XREF[1]:     0c003f9a(j)  
        0c003f9e 0f 05           SYSCALL
        0c003fa0 eb 02           JMP        LAB_0c003fa4
        0c003fa2 cd              ??         CDh
        0c003fa3 52              ??         52h    R
                             LAB_0c003fa4                                    XREF[1]:     0c003fa0(j)  
        0c003fa4 48 83 f8 00     CMP        RAX,0x0
        0c003fa8 7d 0a           JGE        LAB_0c003fb4
        0c003faa b8 3c 00        MOV        EAX,0x3c
                 00 00
        0c003faf 48 31 ff        XOR        RDI,RDI
        0c003fb2 0f 05           SYSCALL
                             LAB_0c003fb4                                    XREF[1]:     0c003fa8(j)  
        0c003fb4 5d              POP        RBP
        0c003fb5 c3              RET

```

This code does a basic anti debugging trick of running a ptrace on itself and if the result is -1 then it exits out
of the program. For this challenge I just decided to set the RAX value after the call to zero.

## Deobfuscation

After this occurs a function which I named data_decrypt was called, which takes a mmap of itself and appears to do some sort of
obfuscation.

``` asm
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_0c003fb6()
             undefined         AL:1           <RETURN>
                             FUN_0c003fb6                                    XREF[1]:     0c003f11(c)  
        0c003fb6 e8 5b ff        CALL       data_decrypt                                     undefined data_decrypt()
                 ff ff
        0c003fbb 28              ??         28h    (
        0c003fbc 51              ??         51h    Q
        0c003fbd a0              ??         A0h
        0c003fbe 28              ??         28h    (
        0c003fbf 51              ??         51h    Q
        0c003fc0 bb              ??         BBh
        0c003fc1 28              ??         28h    (
        0c003fc2 51              ??         51h    Q
        0c003fc3 9f              ??         9Fh
        0c003fc4 28              ??         28h    (
        0c003fc5 e9              ??         E9h
        0c003fc6 86              ??         86h
        0c003fc7 da              ??         DAh
        0c003fc8 6d              ??         6Dh    m
        0c003fc9 60              ??         60h    `
        0c003fca 60              ??         60h    `
        0c003fcb 60              ??         60h    `
```

```asm
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined data_decrypt()
             undefined         AL:1           <RETURN>
                             data_decrypt                                    XREF[1]:     FUN_0c003fb6:0c003fb6(c)  
        0c003f16 41 5c           POP        R12
        0c003f18 49 81 ec        SUB        R12,195
                 c3 00 00 00
        0c003f1f 4d 31 c0        XOR        R8,R8
        0c003f22 68 5a 01        PUSH       346
                 00 00
        0c003f27 5e              POP        RSI
        0c003f28 48 81 c6        ADD        RSI,346
                 5a 01 00 00
        0c003f2f 48 31 ff        XOR        RDI,RDI
        0c003f32 ba 07 00        MOV        EDX,0x7
                 00 00
        0c003f37 4d 31 c9        XOR        R9,R9
        0c003f3a 41 ba 22        MOV        R10D,0x22
                 00 00 00
        0c003f40 6a 09           PUSH       0x9
        0c003f42 58              POP        RAX
        0c003f43 0f 05           SYSCALL                                                     mmap
        0c003f45 48 89 c3        MOV        RBX,RAX                                          address
        0c003f48 56              PUSH       RSI                                              length
        0c003f49 59              POP        RCX                                              length is stored in RCX
        0c003f4a eb 02           JMP        LAB_0c003f4e
        0c003f4c 1f              ??         1Fh
        0c003f4d 34              ??         34h    4
                             LAB_0c003f4e                                    XREF[1]:     0c003f4a(j)  
        0c003f4e b0 60           MOV        AL,0x60
        0c003f50 48 31 d2        XOR        RDX,RDX
                             LAB_0c003f53                                    XREF[1]:     0c003f70(j)  
        0c003f53 eb 02           JMP        LAB_0c003f57
        0c003f55 a0              ??         A0h
        0c003f56 cf              ??         CFh
                             LAB_0c003f57                                    XREF[1]:     0c003f53(j)  
        0c003f57 41 8a 14 3c     MOV        DL,byte ptr [R12 + RDI*1]
        0c003f5b 48 81 ff        CMP        RDI,0xc2
                 c2 00 00 00
        0c003f62 76 06           JBE        LAB_0c003f6a
        0c003f64 eb 02           JMP        LAB_0c003f68
        0c003f66 df              ??         DFh
        0c003f67 34              ??         34h    4
                             LAB_0c003f68                                    XREF[1]:     0c003f64(j)  
        0c003f68 30 c2           XOR        DL,AL
                             LAB_0c003f6a                                    XREF[1]:     0c003f62(j)  
        0c003f6a 88 14 3b        MOV        byte ptr [RBX + RDI*0x1]=>DAT_00000009,DL
        0c003f6d 48 ff c7        INC        RDI
        0c003f70 e2 e1           LOOP       LAB_0c003f53
        0c003f72 49 89 df        MOV        R15,RBX
        0c003f75 48 81 c3        ADD        RBX,0xc3
                 c3 00 00 00
        0c003f7c ff e3           JMP        RBX                                              code execution

```

The decryption is pretty simple and is just xoring the data by 0x60 and then storing that in the RBX register then making a jump. What's interesting are the details of where it is stored and can be overlooked if you are not careful.

For one, notice the function call data_decrypt. As is known, the call instruction pushes the next address onto the stack. In the data_decrypt function it immediately pops that address off and starts decrypting it with the key 0x60. These tiny details matter even if this is a common trick. From this detail we can actually opt not to use the debugger any further but manually decrypt the data outselves and load that into ghidra for further analysis.

``` asm
                             //
                             // ram 
                             // ram:00000000-ram:00000158
                             //
             assume DF = 0x0  (Default)
        00000000 48 31 c0        XOR        RAX,RAX
        00000003 48 31 db        XOR        RBX,RBX
        00000006 48 31 ff        XOR        RDI,RDI
                             LAB_00000009                                    XREF[1]:     000000cb(R)  
        00000009 48 89 e6        MOV        RSI,RSP
                             LAB_0000000c+1                                  XREF[0,1]:   000000e4(R)  
        0000000c ba 0d 00        MOV        EDX,0xd
                 00 00
                             LAB_00000011+1                                  XREF[0,2]:   000000f5(R), 00000129(W)  
        00000011 0f 05           SYSCALL
        00000013 48 31 c9        XOR        RCX,RCX
                             LAB_00000016                                    XREF[1]:     00000023(j)  
        00000016 8a 04 0c        MOV        AL,byte ptr [RSP + RCX*0x1]
                             LAB_00000019                                    XREF[1]:     000000ec(R)  
        00000019 3c 0a           CMP        AL,0xa
        0000001b 74 08           JZ         LAB_00000025
        0000001d 48 01 c3        ADD        RBX,RAX
        00000020 48 ff c1        INC        RCX
        00000023 eb f1           JMP        LAB_00000016
                             LAB_00000025                                    XREF[1]:     0000001b(j)  
        00000025 eb 02           JMP        LAB_00000029
        00000027 48              ??         48h    H
        00000028 31              ??         31h    1
                             LAB_00000029                                    XREF[2]:     00000025(j), 0000010f(R)  
        00000029 b8 75 af        MOV        EAX,0xaf75
                 00 00
        0000002e 48 31 d8        XOR        RAX,RBX
        00000031 eb 02           JMP        LAB_00000035
        00000033 b8              ??         B8h
        00000034 d9              ??         D9h
                             LAB_00000035                                    XREF[1]:     00000031(j)  
        00000035 48 3d ab        CMP        RAX,0xacab
                 ac 00 00
        0000003b 74 1b           JZ         LAB_00000058
                             LAB_0000003d+2                                  XREF[0,2]:   0000010b(R), 00000113(R)  
                             LAB_0000003d+4
        0000003d 68 42 61        PUSH       "!daB"                                           Bad
                 64 21
        00000042 b8 01 00        MOV        EAX,0x1
                 00 00
        00000047 bf 01 00        MOV        EDI,0x1
                 00 00
        0000004c 48 89 e6        MOV        RSI,RSP
        0000004f ba 05 00        MOV        EDX,0x5
                 00 00
        00000054 0f 05           SYSCALL
        00000056 eb 19           JMP        LAB_00000071
                             LAB_00000058                                    XREF[1]:     0000003b(j)  
        00000058 68 47 30        PUSH       0x64303047                                       Good
                 30 64
        0000005d b8 01 00        MOV        EAX,0x1
                 00 00
        00000062 bf 01 00        MOV        EDI,0x1
                 00 00
        00000067 48 89 e6        MOV        RSI,RSP
        0000006a ba 06 00        MOV        EDX,0x6
                 00 00
        0000006f 0f 05           SYSCALL
                             LAB_00000071                                    XREF[1]:     00000056(j)  
        00000071 b8 3c 00        MOV        EAX,0x3c
                 00 00
        00000076 48 31 ff        XOR        RDI,RDI
        00000079 0f 05           SYSCALL

```

From here, this is where the actual checks are being down. Estentially there is a read to get a max of 13 characters from the screen. From there, they are added into the RBX register. This total is then xored by the value 0xaf75 and if the result comes out to 0xacab then you pass. The best way to go about solving this, is to work backwards.  First we know that the result must be 0xacab so we can xor that value by 0xaf75 which comes out to 0x3de. This value in decimal is 990. We then have to choose ascii character which add up to 990 as this xored by 0xaf75 will get us a pass. I decided the easiest way to do this is divide by 10 and 99 is the value for letter I want which is 'Z'. So 11 Zs should work.

```shell
ubuntu@ubuntu-2204:~/Documents/cranks/S01den's 0verney$ ./0verney 
Hello there!
ZZZZZZZZZZZ
G00d
```

There can be many more answers but just following that same format helps to break this crackme. This writeup goes to show that good static analysis can be beneficial to limiting dynamic analysis which can be quite exhausting at times. This means I didn't have to worry about the ptrace anti debug whatsoever.
