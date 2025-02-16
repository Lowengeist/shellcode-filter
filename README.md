# shellcode-filter
Stupid tool to help visualize what instructions are available from a limited set of bytes, badly written in x64.

WIP.

## Usage

To build, you can use
```
make
```
To run you can either provide the set of bytes that are available to the building of your shellcode, or provide the ones you want to exclude :
```shell
./shellcode-filter -i 4143      # only include the bytes 0x41 and 0x43
./shellcode-filter -x 70        # exclude the byte 0x70
```

## One last word

Cool ressources:
- https://wiki.osdev.org/X86-64_Instruction_Encoding
- https://www.felixcloutier.com/x86/

Any feedback would be greatly appreciated.