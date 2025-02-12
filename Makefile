PROG=shellcode-filter
INTERPRETER=/lib64/ld-linux-x86-64.so.2

$(PROG): $(PROG).o
	ld -I$(INTERPRETER) -lc -e main -o $@ $< 
	rm -f $<
	chmod +x $@

$(PROG).o: $(PROG).asm
	nasm -f elf64 $<

run: $(PROG)
	./$<

clean: 
	rm -f $(PROG) $(PROG).o 