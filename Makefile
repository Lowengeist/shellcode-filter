PROG=shellcode-filter
INTERPRETER=/lib64/ld-linux-x86-64.so.2

build: $(PROG)
	strip $<

$(PROG): $(PROG).o
	ld -I$(INTERPRETER) -lc -o $@ $< 
	rm -f $<
	chmod +x $@

$(PROG).o: $(PROG).asm
	nasm -f elf64 $<

run: build
	./$(PROG)

debug: $(PROG)
	gdb ./$<

clean: 
	rm -f $(PROG) $(PROG).o 