PROG=shellcode-filter
AS = nasm
INTERPRETER=/lib64/ld-linux-x86-64.so.2
ASFLAGS = -f elf64
LDFLAGS = -I$(INTERPRETER) -lc

BUILD_MODE ?= release

all: $(PROG)

$(PROG): $(PROG).o
	ld $(LDFLAGS) -o $@ $<
	@rm -f $<
	@if [ "$(BUILD_MODE)" = "release" ]; then\
		strip -R .hash -R .gnu.version -R .eh_frame $@;\
	fi

$(PROG).o: $(PROG).asm
	$(AS) $(ASFLAGS) -o $@ $<

run: $(PROG)
	./$<

debug: $(PROG)
	gdb ./$<

clean:
	rm -f $(PROG) $(PROG).o