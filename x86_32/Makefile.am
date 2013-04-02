noinst_LIBRARIES	= libx8632.a

SUFFIXES = .asm

libx8632_a_SOURCES	= sha256_xmm.asm

.asm.o:
if HAVE_WINDOWS
	$(YASM) -f win32 $<
else
if HAVE_OSX
	$(YASM) -f macho32 $<
else
	$(YASM) -f elf32 $<
endif
endif
