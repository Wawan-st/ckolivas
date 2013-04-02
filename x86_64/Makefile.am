noinst_LIBRARIES	= libx8664.a

SUFFIXES = .asm

libx8664_a_SOURCES	= sha256_xmm_amd64.asm sha256_sse4_amd64.asm

.asm.o:
if HAVE_WINDOWS
	$(YASM) -f win64 $<
else
if HAVE_OSX
	$(YASM) -f macho64 $<
else
	$(YASM) -f elf64 $<
endif
endif
