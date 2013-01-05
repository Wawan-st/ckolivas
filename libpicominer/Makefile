NAME		= picominer
OFILES		= picominer.o
CPPFLAGS	= -W -Wall -O2 -fpic -DLINUX -DPOSIX -I.. -I../libblkmaker -I/usr/src/picocomputing-5.0.6.1/software/include -I/usr/src/picocomputing-5.0.6.1/software/include/linux
LDFLAGS		=
CC		= g++
LIBRARY		= lib${NAME}.a
SHLIB_MAJOR	= 0
SHLIB_MINOR	= 0
SHLIB_RELEASE	= 1
SHARED_EXT	= .so.${SHLIB_MAJOR}.${SHLIB_MINOR}.${SHLIB_RELEASE}
SHARED_LIBRARY	= lib${NAME}${SHARED_EXT}

INSTALL_PREFIX	= /usr/local

all: ${LIBRARY} ${SHARED_LIBRARY}

${LIBRARY}: ${OFILES}
	ar rc $@ ${OFILES}
	ranlib $@

${SHARED_LIBRARY}:
	${CC} -shared -o ${SHARED_LIBRARY} -Wl,-soname=lib${NAME}.so.${SHLIB_MAJOR} ${OFILES} /usr/local/lib/libpico.a

install:
	( [ -d ${INSTALL_PREFIX} ] || mkdir ${INSTALL_PREFIX} ) && \
	( [ -d ${INSTALL_PREFIX}/lib ] || mkdir ${INSTALL_PREFIX}/lib ) && \
	cp ${LIBRARY} ${INSTALL_PREFIX}/lib && \
	cp ${SHARED_LIBRARY} ${INSTALL_PREFIX}/lib && \
	rm -f ${INSTALL_PREFIX}/lib/lib${NAME}.so && \
	ln -s ${INSTALL_PREFIX}/lib/${SHARED_LIBRARY} \
	   ${INSTALL_PREFIX}/lib/lib${NAME}.so

uninstall:
	rm -f ${INSTALL_PREFIX}/lib/${SHARED_LIBRARY} \
	   ${INSTALL_PREFIX}/lib/lib${NAME}.so \
	   ${INSTALL_PREFIX}/lib/${LIBRARY}

clean:
	rm -f ${OFILES} ${LIBRARY} ${SHARED_LIBRARY} lib${NAME}.so.1 lib${NAME}.so
