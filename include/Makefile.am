include_HEADERS = sysinfo.h readproc.h
noinst_HEADERS =

all: setup

setup:
	ln -f -s ${KERNEL_DIR}/include/linux linux
	ln -f -s ${KERNEL_DIR}/include/asm asm

clean:
	rm -f linux asm
