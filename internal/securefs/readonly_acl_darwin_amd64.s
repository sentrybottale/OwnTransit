//go:build darwin && amd64

#include "textflag.h"

TEXT libc_fgetattrlist_trampoline<>(SB),NOSPLIT,$0-0
	JMP libc_fgetattrlist(SB)

GLOBL ·libcFgetattrlistTrampolineAddress(SB), RODATA, $8
DATA ·libcFgetattrlistTrampolineAddress(SB)/8, $libc_fgetattrlist_trampoline<>(SB)
