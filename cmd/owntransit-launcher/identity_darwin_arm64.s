//go:build darwin && arm64

#include "textflag.h"

TEXT libc_mbr_uid_to_uuid_trampoline<>(SB),NOSPLIT,$0-0
	JMP libc_mbr_uid_to_uuid(SB)

GLOBL ·libcMbrUIDToUUIDTrampolineAddress(SB), RODATA, $8
DATA ·libcMbrUIDToUUIDTrampolineAddress(SB)/8, $libc_mbr_uid_to_uuid_trampoline<>(SB)
