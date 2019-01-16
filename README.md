# C ASM Memcheck

This library is intended to validate the compilation of C programs using the
DWARF debug information.

In order to do this, we perform a parallel interpretation of the C source
program and the disassembled binary, and check at each link point (given by the
.debug_line table) that the memory state is the one expected.
