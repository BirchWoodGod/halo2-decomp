#include <stdint.h>
/* Diagnostic only, x86 hosts: positive-normal arithmetic path on native x87.
 * This does not implement the CRT special-value/error paths. The literal DC E1
 * encodes FSUBR ST(1),ST; AT&T assembler subtraction mnemonics are ambiguous.
 * Compare the opcode sequence with original 00327f84 before interpreting results.
 */
double probe_power(double base,double exponent) {
    uint16_t saved,working;double result;
    __asm__ volatile("fnstcw %0":"=m"(saved));
    working=(saved&0x300)|0x7f;
    __asm__ volatile("fldcw %0"::"m"(working));
    __asm__ volatile("fldl %2; fldl %1; fyl2x; fld %%st(0); frndint; .byte 0xdc,0xe1; fxch; fchs; f2xm1; fld1; faddp; fscale; fstp %%st(1); fstpl %0":"=m"(result):"m"(base),"m"(exponent):"st");
    __asm__ volatile("fldcw %0"::"m"(saved));return result;
}
