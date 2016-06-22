/*  
    Copyright (C) 2015-2016  ANSSI
    Copyright (C) 2015  Thomas Cordier

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hexagon.hpp"

static int notify(processor_t::idp_notify msgid, ...)
{
	va_list va;
	va_start(va, msgid);
	int code = invoke_callbacks(HT_IDP, msgid, va);
	return 1;
}

static const char *RegNames[] = {
	// General Registers
	"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
	"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
	"R16", "R17", "R18", "R19", "R20", "R21", "R22", "R23",
	"R24", "R25", "R26", "R27", "R28", "R29", "R30", "R31",	// R29=SP, R30=FP, R31=LR
	// Control Registers
	"SA0", "LC0", "SA1", "LC1",	// C0 , C1 , C2 , C3 
	"C4",				// C4 = P3:0 !!!
	"M0", "M1",			// C6 , C7
	"USR", "PC", "UGP", "GP",	// C8 , C9 , C10, C11
	"CS0", "CS1", "UPCYCLELOW", "UPCYCLEHI",	// C12, C13, C14, C15
	// Virtual Segment Registers
	"VCS", "VDS",
};

// module registration

static const char *const shnames[] = { "Hexagon", NULL };
static const char *const lnames[] = { "Qualcomm Hexagon DSP v5", NULL };

static asm_t gas = {
	ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR | AS_LALIGN |
	    AS_1TEXT | AS_ONEDUP | AS_COLON,
	1,			// uflag
	"GNU assembler",	// name
	0,			// help
	NULL,			// header
	NULL,			// bad instructions
	".org",			// origin
	".end",			// end

	"//",			// comment string
	'"',			// string delimiter
	'\'',			// char delimiter
	"\"'",			// special symbols in char and string constants

	".ascii",		// ascii
	".byte",		// byte
	".short",		// word
	".long",		// dword
	".quad",		// qword
	NULL,			// oword  (16 bytes)
	".float",		// float
	".double",		// double
	NULL,			// tbyte (no information about this directive)
	NULL,			// packreal
	".ds.#s(b,w,l,d) #d, #v",	// arrays (#h,#d,#v,#s(...)
	".ds.b %s",		// bss
	".equ",			// equ
	NULL,			// seg

	NULL,			// int (*checkarg_preline)(char *argstr, s_preline *S);
	NULL,			// char *(*checkarg_atomprefix)(char *operand,int *res);
	NULL,			// char *checkarg_operations;

	NULL,			// uchar *XlatAsciiOutput
	".",			// char *a_curip;
	NULL,			// function header
	NULL,			// function footer
	".globl",		// public
	NULL,			// weak
	".extern",		// extrn
	NULL,			// comdef
	NULL,			// get name of type
	".align",		// align
	'(', ')',		// lbrace, rbrace
	"%",			// mod
	"&",			// and
	"|",			// or
	"^",			// xor
	"~",			// not
	">>",			// shl
	"<<",			// shr
	NULL,			// sizeof
};

asm_t *asms[] = { &gas, NULL };

#define rVcs (qnumber(RegNames)-2)
#define rVds (qnumber(RegNames)-1)

processor_t LPH = {
	IDP_INTERFACE_VERSION,	// version
	0x8666,			// id
	/*  flags used
	   = PR_USE32           // supports 32-bit addressing?
	   = PR_DEFSEG32        // segments are 32-bit by default

	   -- by hexagon
	   - PR_WORD_INS        // instruction codes are grouped 2bytes in binrary line prefix
	   h PR_NO_SEGMOVE      // the processor module doesn't support move_segm() (i.e. the user can't move segments)
	   h PRN_HEX            // default number representation: == hex
	   ? PR_DELAYED         // has delayed jumps and calls if this flag is set, processor_t::is_basic_block_end should be implemented
	   -- by arm module
	   a PR_SEGS            // has segment registers?
	   a PR_RNAMESOK        // allow to user register names for location names
	   a PR_TYPEINFO        // the processor module supports type information callbacks ALL OF THEM SHOULD BE IMPLEMENTED!  (the ones >= decorate_name)
	   a PR_SGROTHER        // the segment registers don't contain the segment selectors, something else
	   a PR_USE_ARG_TYPES   // use processor_t::use_arg_types callback
	   a PR_CNDINSNS        // has conditional instructions
	 */

	PR_CNDINSNS | PR_NO_SEGMOVE | PR_USE32 | PR_DEFSEG32 | PRN_HEX,	// flags
	8,			// 8 bits in a byte for code segments
	8,			// 8 bits in a byte for other segments
	shnames,
	lnames,
	asms,
	notify,
	header,
	footer,
	segstart,
	segend,
	NULL,			// assumes,
	ana,
	emu,
	out,
	outop,
	intel_data,
	NULL,			// compare operands
	NULL,			// can have type

	qnumber(RegNames),	// Number of registers
	RegNames,		// Register names
	NULL,			// get abstract register

	0,			// Number of register files
	NULL,			// Register file names
	NULL,			// Register descriptions
	NULL,			// Pointer to CPU registers

	rVcs,			// first
	rVds,			// last
	1,			// size of a segment register
	rVcs, rVds,

	NULL,			// No known code start sequences
	/*    retcodes */ NULL,

	0,
	Hexa_last,
	Instructions,

	NULL,			// int   (idaapi *is_far_jump)(int icode);
	NULL,			// ea_t (idaapi *translate)(ea_t base, adiff_t offset);
	0,			// size_t tbyte_size;
	NULL,			// int (idaapi *realcvt)(void *m, uint16 *e, uint16 swt);
	{ 0, 0, 0, 0 },		// char real_width[4];
	NULL,			// bool (idaapi *is_switch)(switch_info_ex_t *si);
	NULL,			// int32 (idaapi *gen_map_file)(FILE *fp);
	NULL,			// ea_t (idaapi *extract_address)(ea_t ea,const char *string,int x);
	NULL,			// int (idaapi *is_sp_based)(const op_t &x);
	NULL,			// bool (idaapi *create_func_frame)(func_t *pfn);
	NULL,			// int (idaapi *get_frame_retsize)(func_t *pfn);
	NULL,			// void (idaapi *gen_stkvar_def)(char *buf, size_t bufsize, const member_t *mptr, sval_t v);
	NULL,			// bool (idaapi *u_outspec)(ea_t ea,uchar segtype);
	0,			// int icode_return;
	0,			// set_options_t *set_idp_options;
	0,			// int (idaapi *is_align_insn)(ea_t ea);
	0,			// mvm_t *mvm;
	0,			// int high_fixup_bits;
};
