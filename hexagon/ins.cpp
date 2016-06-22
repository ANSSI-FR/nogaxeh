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

#include "ins.hpp"

instruc_t Instructions[] = {

	{"", 0}
	,			// Unknown Operation
	// ALU32_ALU
	{"ADD", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_ADD_Rd_Rs_s16,
	{"ADD", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_ADD_Rd_Rs_Rt,
	{"ADD", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_ADDsat_Rd_Rs_Rt,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_AND_Rd_Rs_s10,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_AND_Rd_Rs_Rt,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_ANDnot_Rd_Rt_Rs,
	{"NOT", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_NOT_Rd_Rs,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_OR_Rd_Rs_s10,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_OR_Rd_Rs_Rt,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_ORnot_Rd_Rs_Rt,
	{"XOR", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_XOR_Rd_Rs_Rt,
	{"NEG", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_NEG_Rd_Rs,
	{"NOP", 0}
	,			// Hexa_ALU32_NOP, !!!! to change ?
	{"SUB", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_SUB_Rd_s10_Rs,
	{"SUB", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_SUB_Rd_Rt_Rs,
	{"SUB", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_SUBsat_Rd_Rt_Rs,
	{"SXTB", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_SXTB_Rd_Rs,
	{"SXTH", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_SXTH_Rd_Rs,
	{"Timm", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_TransferImm_Rd_s16,
	{"Timm", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_TransferImm_Rdd_s8,
	{"Timm", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_TransferImmLow_Rd_u16,
	{"Timm", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_TransferImmHigh_Rd_u16,
	{"Treg", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_TransferReg_Rd_Rs,
	{"Treg", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_TransferReg_Rdd_Rss,
	{"VADDH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VADDH_Rd_Rs_Rt,
	{"VADDH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VADDHsat_Rd_Rs_Rt,
	{"VADDUH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VADDUHsat_Rd_Rs_Rt,
	{"VAVGH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VAVGH_Rd_Rs_Rt,
	{"VAVGH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VAVGHrnd_Rd_Rs_Rt,
	{"VNAVGH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VNAVGH_Rd_Rs_Rt,
	{"VSUBH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VSUBH_Rd_Rs_Rt,
	{"VSUBH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VSUBHsat_Rd_Rs_Rt,
	{"VSUBUH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_VSUBUHsat_Rd_Rs_Rt,
	{"ZXTB", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_ZXTB_Rd_Rs,
	{"ZXTH", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_ZXTH_Rd_Rs,

	// ALU32_PERM
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rd_RsH_RtH,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rd_RsL_RtH,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rd_RsH_RtL,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rd_RsL_RtL,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rdd_S8_S8,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rdd_S8_U8,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rdd_S8_Rs,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rdd_Rs_S8,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_COMBINE_Rdd_Rs_Rt,
	{"MUX", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_MUX_Rd_Pu_S8_S8,
	{"MUX", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_MUX_Rd_Pu_S8_Rs,
	{"MUX", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_MUX_Rd_Pu_Rs_S8,
	{"MUX", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_MUX_Rd_Pu_Rs_Rt,
	{"ASLH", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_ASLH_Rd_Rs,
	{"ASRH", CF_CHG1 | CF_USE2}
	,			// Hexa_ALU32_ASRH_Rd_Rs,
	{"PACKHL", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_PACKHL_Rd_Rs_Rt,

	// ALU32_PRED
	{"ADD", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_ADD_Pu_Rd_Rs_S8,
	{"ADD", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_ADD_Pu_Rd_Rs_Rt,
	{"ASLH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_ASLH_Pu_Rd_Rs,
	{"ASRH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_ASRH_Pu_Rd_Rs,
	{"COMBINE", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_COMBINE_Pu_Rd_Rs_Rt,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_AND_Pu_Rd_Rs_Rt,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_OR_Pu_Rd_Rs_Rt,
	{"XOR", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_XOR_Pu_Rd_Rs_Rt,
	{"SUB", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_ALU32_C_SUB_Pu_Rd_Rs_Rt,
	{"SXTB", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_SXTB_Pu_Rd_Rs,
	{"SXTH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_SXTH_Pu_Rd_Rs,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_TransferImm_Pu_Rd_S12,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_TransferReg_Pu_Rd_Rs,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_TransferReg_Pu_Rdd_Rss,
	{"ZXTB", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_ZXTB_Pu_Rd_Rs,
	{"ZXTH", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_C_ZXTH_Pu_Rd_Rs,
	{"CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_eq_Pu_Rs_S10,
	{"!CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_eq_Pu_Rs_S10,
	{"CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_eq_Pu_Rs_Rt,
	{"!CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_eq_Pu_Rs_Rt,
	{"CMP.GT", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_gt_Pu_Rs_S10,
	{"!CMP.GT", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_gt_Pu_Rs_S10,
	{"CMP.GT", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_gt_Pu_Rs_Rt,
	{"!CMP.GT", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_gt_Pu_Rs_Rt,
	{"CMP.GTU", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_gtu_Pu_Rs_U9,
	{"!CMP.GTU", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_gtu_Pu_Rs_U9,
	{"CMP.GTU", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_gtu_Pu_Rs_Rt,
	{"!CMP.GTU", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_gtu_Pu_Rs_Rt,
	{"CMP.GE", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_ge_Pu_Rs_S8,
	{"CMP.GEU", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_geu_Pu_Rs_U7,
	{"CMP.LT", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_lt_Pu_Rs_Rt,
	{"CMP.LTU", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_ltu_Pu_Rs_Rt,
	{"CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_eq_Rd_Rs_S8,
	{"!CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_eq_Rd_Rs_S8,
	{"CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_CMP_eq_Rd_Rs_Rt,
	{"!CMP.EQ", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_ALU32_not_CMP_eq_Rd_Rs_Rt,

	// CR
	{"FASTCORNER9", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_FASTCORNER9_Pd_Ps_Pt,
	{"!FASTCORNER9", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_not_FASTCORNER9_Pd_Ps_Pt,
	{"ALL8", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_ALL8_Pd_Ps,
	{"ANY8", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_ANY8_Pd_Ps,
	{"LOOP0", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_LOOP0_R72_U10,
	{"LOOP0", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_LOOP0_R72_Rs,
	{"LOOP1", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_LOOP1_R72_U10,
	{"LOOP1", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_LOOP1_R72_Rs,
	{"ADD", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_ADD_Rd_Pc_U6,
	{"SP1LOOP0", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_SP1LOOP0_P3_R72_U10,
	{"SP1LOOP0", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_SP1LOOP0_P3_R72_Rs,
	{"SP2LOOP0", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_SP2LOOP0_P3_R72_U10,
	{"SP2LOOP0", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_SP2LOOP0_P3_R72_Rs,
	{"SP3LOOP0", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_SP3LOOP0_P3_R72_U10,
	{"SP3LOOP0", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_SP3LOOP0_P3_R72_Rs,
	{"", CF_CHG1 | CF_USE2}
	,			// Hexa_CR_TransferPred_Pd_Ps,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_AND_Pd_Ps_AND_Pt_Pu,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_AND_Pd_Ps_OR_Pt_Pu,
	{"AND", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_AND_Pd_Pt_Ps,
	{"NOT", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_NOT_Pd_Ps,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_OR_Pd_Ps_AND_Pt_Pu,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4}
	,			// Hexa_CR_OR_Pd_Ps_OR_Pt_Pu,
	{"OR", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_OR_Pd_Pt_Ps,
	{"XOR", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_XOR_Pd_Ps_Pt,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_TransferPred_Cd_Rs,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_TransferPred_Cdd_Rss,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_TransferPred_Rd_Cs,
	{"", CF_CHG1 | CF_USE2 | CF_USE3}
	,			// Hexa_CR_TransferPred_Rdd_Css,

	// J_JR
	{"CALLR", CF_CHG1}
	,			// Hexa_J_JR_CALLR_Rs,
	{"CALLR", CF_CHG1}
	,			// Hexa_J_JR_C_CALLR_Pu_Rs,
	{"HINTJR", CF_CHG1}
	,			// Hexa_J_JR_HINTJ_Rs,
	{"JUMPR", CF_CHG1}
	,			// Hexa_J_JR_JUMPR_Rs,
	{"JUMPR", CF_CHG1}
	,			// Hexa_J_JR_C_JUMPR_Pu_Rs,
	{"CALL", CF_CHG1}
	,			// Hexa_J_JR_CALL_R222,
	{"CALL", CF_CHG1}
	,			// Hexa_J_JR_C_CALL_Pu_R152,
	{"CMP.EQ", CF_CHG1}
	,			// Hexa_J_JR_CMP_EQ_Pd_Rs_C_JUMP_R92,
	{"CMP.EQ", CF_CHG1}
	,			// Hexa_J_JR_CMP_EQ_Pd_Rs_U5_C_JUMP_R92,
	{"CMP.EQ", CF_CHG1}
	,			// Hexa_J_JR_CMP_EQ_Pd_Rs_Rt_C_JUMP_R92,
	{"CMP.GT", CF_CHG1}
	,			// Hexa_J_JR_CMP_GT_Pd_Rs_C_JUMP_R92,
	{"CMP.GT", CF_CHG1}
	,			// Hexa_J_JR_CMP_GT_Pd_Rs_U5_C_JUMP_R92,
	{"CMP.GT", CF_CHG1}
	,			// Hexa_J_JR_CMP_GT_Pd_Rs_Rt_C_JUMP_R92,
	{"CMP.GTU", CF_CHG1}
	,			// Hexa_J_JR_CMP_GTU_Pd_Rs_U5_C_JUMP_R92,
	{"CMP.GTU", CF_CHG1}
	,			// Hexa_J_JR_CMP_GTU_Pd_Rs_Rt_C_JUMP_R92,
	{"TSTBIT", CF_CHG1}
	,			// Hexa_J_JR_TSTBIT_Pd_Rs_C_JUMP_R92,
	{"JUMP", CF_CHG1}
	,			// Hexa_J_JR_C_JUMP_Pu_R152,
	{"JUMP", CF_CHG1}
	,			// Hexa_J_JR_JUMP_R222,
	{"!=#0", CF_CHG1}
	,			// Hexa_J_JR_C_differ_Rs_JUMPp_R132,
	{"<=#0", CF_CHG1}
	,			// Hexa_J_JR_C_lower_Rs_JUMPp_R132,
	{"==#0", CF_CHG1}
	,			// Hexa_J_JR_C_equal_Rs_JUMPp_R132,
	{">=#0", CF_CHG1}
	,			// Hexa_J_JR_C_greater_Rs_JUMPp_R132,
	{"JUMP", CF_CHG1}
	,			// Hexa_J_JR_Transfer_Rd_U6_JUMP_R92,
	{"JUMP", CF_CHG1}
	,			// Hexa_J_JR_Transfer_Rd_Rs_JUMP_R92,

	// LD
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Re_U6,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rs_S113,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rs_Rt_U2,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rt_U2_U6,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rx_S43,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rx_S43_circ_Mu,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rx_circ_Mu,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rx_Mu,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_MEMD_Rdd_Rx_Mu_brev,
	{"MEMD", CF_CHG1 | CF_CHG2 | CF_USE2}
	,			// Hexa_LD_MEMD_Rdd_GP_U163,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_C_MEMD_Rdd_U6,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_C_MEMD_Rdd_Rs_U63,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_C_MEMD_Rdd_Rx_S43,
	{"MEMD", CF_CHG1}
	,			// Hexa_LD_C_MEMD_Rdd_Rs_Rt_U2,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Re_U6,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rs_S112,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rs_Rt_U2,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rt_U2_U6,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rx_S42,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rx_S42_circ_Mu,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rx_circ_Mu,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rx_Mu,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_Rx_Mu_brev,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_MEMW_Rd_GP_U162,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_C_MEMW_Rd_U6,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_C_MEMW_Rd_Rs_U62,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_C_MEMW_Rd_Rx_S42,
	{"MEMW", CF_CHG1}
	,			// Hexa_LD_C_MEMW_Rd_Rs_Rt_U2,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Re_U6,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rs_S111,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rs_Rt_U2,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rt_U2_U6,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rx_S41,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rx_S41_circ_Mu,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rx_circ_Mu,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rx_Mu,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_Rx_Mu_brev,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_MEMH_Rd_GP_U161,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_C_MEMH_Rd_U6,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_C_MEMH_Rd_Rs_U61,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_C_MEMH_Rd_Rx_S41,
	{"MEMH", CF_CHG1}
	,			// Hexa_LD_C_MEMH_Rd_Rs_Rt_U2,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Re_U6,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rs_S110,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rs_Rt_U2,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rt_U2_U6,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rx_S40,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rx_S40_circ_Mu,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rx_circ_Mu,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rx_Mu,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_Rx_Mu_brev,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_MEMB_Rd_GP_U160,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_C_MEMB_Rd_U6,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_C_MEMB_Rd_Rs_U60,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_C_MEMB_Rd_Rx_S40,
	{"MEMB", CF_CHG1}
	,			// Hexa_LD_C_MEMB_Rd_Rs_Rt_U2,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Re_U6,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rs_S111,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rs_Rt_U2,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rt_U2_U6,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rx_S41,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rx_S41_circ_Mu,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rx_circ_Mu,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rx_Mu,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_Rx_Mu_brev,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_MEMUH_Rd_GP_U161,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_C_MEMUH_Rd_U6,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_C_MEMUH_Rd_Rs_U61,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_C_MEMUH_Rd_Rx_S41,
	{"MEMUH", CF_CHG1}
	,			// Hexa_LD_C_MEMUH_Rd_Rs_Rt_U2,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Re_U6,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rs_S110,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rs_Rt_U2,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rt_U2_U6,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rx_S40,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rx_S40_circ_Mu,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rx_circ_Mu,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rx_Mu,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_Rx_Mu_brev,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_MEMUB_Rd_GP_U160,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_C_MEMUB_Rd_U6,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_C_MEMUB_Rd_Rs_U60,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_C_MEMUB_Rd_Rx_S40,
	{"MEMUB", CF_CHG1}
	,			// Hexa_LD_C_MEMUB_Rd_Rs_Rt_U2,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Re_U6,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rs,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rs_S111,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rt_U2_U6,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rx_S41,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rx_S41_circ_Mu,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rx_circ_Mu,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rx_Mu,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rd_Rx_Mu_brev,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Re_U6,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rs,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rs_S111,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rt_U2_U6,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rx_S41,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rx_S41_circ_Mu,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rx_circ_Mu,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rx_Mu,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rd_Rx_Mu_brev,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Re_U6,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rs,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rs_S112,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rt_U2_U6,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rx_S42,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rx_S42_circ_Mu,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rx_circ_Mu,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rx_Mu,
	{"MEMBH", CF_CHG1}
	,			// Hexa_LD_MEMBH_Rdd_Rx_Mu_brev,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Re_U6,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rs,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rs_S112,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rt_U2_U6,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rx_S42,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rx_S42_circ_Mu,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rx_circ_Mu,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rx_Mu,
	{"MEMUBH", CF_CHG1}
	,			// Hexa_LD_MEMUBH_Rdd_Rx_Mu_brev,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Re_U6,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rs,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rs_S111,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rt_U2_U6,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rx_S41,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rx_S41_circ_Mu,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rx_circ_Mu,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu,
	{"MEMH_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu_brev,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Re_U6,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rs,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rs_S110,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rt_U2_U6,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rx_S40,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rx_S40_circ_Mu,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rx_circ_Mu,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu,
	{"MEMB_FIFO", CF_CHG1}
	,			// Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu_brev,
	{"DEALLOCFRAME", CF_CHG1}
	,			// Hexa_LD_DEALLOCFRAME,
	{"DEALLOC_RETURN", CF_CHG1}
	,			// Hexa_LD_DEALLOC_RETURN,
	{"DEALLOC_RETURN", CF_CHG1}
	,			// Hexa_LD_C_DEALLOC_RETURN_Ps,

	// MEMOP
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_CLRBIT_U5,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_SETBIT_U5,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_+_U5,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_-_U5,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_+_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_-_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_|_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_MEMOP_MEMB_Rs_U60_&_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_CLRBIT_U5,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_SETBIT_U5,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_+_U5,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_-_U5,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_+_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_-_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_|_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_MEMOP_MEMH_Rs_U61_&_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_CLRBIT_U5,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_SETBIT_U5,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_+_U5,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_-_U5,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_+_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_-_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_|_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_MEMOP_MEMW_Rs_U62_&_Rt,

	// ST
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Re_U6_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rs_S113_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rs_Ru_U2_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Ru_U2_U6_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rx_S43_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rx_S43_circ_Mu_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rx_circ_Mu_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rx_Mu_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_Rx_Mu_brev_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_MEMD_GP_U163_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_C_MEMD_U6_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_C_MEMD_Rs_U63_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_C_MEMD_Rx_S43_Rtt,
	{"MEMD", CF_CHG1}
	,			// Hexa_ST_C_MEMD_Rs_Rt_U2_Rtt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Re_U6_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rs_S112_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rs_Ru_U2_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Ru_U2_U6_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rx_S42_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rx_S42_circ_Mu_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rx_circ_Mu_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rx_Mu_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rx_Mu_brev_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_GP_U162_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_C_MEMW_U6_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_C_MEMW_Rs_U62_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_C_MEMW_Rx_S42_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_C_MEMW_Rs_Rt_U2_Rt,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_MEMW_Rs_U112_S8,
	{"MEMW", CF_CHG1}
	,			// Hexa_ST_C_MEMW_Rs_U62_S6,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Re_U6_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rs_S111_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rs_Ru_U2_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Ru_U2_U6_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rx_S41_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rx_S41_circ_Mu_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rx_circ_Mu_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rx_Mu_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rx_Mu_brev_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_GP_U161_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_C_MEMH_U6_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_C_MEMH_Rs_U61_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_C_MEMH_Rx_S41_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_C_MEMH_Rs_Rt_U2_Rt,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_MEMH_Rs_U111_S8,
	{"MEMH", CF_CHG1}
	,			// Hexa_ST_C_MEMH_Rs_U61_S6,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Re_U6_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rs_S110_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rs_Ru_U2_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Ru_U2_U6_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rx_S40_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rx_S40_circ_Mu_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rx_circ_Mu_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rx_Mu_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rx_Mu_brev_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_GP_U160_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_C_MEMB_U6_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_C_MEMB_Rs_U60_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_C_MEMB_Rx_S40_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_C_MEMB_Rs_Rt_U2_Rt,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_MEMB_Rs_U110_S8,
	{"MEMB", CF_CHG1}
	,			// Hexa_ST_C_MEMB_Rs_U60_S6,
	{"ALLOCFRAME", CF_CHG1}
	,			// Hexa_ST_ALLOCFRAME_U113,

	// SYSTEM
	{"MEMW_LOCKED", CF_CHG1}
	,			// Hexa_SYSTEM_MEMW_LOCKED_Rd_Rs,
	{"MEMD_LOCKED", CF_CHG1}
	,			// Hexa_SYSTEM_MEMW_LOCKED_Rdd_Rs,
	{"MEMD_LOCKED", CF_CHG1}
	,			// Hexa_SYSTEM_MEMW_LOCKED_Rs_Pd_Rtt,
	{"MEMW_LOCKED", CF_CHG1}
	,			// Hexa_SYSTEM_MEMW_LOCKED_Rs_Pd_Rt,
	{"DCZEROA", CF_CHG1}
	,			// Hexa_SYSTEM_DCZEROA_Rs,
	{"BARRIER", CF_CHG1}
	,			// Hexa_SYSTEM_BARRIER,
	{"BRKPT", CF_CHG1}
	,			// Hexa_SYSTEM_BRKPT,
	{"DCFETCH", CF_CHG1}
	,			// Hexa_SYSTEM_DCFETCH_Rs,
	{"DCFETCH", CF_CHG1}
	,			// Hexa_SYSTEM_DCFETCH_Rs_U113,
	{"DCCLEANA", CF_CHG1}
	,			// Hexa_SYSTEM_DCCLEANA_Rs,
	{"DCCLEANINVA", CF_CHG1}
	,			// Hexa_SYSTEM_DCCLEANINVA_Rs,
	{"DCINVA", CF_CHG1}
	,			// Hexa_SYSTEM_DCINVA_Rs,
	{"ICINVA", CF_CHG1}
	,			// Hexa_SYSTEM_ICINVA_Rs,
	{"ISYNC", CF_CHG1}
	,			// Hexa_SYSTEM_ISYNC,
	{"L2FETCH", CF_CHG1}
	,			// Hexa_SYSTEM_L2FETCH_Rs_Rt,
	{"L2FETCH", CF_CHG1}
	,			// Hexa_SYSTEM_L2FETCH_Rs_Rtt,
	{"PAUSE", CF_CHG1}
	,			// Hexa_SYSTEM_PAUSE_U8,
	{"SYNCHT", CF_CHG1}
	,			// Hexa_SYSTEM_SYNCHT,
	{"TRACE", CF_CHG1}
	,			// Hexa_SYSTEM_TRACE_Rs,
	{"TRAP0", CF_CHG1}
	,			// Hexa_SYSTEM_TRAP0_U8,
	{"TRAP1", CF_CHG1}
	,			// Hexa_SYSTEM_TRAP1_U8,

	// XTYPE_ALU
	{"ABS", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ABS_Rdd_Rss,
	{"ABS", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ABS_Rd_Rs,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADD_Rd_Rs_ADD_Ru_S6,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADD_Rd_Rs_ADD_S6_Ru,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_S8,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_Rt,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_S8,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_Rt,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADD_Rd_Rs_Rt_sat_deprecated,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADD_Rdd_Rs_Rtt,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADDh_Rd_Rt_Rs,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt_Px_carry,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_SUB_Rdd_Rss_Rtt_Px_carry,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_AND_Rdd_Rss_Rtt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_AND_Rdd_Rtt_n_Rss,
	{"NOT", CF_CHG1}
	,			// Hexa_XTYPE_ALU_NOT_Rdd_Rss,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_OR_Rdd_Rss_Rtt,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_OR_Rdd_Rtt_n_Rss,
	{"XOR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_XOR_Rdd_Rss_Rtt,
	{"XOR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_xoreq_XOR_Rdd_Rss_Rtt,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_OR_Rx_Ru_AND_Rx_S10,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_andeq_AND_Rs_Rt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_oreq_AND_Rs_Rt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_xoreq_AND_Rs_Rt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_andeq_AND_Rs_n_Rt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_oreq_AND_Rs_n_Rt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_xoreq_AND_Rs_n_Rt,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_andeq_OR_Rs_Rt,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_oreq_OR_Rs_Rt,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_xoreq_OR_Rs_Rt,
	{"XOR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_andeq_XOR_Rs_Rt,
	{"XOR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_oreq_XOR_Rs_Rt,
	{"XOR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_xoreq_XOR_Rs_Rt,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_oreq_AND_Rs_S10,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_ALU_oreq_OR_Rs_S10,
	{"MAX", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MAX_Rd_Rs_Rt,
	{"MAXU", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MAXU_Rd_Rs_Rt,
	{"MAX", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MAX_Rdd_Rss_Rtt,
	{"MAXU", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MAXU_Rdd_Rss_Rtt,
	{"MIN", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MIN_Rd_Rs_Rt,
	{"MINU", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MINU_Rd_Rs_Rt,
	{"MIN", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MIN_Rdd_Rss_Rtt,
	{"MINU", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MINU_Rdd_Rss_Rtt,
	{"MODWRAP", CF_CHG1}
	,			// Hexa_XTYPE_ALU_MODWRAP_Rd_Rs_Rt,
	{"NEG", CF_CHG1}
	,			// Hexa_XTYPE_ALU_NEG_Rd_Rs_sat,
	{"NEG", CF_CHG1}
	,			// Hexa_XTYPE_ALU_NEG_Rdd_Rss,
	{"CROUND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_CROUND_Rd_Rs_U5,
	{"CROUND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_CROUND_Rd_Rs_Rt,
	{"ROUND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ROUND_Rd_Rs_U5,
	{"ROUND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ROUND_Rd_Rs_Rt,
	{"ROUND", CF_CHG1}
	,			// Hexa_XTYPE_ALU_ROUND_Rdd_Rss_sat,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_SUB_Rd_Rt_Rs_sat_deprecated,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_SUB_Rdd_Rtt_Rss,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_pluseq_SUB_Rd_Rt_Rs,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_SUBh_Rd_Rt_Rs,
	{"SXTW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_SXTW_Rdd_Rs,
	{"VABSH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VABSH_Rdd_Rss,
	{"VABSW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VABSW_Rdd_Rss,
	{"VABSDIFFH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VABSDIFFH_Rdd_Rtt_Rss,
	{"VABSDIFFW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VABSDIFFW_Rdd_Rtt_Rss,
	{"VADDB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VADDB_Rdd_Rss_Rtt,
	{"VADDUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VADDUB_Rdd_Rss_Rtt,
	{"VADDH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VADDH_Rdd_Rss_Rtt,
	{"VADDUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VADDUH_Rdd_Rss_Rtt_sat,
	{"VADDW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VADDW_Rdd_Rss_Rtt_sat,
	{"VADDHUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VADDHUB_Rd_Rss_Rtt_sat,
	{"VRADDUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRADDUB_Rdd_Rss_Rtt,
	{"VRADDUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_pluseq_VRADDUB_Rdd_Rss_Rtt,
	{"VRADDH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRADDH_Rd_Rss_Rtt,
	{"VRADDUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRADDUH_Rd_Rss_Rtt,
	{"VAVGH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VAVGH_Rdd_Rss_Rtt,
	{"VAVGUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VAVGUH_Rdd_Rss_Rtt,
	{"VNAVGH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VNAVGH_Rdd_Rss_Rtt,
	{"VAVGUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VAVGUB_Rdd_Rss_Rtt,
	{"VAVGW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VAVGW_Rdd_Rss_Rtt,
	{"VAVGUW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VAVGUW_Rdd_Rss_Rtt,
	{"VNAVGW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VNAVGW_Rdd_Rss_Rtt,
	{"VCNEGH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VCNEGH_Rdd_Rss_Rt,
	{"VRCNEGH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_pluseq_VRCNEGH_Rxx_Rss_Rt,
	{"VMAXB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMAXB_Rdd_Rtt_Rss,
	{"VMAXUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMAXUB_Rdd_Rtt_Rss,
	{"VMAXH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMAXH_Rdd_Rtt_Rss,
	{"VMAXUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMAXUH_Rdd_Rtt_Rss,
	{"VRMAXH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMAXH_Rdd_Rtt_Ru,
	{"VRMAXUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMAXUH_Rdd_Rtt_Ru,
	{"VMAXW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMAXW_Rdd_Rtt_Rss,
	{"VMAXUW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMAXUW_Rdd_Rtt_Rss,
	{"VRMAXW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMAXW_Rdd_Rtt_Ru,
	{"VRMAXUW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMAXUW_Rdd_Rtt_Ru,
	{"VMINB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMINB_Rdd_Rtt_Rss,
	{"VMINUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMINUB_Rdd_Rtt_Rss,
	{"VMINH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMINH_Rdd_Rtt_Rss,
	{"VMINUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMINUH_Rdd_Rtt_Rss,
	{"VRMINH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMINH_Rdd_Rtt_Ru,
	{"VRMINUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMINUH_Rdd_Rtt_Ru,
	{"VMINW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMINW_Rdd_Rtt_Rss,
	{"VMINUW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VMINUW_Rdd_Rtt_Rss,
	{"VRMINW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMINW_Rdd_Rtt_Ru,
	{"VRMINUW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRMINUW_Rdd_Rtt_Ru,
	{"VRSADUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VRSADUB_Rdd_Rss_Rtt,
	{"VRSADUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_pluseg_VRSADUB_Rxx_Rss_Rtt,
	{"VSUBB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VSUBB_Rdd_Rtt_Rss,
	{"VSUBUB", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VSUBUB_Rdd_Rtt_Rss,
	{"VSUBH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VSUBH_Rdd_Rtt_Rss,
	{"VSUBUH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VSUBUH_Rdd_Rtt_Rss_sat,
	{"VSUBW", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VSUBW_Rdd_Rtt_Rss,
	{"VACSH", CF_CHG1}
	,			// Hexa_XTYPE_ALU_VACSH_Rxx_Pe_Rss_Rtt,

	// XTYPE-BIT
	{"ADD(CLB", CF_CHG1}
	,			// Hexa_XTYPE_BIT_ADD_Rd_CLB_Rs_S6,
	{"ADD(CLB", CF_CHG1}
	,			// Hexa_XTYPE_BIT_ADD_Rd_CLB_Rss_S6,
	{"CL0", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CL0_Rd_Rs,
	{"CL0", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CL0_Rd_Rss,
	{"CL1", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CL1_Rd_Rs,
	{"CL1", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CL1_Rd_Rss,
	{"CLB", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CLB_Rd_Rs,
	{"CLB", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CLB_Rd_Rss,
	{"NORMAMT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_NORMAMT_Rd_Rs,
	{"NORMAMT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_NORMAMT_Rd_Rss,
	{"POPCOUNT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_POPCOUNT_Rd_Rss,
	{"CT0", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CT0_Rd_Rs,
	{"CT0", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CT0_Rdd_Rss,
	{"CT1", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CT1_Rd_Rs,
	{"CT1", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CT1_Rdd_Rss,
	{"EXTRACT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_U5_U5,
	{"EXTRACT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_Rtt,
	{"EXTRACTU", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_U5_U5,
	{"EXTRACTU", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_Rtt,
	{"EXTRACT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_U6_U6,
	{"EXTRACT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_Rtt,
	{"EXTRACTU", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_U6_U6,
	{"EXTRACTU", CF_CHG1}
	,			// Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_Rtt,
	{"INSERT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_INSERT_Rd_Rs_U5_U5,
	{"INSERT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_INSERT_Rd_Rs_Rtt,
	{"INSERT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_INSERT_Rdd_Rss_U6_U6,
	{"INSERT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_INSERT_Rdd_Rss_Rtt,
	{"DEINTERLEAVE", CF_CHG1}
	,			// Hexa_XTYPE_BIT_DEINTERLEAVE_Rdd_Rss,
	{"INTERLEAVE", CF_CHG1}
	,			// Hexa_XTYPE_BIT_INTERLEAVE_Rdd_Rss,
	{"LFS", CF_CHG1}
	,			// Hexa_XTYPE_BIT_LFS_Rdd_Rss_Rtt,
	{"PARITY", CF_CHG1}
	,			// Hexa_XTYPE_BIT_PARITY_Rd_Rs_Rt,
	{"PARITY", CF_CHG1}
	,			// Hexa_XTYPE_BIT_PARITY_Rdd_Rss_Rtt,
	{"BREV", CF_CHG1}
	,			// Hexa_XTYPE_BIT_BREV_Rd_Rs,
	{"BREV", CF_CHG1}
	,			// Hexa_XTYPE_BIT_BREV_Rdd_Rss,
	{"CLRBIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_U5,
	{"CLRBIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_Rt,
	{"SETBIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_SETBIT_Rd_Rs_U5,
	{"SETBIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_SETBIT_Rd_Rs_Rt,
	{"TOGGLEBIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_U5,
	{"TOGGLEBIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_Rt,
	{"BITSPLIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_U5,
	{"BITSPLIT", CF_CHG1}
	,			// Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_Rt,
	{"TABLEIDXD", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXD_Rx_Rs_U4_S6_raw,
	{"TABLEIDXD", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXD_Rx_Rs_U4_U5,
	{"TABLEIDXW", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXW_Rx_Rs_U4_S6_raw,
	{"TABLEIDXW", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXW_Rx_Rs_U4_U5,
	{"TABLEIDXH", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXH_Rx_Rs_U4_S6_raw,
	{"TABLEIDXH", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXH_Rx_Rs_U4_U5,
	{"TABLEIDXB", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXB_Rx_Rs_U4_S6_raw,
	{"TABLEIDXB", CF_CHG1}
	,			// Hexa_XTYPE_BIT_TABLEIDXB_Rx_Rs_U4_U5,

	// XTYPE-COMPLEX
	{"VXADDSUBH", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VXADDSUBH_Rdd_Rss_Rtt,
	{"VXSUBADDH", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VXSUBADDH_Rdd_Rss_Rtt,
	{"VXADDSUBW", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VXADDSUBW_Rdd_Rss_Rtt,
	{"VXSUBADDW", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VXSUBADDW_Rdd_Rss_Rtt,
	{"CMPY", CF_CHG1}
	,			//       Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rt,
	{"CMPY", CF_CHG1}
	,			//       Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rtet,
	{"CMPY", CF_CHG1}
	,			//       Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rt,
	{"CMPY", CF_CHG1}
	,			//       Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rtet,
	{"CMPY", CF_CHG1}
	,			//       Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rt,
	{"CMPY", CF_CHG1}
	,			//       Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rtet,
	{"CMPYI", CF_CHG1}
	,			//      Hexa_XTYPE_COMPLEX_CMPYI_Rdd_Rs_Rt,
	{"CMPYR", CF_CHG1}
	,			//      Hexa_XTYPE_COMPLEX_CMPYR_Rdd_Rs_Rt,
	{"CMPYI", CF_CHG1}
	,			//      Hexa_XTYPE_COMPLEX_pluseq_CMPYI_Rdd_Rs_Rt,
	{"CMPYR", CF_CHG1}
	,			//      Hexa_XTYPE_COMPLEX_pluseq_CMPYR_Rdd_Rs_Rt,
	{"CMPY", CF_CHG1}
	,			//      Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rt,
	{"CMPY", CF_CHG1}
	,			//      Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rtet,
	{"CMPYIWH", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rt,
	{"CMPYIWH", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rtet,
	{"CMPYRWH", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rt,
	{"CMPYRWH", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rtet,
	{"VCMPYI", CF_CHG1}
	,			//     Hexa_XTYPE_COMPLEX_VCMPYI_Rdd_Rss_Rtt,
	{"VCMPYR", CF_CHG1}
	,			//     Hexa_XTYPE_COMPLEX_VCMPYR_Rdd_Rss_Rtt,
	{"VCMPYI", CF_CHG1}
	,			//     Hexa_XTYPE_COMPLEX_pluseq_VCMPYI_Rdd_Rss_Rtt,
	{"VCMPYR", CF_CHG1}
	,			//     Hexa_XTYPE_COMPLEX_pluseq_VCMPYR_Rdd_Rss_Rtt,
	{"VCONJ", CF_CHG1}
	,			//     Hexa_XTYPE_COMPLEX_VCONJ_Rdd_Rss,
	{"VCROTATE", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VROTATE_Rdd_Rss_Rt,
	{"VRCMPYI", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rtt,
	{"VRCMPYI", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rttet,
	{"VRCMPYR", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rtt,
	{"VRCMPYR", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rttet,
	{"VRCMPYI", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rtt,
	{"VRCMPYI", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rttet,
	{"VRCMPYR", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rtt,
	{"VRCMPYR", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rttet,
	{"VRCMPYS", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rt,
	{"VRCMPYS", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rtt,
	{"VRCMPYS", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rt,
	{"VRCMPYS", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rtt,
	{"VRCMPYS", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rt,
	{"VRCMPYS", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rtt,
	{"VRCROTATE", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_VRCROTATE_Rdd_Rss_Rt_U2,
	{"VRCROTATE", CF_CHG1}
	,			// Hexa_XTYPE_COMPLEX_pluseq_VRCROTATE_Rdd_Rss_Rt_U2,

	// XTYPE-FP
	{"SFADD", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFADD_Rd_Rs_Rt,
	{"DFCLASS", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFCLASS_Pd_Rss_U5,
	{"SFCLASS", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFCLASS_Pd_Rss_U5,
	{"DFCMP.EQ", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFCMPEQ_Pd_Rss_Rtt,
	{"DFCMP.GE", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFCMPGE_Pd_Rss_Rtt,
	{"DFCMP.GT", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFCMPGT_Pd_Rss_Rtt,
	{"DFCMP.UO", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFCMPUO_Pd_Rss_Rtt,
	{"SFCMP.EQ", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFCMPEQ_Pd_Rs_Rt,
	{"SFCMP.GE", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFCMPGE_Pd_Rs_Rt,
	{"SFCMP.GT", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFCMPGT_Pd_Rs_Rt,
	{"SFCMP.UO", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFCMPUO_Pd_Rs_Rt,
	{"CONVERT_DF2SF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_D2SF_Rd_Rss,
	{"CONVERT_SF2DF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_SF2DF_Rdd_Rs,
	{"CONVERT_D2SF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_D2SF_Rd_Rss,
	{"CONVERT_UD2SF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_UD2SF_Rd_Rss,
	{"CONVERT_W2SF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_W2SF_Rd_Rs,
	{"CONVERT_UW2SF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_UW2SF_Rd_Rs,
	{"CONVERT_D2DF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_D2DF_Rdd_Rss,
	{"CONVERT_UD2DF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_UD2DF_Rdd_Rss,
	{"CONVERT_W2DF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_W2DF_Rdd_Rs,
	{"CONVERT_UW2DF", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_UW2DF_Rdd_Rs,
	{"CONVERT_DF2UW", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_DF2UW_Rd_Rss,
	{"CONVERT_DF2W", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_DF2W_Rd_Rss,
	{"CONVERT_SF2UW", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_SF2UW_Rd_Rs,
	{"CONVERT_SF2W", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_SF2W_Rd_Rs,
	{"CONVERT_DF2UD", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_DF2UD_Rdd_Rss,
	{"CONVERT_DF2D", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_DF2D_Rdd_Rss,
	{"CONVERT_SF2UD", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_SF2UD_Rdd_Rs,
	{"CONVERT_SF2D", CF_CHG1}
	,			// Hexa_XTYPE_FP_CONVERT_SF2D_Rdd_Rs,
	{"SFFIXUPD", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFFIXUPD_Rd_Rs_Rt,
	{"SFFIXUPN", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFFIXUPN_Rd_Rs_Rt,
	{"SFFIXUPR", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFFIXUPR_Rd_Rs,
	{"SFMPY", CF_CHG1}
	,			// Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt,
	{"SFMPY", CF_CHG1}
	,			// Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt,
	{"SFMPY", CF_CHG1}
	,			// Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_Pu,
	{"SFINVSQRTA", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFINVSQRTA_Rd_Pe_Rs,
	{"SFMPY", CF_CHG1}
	,			// Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_lib,
	{"SFMPY", CF_CHG1}
	,			// Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt_lib,
	{"SFMAKE", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFMAKE_Rd_neg,
	{"SFMAKE", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFMAKE_Rd_pos,
	{"DFMAKE", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFMAKE_Rdd_neg,
	{"DFMAKE", CF_CHG1}
	,			// Hexa_XTYPE_FP_DFMAKE_Rdd_pos,
	{"SFMAX", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFMAX_Rd_Rs_Rt,
	{"SFMIN", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFMIN_Rd_Rs_Rt,
	{"SFMPY", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFMPY_Rd_Rs_Rt,
	{"SFSUB", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFSUB_Rd_Rs_Rt,
	{"SFRECIPA", CF_CHG1}
	,			// Hexa_XTYPE_FP_SFRECIPA_Rd_Pe_Rs_Rt,

	// XTYPE-MPY
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_eqplus_MPYI_Rd_Rs_U8,
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_eqless_MPYI_Rd_Rs_U8,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_U8,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_Rt,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_U62_Rs,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_Rs_U6,
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYI_Rd_Rs_M9,
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYI_Rd_Rs_Rt,
	{"MPYUI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYUI_Rd_Rs_Rt,
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_U8,
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPYI_Rd_Rs_U8,
	{"MPYI", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_Rt,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_MPY_ADD_Ry_Ru_MPYI_Ry_Rt,
	{"VMPYWEH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt,
	{"VMPYWOH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt,
	{"VMPYWEH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt,
	{"VMPYWOH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt,
	{"VMPYWEUH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt,
	{"VMPYWOUH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt,
	{"VMPYWEUH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt,
	{"VMPYWOUH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYh_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYh_Rdd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYh_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPYh_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYh_Rdd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPYh_Rdd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYUh_Rd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYUh_Rdd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYUh_Rd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPYUh_Rd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYUh_Rdd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPYUh_Rdd_Rs_Rt,
	{"PMPYW", CF_CHG1}
	,			// Hexa_XTYPE_MPY_PMPYW_Rdd_Rs_Rt,
	{"PMPYW", CF_CHG1}
	,			// Hexa_XTYPE_MPY_xoreq_PMPYW_Rdd_Rs_Rt,
	{"VRMPYWEH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VRMPYWEH_Rdd_Rss_Rtt,
	{"VRMPYWOH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VRMPYWOH_Rdd_Rss_Rtt,
	{"VRMPYWEH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VRMPYWEH_Rdd_Rss_Rtt,
	{"VRMPYWOH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VRMPYWOH_Rdd_Rss_Rtt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYuh_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt,
	{"MPYSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYSU_Rd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYU_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPY_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPY_Rd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPY_Rdd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_MPYU_Rdd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPY_Rdd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_MPYU_Rdd_Rs_Rt,
	{"MPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPY_Rdd_Rs_Rt,
	{"MPYU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_lesseq_MPYU_Rdd_Rs_Rt,
	{"VDMPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VDMPY_Rdd_Rss_Rtt,
	{"VDMPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VDMPY_Rdd_Rss_Rtt,
	{"VDMPY", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt,
	{"VRMPYBSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VRMPYBSU_Rdd_Rss_Rtt,
	{"VRMPYBU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VRMPYBU_Rdd_Rss_Rtt,
	{"VRMPYBSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VRMPYBSU_Rdd_Rss_Rtt,
	{"VRMPYBU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VRMPYBU_Rdd_Rss_Rtt,
	{"VDMPYBSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VDMPYBSU_Rdd_Rss_Rtt,
	{"VDMPYBSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VDMPYBSU_Rdd_Rss_Rtt,
	{"VMPYEH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYEH_Rdd_Rss_Rtt,
	{"VMPYEH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYEH_pluseq_Rdd_Rss_Rtt,
	{"VMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYH_Rdd_Rs_Rt,
	{"VMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYH_pluseq_Rdd_Rs_Rt,
	{"VMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYH_Rd_Rs_Rt,
	{"VMPYHSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYHSU_Rdd_Rs_Rt,
	{"VMPYHSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYHSU_pluseq_Rdd_Rs_Rt,
	{"VRMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VRMPYH_Rdd_Rss_Rtt,
	{"VRMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VRMPYH_Rdd_Rss_Rtt,
	{"VMPYBSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYBSU_Rdd_Rs_Rt,
	{"VMPYBU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VMPYBU_Rdd_Rs_Rt,
	{"VMPYBSU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VMPYBSU_Rdd_Rs_Rt,
	{"VMPYBU", CF_CHG1}
	,			// Hexa_XTYPE_MPY_pluseq_VMPYBU_Rdd_Rs_Rt,
	{"VPMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_VPMPYH_Rdd_Rs_Rt,
	{"VPMPYH", CF_CHG1}
	,			// Hexa_XTYPE_MPY_xoreq_VPMPYH_Rdd_Rs_Rt,

	// XTYPE-PERM
	{"DECBIN", CF_CHG1}
	,			// Hexa_XTYPE_PERM_DECBIN_Rdd_Rss_Rtt,
	{"SAT", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SAT_Rd_Rss,
	{"SATB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SATB_Rd_Rs,
	{"SATH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SATH_Rd_Rs,
	{"SATUB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SATUB_Rd_Rs,
	{"SATUH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SATUH_Rd_Rs,
	{"SWIZ", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SWIZ_Rd_Rs,
	{"VALIGNB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_U3,
	{"VALIGNB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_Pu,
	{"VRNDWH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VRNDWH_Rdd_Rs,
	{"VSATHB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATHB_Rd_Rs,
	{"VSATHB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATHB_Rd_Rss,
	{"VSATHUB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATHUB_Rd_Rs,
	{"VSATHUB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATHUB_Rd_Rss,
	{"VSATWH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATWH_Rd_Rss,
	{"VSATWUH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATWUH_Rd_Rss,
	{"VSATHB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATHB_Rdd_Rss,
	{"VSATHUB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATHUB_Rdd_Rss,
	{"VSATWH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATWH_Rdd_Rss,
	{"VSATWUH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSATWUH_Rdd_Rss,
	{"SHUFFEB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SHUFFEB_Rdd_Rss_Rtt,
	{"SHUFFEH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SHUFFEH_Rdd_Rss_Rtt,
	{"SHUFFOB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SHUFFOB_Rdd_Rtt_Rss,
	{"SHUFFOH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_SHUFFOH_Rdd_Rtt_Rss,
	{"VSPLATB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSPLATB_Rd_Rs,
	{"VSPLATH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSPLATH_Rdd_Rs,
	{"VSPLICEB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_U3,
	{"VSPLICEB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_Pu,
	{"VSXTBH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSXTBH_Rdd_Rs,
	{"VSXTHW", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VSXTBW_Rdd_Rs,
	{"VTRUNEHB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VTRUNEHB_Rdd_Rs,
	{"VTRUNOHB", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VTRUNOHB_Rdd_Rs,
	{"VTRUNEWH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VTRUNEWH_Rdd_Rss_Rtt,
	{"VTRUNOWH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VTRUNOWH_Rdd_Rss_Rtt,
	{"VZXTBH", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VZXTBH_Rdd_Rs,
	{"VZXTHW", CF_CHG1}
	,			// Hexa_XTYPE_PERM_VZXTHW_Rdd_Rs,

	// XTYPE-PRED
	{"BOUNDSCHECK", CF_CHG1}
	,			// Hexa_XTYPE_PRED_BOUNDSCHECK_Pd_Rs_Rtt,
	{"BOUNDSCHECK", CF_CHG1}
	,			// Hexa_XTYPE_PRED_BOUNDSCHECK_Pd_Rss_Rtt,
	{"CMPB.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_U8,
	{"CMPB.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_Rt,
	{"CMPB.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_S8,
	{"CMPB.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_Rt,
	{"CMPB.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_U7,
	{"CMPB.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_Rt,
	{"CMPH.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_U8,
	{"CMPH.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_Rt,
	{"CMPH.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_S8,
	{"CMPH.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_Rt,
	{"CMPH.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_U7,
	{"CMPH.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_Rt,
	{"CMP.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMP_EQ_Pd_Rss_Rtt,
	{"CMP.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMP_GT_Pd_Rss_Rtt,
	{"CMP.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_CMP_GTU_Pd_Rss_Rtt,
	{"BITSCLR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_U6,
	{"BITSCLR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_Rt,
	{"BITSSET", CF_CHG1}
	,			// Hexa_XTYPE_PRED_BITSSET_Pd_Rs_Rt,
	{"MASK", CF_CHG1}
	,			// Hexa_XTYPE_PRED_MASK_Rdd_Pt,
	{"TLBMATCH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_TLBMATCH_Pd_Rss_Rt,
	{"", CF_CHG1}
	,			// Hexa_XTYPE_PRED_transfertPred_Rd_Pt,
	{"", CF_CHG1}
	,			// Hexa_XTYPE_PRED_transfertPred_Pt_Rd,
	{"TSTBIT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_U5,
	{"TSTBIT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_Rt,
	{"VCMPB.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_U8,
	{"VCMPB.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_Rtt,
	{"VCMPB.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_S8,
	{"VCMPB.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_Rtt,
	{"VCMPB.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_U7,
	{"VCMPB.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_Rtt,
	{"VCMPH.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_U8,
	{"VCMPH.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_Rtt,
	{"VCMPH.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_S8,
	{"VCMPH.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_Rtt,
	{"VCMPH.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_U7,
	{"VCMPH.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_Rtt,
	{"VCMPW.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_U8,
	{"VCMPW.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_Rtt,
	{"VCMPW.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_S8,
	{"VCMPW.GT", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_Rtt,
	{"VCMPW.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_U7,
	{"VCMPW.GTU", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_Rtt,
	{"ANY8(VCMPB.EQ", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ANY8_VCMPB_EQ_Pd_Rss_Rtt,
	{"VITPACK", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VITPACK_Rd_Ps_Pt,
	{"VMUX", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VMUX_Rd_Pu_Rss_Rtt,

	// XTYPE-SHIFT
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_Rdd_Rs_U5,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rdd_Rs_U5,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_Rdd_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_Rdd_Rss_U6,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_Rdd_Rss_U6,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ADD_Rx_U8_ASL_Rx_U5,
	{"ADD", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ADD_Rx_U8_LSR_Rx_U5,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_PRED_SUB_Rx_U8_ASL_Rx_U5,
	{"SUB", CF_CHG1}
	,			// Hexa_XTYPE_PRED_SUB_Rx_U8_LSR_Rx_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_pluseq_Rx_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_lesseq_Rx_Rs_U5,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_pluseq_Rx_Rs_U5,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_lesseq_Rx_Rs_U5,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_pluseq_Rx_Rs_U5,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_lesseq_Rx_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_pluseq_Rxx_Rss_U6,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_lesseq_Rxx_Rss_U6,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_pluseq_Rxx_Rss_U6,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_lesseq_Rxx_Rss_U6,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_pluseq_Rxx_Rss_U6,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_lesseq_Rxx_Rss_U6,
	{"ADDASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ADDAS_Rdd_Rss_Rtt_U3,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_PRED_AND_Rx_U8_ASL_Rx_U5,
	{"AND", CF_CHG1}
	,			// Hexa_XTYPE_PRED_AND_Rx_U8_LSR_Rx_U5,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_OR_Rx_U8_ASL_Rx_U5,
	{"OR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_OR_Rx_U8_LSR_Rx_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_andeq_Rx_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_oreq_Rx_Rs_U5,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_andeq_Rx_Rs_U5,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_oreq_Rx_Rs_U5,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_andeq_Rx_Rs_U5,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_oreq_Rx_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_andeq_Rxx_Rss_U6,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_oreq_Rxx_Rss_U6,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_andeq_Rxx_Rss_U6,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_oreq_Rxx_Rss_U6,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_andeq_Rxx_Rss_U6,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_oreq_Rxx_Rss_U6,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_xoreq_Rdd_Rs_U5,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_xoreq_Rdd_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_xoreq_Rxx_Rss_U6,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_xoreq_Rxx_Rss_U6,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rd_Rs_U5,
	{"ASRRND", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASRRND_Rd_Rs_U5,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6,
	{"ASRRND", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASRRND_Rdd_Rss_U6,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_Rd_Rs_U5,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_Rdd_Rs_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rdd_Rs_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_Rdd_S6_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_Rdd_Rs_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_Rdd_Rs_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_Rdd_Rss_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rdd_Rss_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_Rdd_Rss_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_Rdd_Rss_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_pluseq_Rdd_Rs_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_lesseq_Rdd_Rs_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_pluseq_Rdd_Rs_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_lesseq_Rdd_Rs_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_pluseq_Rdd_Rs_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_lesseq_Rdd_Rs_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_pluseq_Rdd_Rs_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_lesseq_Rdd_Rs_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_pluseq_Rdd_Rss_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_lesseq_Rdd_Rss_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_pluseq_Rdd_Rss_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_lesseq_Rdd_Rss_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_pluseq_Rdd_Rss_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_lesseq_Rdd_Rss_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_pluseq_Rdd_Rss_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_lesseq_Rdd_Rss_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_andeq_Rdd_Rs_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_oreq_Rdd_Rs_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_andeq_Rdd_Rs_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_oreq_Rdd_Rs_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_andeq_Rdd_Rs_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_oreq_Rdd_Rs_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_andeq_Rdd_Rs_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_oreq_Rdd_Rs_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_andeq_Rdd_Rss_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_oreq_Rdd_Rss_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_andeq_Rdd_Rss_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_oreq_Rdd_Rss_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_andeq_Rdd_Rss_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_oreq_Rdd_Rss_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_andeq_Rdd_Rss_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_oreq_Rdd_Rss_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_xoreq_Rdd_Rss_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_xoreq_Rdd_Rss_Rt,
	{"LSL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSL_xoreq_Rdd_Rss_Rt,
	{"LSR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_LSR_xoreq_Rdd_Rss_Rt,
	{"ASL", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt,
	{"ASR", CF_CHG1}
	,			// Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt,
	{"VASLH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASLH_Rdd_Rss_U4,
	{"VASRH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRH_Rdd_Rss_U4,
	{"VLSRH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_U4,
	{"VASRHUB", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRHUB_Rdd_Rss_U4,
	{"VASLH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASLH_Rdd_Rss_Rt,
	{"VASRH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRH_Rdd_Rss_Rt,
	{"VLSLH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VLSLH_Rdd_Rss_Rt,
	{"VLSRH", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_Rt,
	{"VASLW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASLW_Rdd_Rss_U5,
	{"VASRW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRW_Rdd_Rss_U5,
	{"VLSRW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_U5,
	{"VASLW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASLW_Rdd_Rss_Rt,
	{"VASRW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRW_Rdd_Rss_Rt,
	{"VLSLW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VLSLW_Rdd_Rss_Rt,
	{"VLSRW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_Rt,
	{"VASRW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRW_Rd_Rss_U5,
	{"VASRW", CF_CHG1}
	,			// Hexa_XTYPE_PRED_VASRW_Rd_Rss_Rt,

	// NV
	{"CMP_EQ", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_EQ_Ns_R92,
	{"CMP_EQ", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_EQ_Ns_U5_R92,
	{"CMP_EQ", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_EQ_Ns_Rt_R92,
	{"CMP_GT", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GT_Ns_R92,
	{"CMP_GT", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GT_Ns_U5_R92,
	{"CMP_GT", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GT_Ns_Rt_R92,
	{"CMP_GT", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GT_Rt_Ns_R92,
	{"CMP_GTU", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GTU_Ns_U5_R92,
	{"CMP_GTU", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GTU_Ns_Rs_R92,
	{"CMP_GTU", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_GTU_Rs_Ns_R92,
	{"TSTBIT", CF_CHG1}
	,			// Hexa_NV_C_JUMP_CMP_TSTBIT_Ns_R92,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Re_U6_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rs_S112_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rs_Ru_U2_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Ru_U2_U6_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rx_S42_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rx_S42_circ_Mu_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rx_circ_Mu_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rx_Mu_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_Rx_Mu_brev_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_MEMW_GP_U162_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_C_MEMW_U6_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_C_MEMW_Rs_U62_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_C_MEMW_Rs_Ru_U2_Nt,
	{"MEMW", CF_CHG1}
	,			// Hexa_NV_C_MEMW_Rx_S42_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Re_U6_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rs_S111_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rs_Ru_U2_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Ru_U2_U6_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rx_S41_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rx_S41_circ_Mu_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rx_circ_Mu_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rx_Mu_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_Rx_Mu_brev_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_MEMH_GP_U161_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_C_MEMH_U6_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_C_MEMH_Rs_U61_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_C_MEMH_Rs_Ru_U2_Nt,
	{"MEMH", CF_CHG1}
	,			// Hexa_NV_C_MEMH_Rx_S41_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Re_U6_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rs_S110_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rs_Ru_U2_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Ru_U2_U6_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rx_S40_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rx_S40_circ_Mu_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rx_circ_Mu_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rx_Mu_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_Rx_Mu_brev_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_MEMB_GP_U160_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_C_MEMB_U6_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_C_MEMB_Rs_U60_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_C_MEMB_Rs_Ru_U2_Nt,
	{"MEMB", CF_CHG1}
	,			// Hexa_NV_C_MEMB_Rx_S40_Nt,

	{"nada", CF_CHG1}
	,			// Hexa_CONST_EXT,
	{"nada_bis", CF_CHG1}
	,			// Hexa_DUPLEX,
};

//#ifdef __INSTRS_HPP
CASSERT(qnumber(Instructions) == Hexa_last);
//#endif
