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

#include "out.hpp"

void idaapi out(void)
{
	uint32 instr;
	get_many_bytes(cmd.ea, &instr, 4);

	char buf[MAXSTR];
	init_output_buffer(buf, sizeof(buf));

	if ((cmd.segpref & 0x03) == 1) {
		OutLine("{  ");
	}
	uint16 id = cmd.itype;
	switch (id) {
		// 4 operands
		// IF (O0) 01 = XYZ (O2,O3)
	case Hexa_ALU32_C_ADD_Pu_Rd_Rs_S8:
	case Hexa_ALU32_C_ADD_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_COMBINE_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_AND_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_OR_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_XOR_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_SUB_Pu_Rd_Rs_Rt:
		out_snprintf("if (");
		out_one_operand(0);
		out_snprintf(") ");
		out_one_operand(1);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(2);
		out_symbol(',');
		out_one_operand(3);
		out_symbol(')');
		break;

		// IF (O0) 01 = XYZ (O2)
	case Hexa_ALU32_C_ASLH_Pu_Rd_Rs:
	case Hexa_ALU32_C_ASRH_Pu_Rd_Rs:
	case Hexa_ALU32_C_SXTB_Pu_Rd_Rs:
	case Hexa_ALU32_C_SXTH_Pu_Rd_Rs:
	case Hexa_ALU32_C_ZXTB_Pu_Rd_Rs:
	case Hexa_ALU32_C_ZXTH_Pu_Rd_Rs:
		out_snprintf("if (");
		out_one_operand(0);
		out_snprintf(") ");
		out_one_operand(1);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(2);
		out_symbol(')');
		break;

		// IF (O0) 01 = O2
	case Hexa_ALU32_C_TransferImm_Pu_Rd_S12:
		out_snprintf("if (");
		out_one_operand(0);
		out_snprintf(") ");
		out_one_operand(1);
		out_symbol('=');
		out_one_operand(2);
		break;

		// O0 = XYZ (O1,O2,O3)
	case Hexa_ALU32_MUX_Rd_Pu_S8_S8:
	case Hexa_ALU32_MUX_Rd_Pu_S8_Rs:
	case Hexa_ALU32_MUX_Rd_Pu_Rs_S8:
	case Hexa_ALU32_MUX_Rd_Pu_Rs_Rt:
	case Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_U6_U6:
	case Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_U6_U6:
	case Hexa_XTYPE_BIT_INSERT_Rdd_Rss_U6_U6:
	case Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_U5_U5:
	case Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_U5_U5:
	case Hexa_XTYPE_BIT_INSERT_Rd_Rs_U5_U5:
	case Hexa_XTYPE_BIT_TABLEIDXD_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_BIT_TABLEIDXW_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_BIT_TABLEIDXH_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_BIT_TABLEIDXB_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_COMPLEX_VRCROTATE_Rdd_Rss_Rt_U2:
	case Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_Pu:
	case Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_Pu:
	case Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_U3:
	case Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_U3:
	case Hexa_XTYPE_PRED_VMUX_Rd_Pu_Rss_Rtt:
	case Hexa_XTYPE_PRED_ADDASL_Rd_Rs_Rt_U3:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(',');
		out_one_operand(3);
		out_symbol(')');
		break;

		// O0 += XYZ (O1,O2,O3)
	case Hexa_XTYPE_COMPLEX_pluseq_VRCROTATE_Rdd_Rss_Rt_U2:
		out_one_operand(0);
		out_symbol('+');
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(',');
		out_one_operand(3);
		out_symbol(')');
		break;

		// O0 = XYZ (O1, AND(O2,O3))
	case Hexa_CR_AND_Pd_Ps_AND_Pt_Pu:
	case Hexa_CR_OR_Pd_Ps_AND_Pt_Pu:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",AND(");
		out_one_operand(2);
		out_symbol(',');
		out_one_operand(3);
		OutLine("))");
		break;

		// O0 = XYZ (O1, OR(O2,O3))
	case Hexa_CR_AND_Pd_Ps_OR_Pt_Pu:
	case Hexa_CR_OR_Pd_Ps_OR_Pt_Pu:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",OR(");
		out_one_operand(2);
		out_symbol(',');
		out_one_operand(3);
		OutLine("))");
		break;

		// O0 = XYZ(O1,O2); if (O0.new) JUMP O3
	case Hexa_J_JR_CMP_EQ_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_GTU_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_EQ_Pd_Rs_Rt_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_Rt_C_JUMP_R92:
	case Hexa_J_JR_CMP_GTU_Pd_Rs_Rt_C_JUMP_R92:
		if ((cmd.segpref & 0x03) == 3) {
			OutLine("{ ");
		}
		out_snprintf("P%d", cmd.Operands[0].reg);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		OutLine("); if (");
		out_one_operand(0);
		OutLine(") JUMP");
		if ((cmd.auxpref & 0x03) == 1) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x03) == 2) {
			OutLine(":nt ");
		}
		out_one_operand(3);
		if ((cmd.segpref & 0x03) == 3) {
			OutLine(" }");
		}
		break;

		// O0 = XYZ (O1,ADD(O2,O3))
	case Hexa_XTYPE_ALU_ADD_Rd_Rs_ADD_Ru_S6:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(", ADD(");
		out_one_operand(2);
		OutLine(",");
		out_one_operand(3);
		OutLine("))");
		break;

		// O0 = XYZ (O1,SUB(O2,O3))
	case Hexa_XTYPE_ALU_ADD_Rd_Rs_SUB_S6_Ru:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(", SUB(");
		out_one_operand(2);
		OutLine(",");
		out_one_operand(3);
		OutLine("))");
		break;

		// O0,O1 = XYZ (O2,O3)
	case Hexa_XTYPE_ALU_VACSH_Rxx_Pe_Rss_Rtt:
	case Hexa_XTYPE_FP_SFRECIPA_Rd_Pe_Rs_Rt:
		out_one_operand(0);
		OutLine(",");
		out_one_operand(1);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(2);
		OutLine(",");
		out_one_operand(3);
		OutLine(")");
		break;

		// O0 += XYZ (O1,O2,O3)
	case Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_Pu_scale:
		out_one_operand(0);
		OutLine("+=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine(",");
		out_one_operand(3);
		OutLine("):scale");
		break;

		// O0 = XYZ (O1,O2,O3):carry
	case Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt_Px_carry:
	case Hexa_XTYPE_ALU_SUB_Rdd_Rss_Rtt_Px_carry:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine(",");
		out_one_operand(3);
		OutLine("):carry");
		break;

		// O0 = XYZ (O1,MPY(O2,O3))
	case Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_U6:
	case Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_Rt:
	case Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_U62_Rs:
	case Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_Rs_U6:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",MPYI(");
		out_one_operand(2);
		OutLine(",");
		out_one_operand(3);
		OutLine("))");
		break;

		// O0 = XYZ (O1,MPY(O0,O2))
	case Hexa_XTYPE_MPY_ADD_Ry_Ru_MPYI_Ry_Rt:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",MPYI(");
		out_one_operand(0);
		OutLine(",");
		out_one_operand(2);
		OutLine("))");
		break;

		// 3 operands
		// O0 = XYZ (O1,O2)
	case Hexa_ALU32_ADD_Rd_Rs_s16:
	case Hexa_ALU32_ADD_Rd_Rs_Rt:
	case Hexa_ALU32_AND_Rd_Rs_Rt:
	case Hexa_ALU32_OR_Rd_Rs_Rt:
	case Hexa_ALU32_XOR_Rd_Rs_Rt:
	case Hexa_ALU32_SUB_Rd_Rt_Rs:
	case Hexa_ALU32_VADDH_Rd_Rs_Rt:
	case Hexa_ALU32_VAVGH_Rd_Rs_Rt:
	case Hexa_ALU32_VNAVGH_Rd_Rs_Rt:
	case Hexa_ALU32_VSUBH_Rd_Rs_Rt:
	case Hexa_ALU32_AND_Rd_Rs_s10:
	case Hexa_ALU32_OR_Rd_Rs_s10:
	case Hexa_ALU32_SUB_Rd_s10_Rs:
	case Hexa_ALU32_COMBINE_Rdd_S8_S8:
	case Hexa_ALU32_COMBINE_Rdd_S8_U6:
	case Hexa_ALU32_COMBINE_Rdd_S8_Rs:
	case Hexa_ALU32_COMBINE_Rdd_Rs_S8:
	case Hexa_ALU32_COMBINE_Rdd_Rs_Rt:
	case Hexa_ALU32_PACKHL_Rd_Rs_Rt:
	case Hexa_ALU32_CMP_eq_Pu_Rs_S10:
	case Hexa_ALU32_not_CMP_eq_Pu_Rs_S10:
	case Hexa_ALU32_CMP_eq_Pu_Rs_Rt:
	case Hexa_ALU32_not_CMP_eq_Pu_Rs_Rt:
	case Hexa_ALU32_CMP_gt_Pu_Rs_S10:
	case Hexa_ALU32_not_CMP_gt_Pu_Rs_S10:
	case Hexa_ALU32_CMP_gt_Pu_Rs_Rt:
	case Hexa_ALU32_not_CMP_gt_Pu_Rs_Rt:
	case Hexa_ALU32_CMP_gtu_Pu_Rs_U9:
	case Hexa_ALU32_not_CMP_gtu_Pu_Rs_U9:
	case Hexa_ALU32_CMP_gtu_Pu_Rs_Rt:
	case Hexa_ALU32_not_CMP_gtu_Pu_Rs_Rt:
	case Hexa_ALU32_CMP_eq_Rd_Rs_S8:
	case Hexa_ALU32_not_CMP_eq_Rd_Rs_S8:
	case Hexa_ALU32_CMP_eq_Rd_Rs_Rt:
	case Hexa_ALU32_not_CMP_eq_Rd_Rs_Rt:
	case Hexa_CR_FASTCORNER9_Pd_Ps_Pt:
	case Hexa_CR_not_FASTCORNER9_Pd_Ps_Pt:
	case Hexa_CR_AND_Pd_Pt_Ps:
	case Hexa_CR_OR_Pd_Pt_Ps:
	case Hexa_CR_XOR_Pd_Ps_Pt:
	case Hexa_XTYPE_ALU_ADD_Rd_Rs_Rt_sat_deprecated:
	case Hexa_XTYPE_ALU_MAX_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MAXU_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MIN_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MINU_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MODWRAP_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_CROUND_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_ROUND_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_ADDh_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_SUBh_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_AND_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_OR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_XOR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MAX_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MAXU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MIN_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MINU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_SUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VADDB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDUH_Rdd_Rss_Rtt_sat:
	case Hexa_XTYPE_ALU_VADDW_Rdd_Rss_Rtt_sat:
	case Hexa_XTYPE_ALU_VRADDUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VNAVGH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGUW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VNAVGW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VRSADUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VABSDIFFH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VABSDIFFW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXUH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXUW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINUH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINUW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VSUBUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VSUBH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VSUBUH_Rdd_Rtt_Rss_sat:
	case Hexa_XTYPE_ALU_VSUBW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VRADDH_Rd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDHUB_Rd_Rss_Rtt_sat:
	case Hexa_XTYPE_ALU_VCNEGH_Rdd_Rss_Rt:
	case Hexa_XTYPE_ALU_VRMAXH_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMAXUH_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMAXW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMAXUW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMINH_Rdd_Rss_Ru:
	case Hexa_XTYPE_ALU_VRMINUH_Rdd_Rss_Ru:
	case Hexa_XTYPE_ALU_VRMINW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMINUW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_SUB_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_CROUND_Rd_Rs_U5:
	case Hexa_XTYPE_ALU_ROUND_Rd_Rs_U5:
	case Hexa_XTYPE_ALU_VRADDUH_Rd_Rss_Rtt:
	case Hexa_XTYPE_BIT_PARITY_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_SETBIT_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_Rt:
	case Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_INSERT_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_LFS_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_PARITY_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_Rtt:
	case Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_Rtt:
	case Hexa_XTYPE_BIT_INSERT_Rd_Rs_Rtt:
	case Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_U5:
	case Hexa_XTYPE_BIT_SETBIT_Rd_Rs_U5:
	case Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_U5:
	case Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_U5:
	case Hexa_XTYPE_COMPLEX_VXADDSUBH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXSUBADDH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXADDSUBW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXSUBADDW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VCROTATE_Rdd_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYI_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYR_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rt:
	case Hexa_XTYPE_FP_SFADD_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFFIXUPD_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFFIXUPN_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFMAX_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFMIN_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFSUB_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_DFCLASS_Pd_Rss_U5:
	case Hexa_XTYPE_FP_SFCLASS_Pd_Rs_U5:
	case Hexa_XTYPE_FP_SFCMPEQ_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPGE_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPGT_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPUO_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_DFCMPEQ_Pd_Rss_Rtt:
	case Hexa_XTYPE_FP_DFCMPGE_Pd_Rss_Rtt:
	case Hexa_XTYPE_FP_DFCMPGT_Pd_Rss_Rtt:
	case Hexa_XTYPE_FP_DFCMPUO_Pd_Rss_Rtt:
	case Hexa_XTYPE_MPY_MPYI_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYUh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYur_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYSU_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYU_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYH_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VDMPY_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYBU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VDMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_MPYUh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_PMPYW_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYH_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYHSU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYBSU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYBU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VPMPYH_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYh_Rdd_Rs_Rt:
	case Hexa_XTYPE_PERM_DECBIN_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_SHUFFEB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_SHUFFEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_VTRUNEWH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_VTRUNOWH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_SHUFFOB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_PERM_SHUFFOH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_VITPACK_Rd_Ps_Pt:
	case Hexa_XTYPE_PRED_BOUNDSCHECK_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_CMP_EQ_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_CMP_GT_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_CMP_GTU_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_Rtt:
	case Hexa_XTYPE_PRED_TLBMATCH_Pd_Rss_Rt:
	case Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_S8:
	case Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_S8:
	case Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_S8:
	case Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_S8:
	case Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_S8:
	case Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_U8:
	case Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_U8:
	case Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_U8:
	case Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_U8:
	case Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_U8:
	case Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_U7:
	case Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_U7:
	case Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_U7:
	case Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_U7:
	case Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_U7:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt_sat:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt_sat:
	case Hexa_XTYPE_PRED_ASL_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASLH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASRH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSLH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASLW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASRW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSLW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASRW_Rd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_Rd_S6_Rt:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_U5_rnd:
	case Hexa_XTYPE_PRED_ASRRND_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_U5_sat:
	case Hexa_XTYPE_PRED_ASL_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6_rnd:
	case Hexa_XTYPE_PRED_ASRRND_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_VASLW_Rdd_Rss_U5:
	case Hexa_XTYPE_PRED_VASRW_Rdd_Rss_U5:
	case Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_U5:
	case Hexa_XTYPE_PRED_VASRW_Rd_Rss_U5:
	case Hexa_XTYPE_PRED_VASLH_Rdd_Rss_U4:
	case Hexa_XTYPE_PRED_VASRH_Rdd_Rss_U4:
	case Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_U4:
	case Hexa_XTYPE_PRED_VASRHUB_Rdd_Rss_U4:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_ALU_AND_Rdd_Rtt_n_Rss:
	case Hexa_XTYPE_ALU_OR_Rdd_Rtt_n_Rss:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",~");
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_ALU_OR_Rx_Ru_AND_Rx_S10:
		out_one_operand(1);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine(", AND(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine("))");
		break;
	case Hexa_XTYPE_BIT_ADD_Rd_CLB_Rs_S6:
	case Hexa_XTYPE_BIT_ADD_Rd_CLB_Rss_S6:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("),");
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rtet:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine("*)");
		break;
	case Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_lib:
		out_one_operand(0);
		OutLine("+=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine("):lib");
		break;
	case Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt_lib:
		out_one_operand(0);
		OutLine("-=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine("):lib");
		break;
	case Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_U6:
	case Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_U5:
	case Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_BITSSET_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_Rt:
		out_one_operand(0);
		OutLine("=");
		if (cmd.insnpref & 0x01) {
			OutLine("!");
		}
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine(")");
		break;

	case Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_S8:
	case Hexa_XTYPE_ALU_pluseq_SUB_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_pluseq_VRCNEGH_Rxx_Rss_Rt:
	case Hexa_XTYPE_ALU_pluseq_VRADDUB_Rxx_Rss_Rtt:
	case Hexa_XTYPE_ALU_pluseg_VRSADUB_Rxx_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_VCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPYI_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPYR_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rt:
	case Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_VDMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYBU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VDMPY_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_MPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYUh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_MPYh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYUh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYEH_pluseq_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYH_pluseq_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYHSU_pluseq_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_VMPYBSU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_VMPYBU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_U8:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rxx_Rss_U6:
		out_one_operand(0);
		OutLine("+=");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rtet:
		out_one_operand(0);
		OutLine("+=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine("*)");
		break;

	case Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_S8:
	case Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYI_Rd_Rs_U8:
	case Hexa_XTYPE_MPY_lesseq_MPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYUh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYUh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPY_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rxx_Rss_U6:
		out_one_operand(0);
		OutLine("-=");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rtet:
		out_one_operand(0);
		OutLine("-=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",");
		out_one_operand(2);
		OutLine("*)");
		break;

	case Hexa_XTYPE_MPY_eqplus_MPYI_Rd_Rs_U8:
		out_one_operand(0);
		OutLine("=+");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_MPY_eqless_MPYI_Rd_Rs_U8:
		out_one_operand(0);
		OutLine("=-");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;

	case Hexa_XTYPE_ALU_andeq_AND_Rs_Rt:
	case Hexa_XTYPE_ALU_andeq_OR_Rs_Rt:
	case Hexa_XTYPE_ALU_andeq_XOR_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_andeq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_andeq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_andeq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_andeq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_andeq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_andeq_Rxx_Rss_U6:
		out_one_operand(0);
		OutLine("&=");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_ALU_andeq_AND_Rs_n_Rt:
		out_one_operand(0);
		OutLine("&=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",~");
		out_one_operand(2);
		out_symbol(')');
		break;

	case Hexa_XTYPE_ALU_oreq_AND_Rs_Rt:
	case Hexa_XTYPE_ALU_oreq_AND_Rs_S10:
	case Hexa_XTYPE_ALU_oreq_OR_Rs_S10:
	case Hexa_XTYPE_ALU_oreq_OR_Rs_Rt:
	case Hexa_XTYPE_ALU_oreq_XOR_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_oreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_oreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_oreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_oreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_oreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_oreq_Rxx_Rss_U6:
		out_one_operand(0);
		OutLine("|=");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_ALU_oreq_AND_Rs_n_Rt:
		out_one_operand(0);
		OutLine("|=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",~");
		out_one_operand(2);
		out_symbol(')');
		break;

	case Hexa_XTYPE_ALU_xoreq_OR_Rs_Rt:
	case Hexa_XTYPE_ALU_xoreq_XOR_Rs_Rt:
	case Hexa_XTYPE_ALU_xoreq_XOR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_xoreq_AND_Rs_Rt:
	case Hexa_XTYPE_MPY_xoreq_PMPYW_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_xoreq_VPMPYH_Rdd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_xoreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_xoreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_xoreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_xoreq_Rxx_Rss_U6:
		out_one_operand(0);
		OutLine("^=");
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		break;
	case Hexa_XTYPE_ALU_xoreq_AND_Rs_n_Rt:
		out_one_operand(0);
		OutLine("^=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",~");
		out_one_operand(2);
		out_symbol(')');
		break;

		// O0 = XYZ (O1,O2) :sat
	case Hexa_ALU32_ADDsat_Rd_Rs_Rt:
	case Hexa_ALU32_SUBsat_Rd_Rt_Rs:
	case Hexa_ALU32_VADDHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VADDUHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VSUBHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VSUBUHsat_Rd_Rs_Rt:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		OutLine("):sat");
		break;

		// O0 = XYZ (O1,O2) :rnd
	case Hexa_ALU32_VAVGHrnd_Rd_Rs_Rt:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		OutLine("):rnd");
		break;

		// O0 = XYZ (O1,~O2)
	case Hexa_ALU32_ANDnot_Rd_Rt_Rs:
	case Hexa_ALU32_ORnot_Rd_Rs_Rt:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_symbol('~');
		out_one_operand(2);
		out_symbol(')');
		break;

		// O0 = XYZ (O1.H,O2.H)
	case Hexa_ALU32_COMBINE_Rd_RsH_RtH:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(".H,");
		out_one_operand(2);
		OutLine(".H)");
		break;

		// O0 = XYZ (O1.L,O2.H)
	case Hexa_ALU32_COMBINE_Rd_RsL_RtH:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(".L,");
		out_one_operand(2);
		OutLine(".H)");
		break;

		// O0 = XYZ (O1.H,O2.L)
	case Hexa_ALU32_COMBINE_Rd_RsH_RtL:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(".H,");
		out_one_operand(2);
		OutLine(".L)");
		break;

		// O0 = XYZ (O1.L,O2.L)
	case Hexa_ALU32_COMBINE_Rd_RsL_RtL:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(".L,");
		out_one_operand(2);
		OutLine(".L)");
		break;

		// O0 = XYZ(O1,#-1); if (O0.new) JUMP O2
	case Hexa_J_JR_CMP_EQ_Pd_Rs_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_C_JUMP_R92:
		if ((cmd.segpref & 0x03) == 3) {
			OutLine("{ ");
		}
		out_snprintf("P%d", cmd.Operands[0].reg);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",#-1); if (");
		out_one_operand(0);
		OutLine(") JUMP");
		if ((cmd.auxpref & 0x03) == 1) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x03) == 2) {
			OutLine(":nt ");
		}
		out_one_operand(2);
		if ((cmd.segpref & 0x03) == 3) {
			OutLine(" }");
		}
		break;

		// O0 = XYZ(O1,#0); if (O0.new) JUMP O2
	case Hexa_J_JR_TSTBIT_Pd_Rs_C_JUMP_R92:
		if ((cmd.segpref & 0x03) == 3) {
			OutLine("{ ");
		}
		out_snprintf("P%d", cmd.Operands[0].reg);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(",#0); if (");
		out_one_operand(0);
		OutLine(") JUMP");
		if ((cmd.auxpref & 0x03) == 1) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x03) == 2) {
			OutLine(":nt ");
		}
		out_one_operand(2);
		if ((cmd.segpref & 0x03) == 3) {
			OutLine(" }");
		}
		break;

		// R = U6; JUMP R9:2
	case Hexa_J_JR_Transfer_Rd_U6_JUMP_R92:
	case Hexa_J_JR_Transfer_Rd_Rs_JUMP_R92:
		out_one_operand(0);
		OutLine("=");
		out_one_operand(1);
		OutLine(";");
		OutMnem(1, "");
		out_one_operand(2);
		break;

		// XYZ (O0,O1)=O2
	case Hexa_SYSTEM_MEMD_LOCKED_Rs_Pd_Rtt:
	case Hexa_SYSTEM_MEMW_LOCKED_Rs_Pd_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		out_symbol(',');
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

		// O0,O1 = XYZ (O2)
	case Hexa_XTYPE_FP_SFINVSQRTA_Rd_Pe_Rs:
		out_one_operand(0);
		out_symbol(',');
		out_one_operand(1);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(2);
		OutLine(")");
		break;

		// O0 = XX(X (O1,02))
	case Hexa_XTYPE_PRED_ANY8_VCMPB_EQ_Pd_Rss_Rtt:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(',');
		out_one_operand(2);
		out_symbol(')');
		out_symbol(')');
		break;

	case Hexa_XTYPE_PRED_ADD_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_SUB_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_AND_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_OR_Rx_U8_ASL_Rx_U5:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(" ,ASL(");
		out_one_operand(0);
		out_symbol(',');
		out_one_operand(2);
		OutLine("))");
		break;

	case Hexa_XTYPE_PRED_ADD_Rx_U8_LSR_Rx_U5:
	case Hexa_XTYPE_PRED_SUB_Rx_U8_LSR_Rx_U5:
	case Hexa_XTYPE_PRED_AND_Rx_U8_LSR_Rx_U5:
	case Hexa_XTYPE_PRED_OR_Rx_U8_LSR_Rx_U5:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(" ,LSR(");
		out_one_operand(0);
		out_symbol(',');
		out_one_operand(2);
		OutLine("))");
		break;

		// 2 operands
		// O0 = XYZ (O1)
	case Hexa_ALU32_SXTB_Rd_Rs:
	case Hexa_ALU32_SXTH_Rd_Rs:
	case Hexa_ALU32_ZXTH_Rd_Rs:
	case Hexa_ALU32_ASLH_Rd_Rs:
	case Hexa_ALU32_ASRH_Rd_Rs:
	case Hexa_CR_ALL8_Pd_Ps:
	case Hexa_CR_ANY8_Pd_Ps:
	case Hexa_CR_NOT_Pd_Ps:
	case Hexa_SYSTEM_MEMW_LOCKED_Rd_Rs:
	case Hexa_SYSTEM_MEMD_LOCKED_Rdd_Rs:
	case Hexa_XTYPE_ALU_ABS_Rd_Rs:
	case Hexa_XTYPE_ALU_NEG_Rd_Rs_sat:
	case Hexa_XTYPE_ALU_NEG_Rdd_Rss:
	case Hexa_XTYPE_ALU_SXTW_Rdd_Rs:
	case Hexa_XTYPE_ALU_ROUND_Rdd_Rss_sat:
	case Hexa_XTYPE_ALU_ABS_Rdd_Rss:
	case Hexa_XTYPE_ALU_NOT_Rdd_Rss:
	case Hexa_XTYPE_ALU_VABSH_Rdd_Rss:
	case Hexa_XTYPE_ALU_VABSW_Rdd_Rss:
	case Hexa_XTYPE_BIT_CL0_Rd_Rs:
	case Hexa_XTYPE_BIT_CL1_Rd_Rs:
	case Hexa_XTYPE_BIT_CLB_Rd_Rs:
	case Hexa_XTYPE_BIT_NORMAMT_Rd_Rs:
	case Hexa_XTYPE_BIT_CT0_Rd_Rs:
	case Hexa_XTYPE_BIT_CT1_Rd_Rs:
	case Hexa_XTYPE_BIT_CL0_Rd_Rss:
	case Hexa_XTYPE_BIT_CL1_Rd_Rss:
	case Hexa_XTYPE_BIT_CLB_Rd_Rss:
	case Hexa_XTYPE_BIT_NORMAMT_Rd_Rss:
	case Hexa_XTYPE_BIT_POPCOUNT_Rd_Rss:
	case Hexa_XTYPE_BIT_CT0_Rd_Rss:
	case Hexa_XTYPE_BIT_CT1_Rd_Rss:
	case Hexa_XTYPE_BIT_DEINTERLEAVE_Rdd_Rss:
	case Hexa_XTYPE_BIT_INTERLEAVE_Rdd_Rss:
	case Hexa_XTYPE_BIT_BREV_Rdd_Rss:
	case Hexa_XTYPE_BIT_BREV_Rd_Rs:
	case Hexa_XTYPE_COMPLEX_VCONJ_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_W2SF_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_UW2SF_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2UW_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2W_Rd_Rs:
	case Hexa_XTYPE_FP_SFFIXUPR_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2DF_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_W2DF_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_UW2DF_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2UD_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2D_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_DF2SF_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_D2SF_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_UD2SF_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2UW_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2W_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_D2DF_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_UD2DF_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2UD_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2D_Rdd_Rss:
	case Hexa_XTYPE_PERM_SATB_Rd_Rs:
	case Hexa_XTYPE_PERM_SATH_Rd_Rs:
	case Hexa_XTYPE_PERM_SATUB_Rd_Rs:
	case Hexa_XTYPE_PERM_SATUH_Rd_Rs:
	case Hexa_XTYPE_PERM_SWIZ_Rd_Rs:
	case Hexa_XTYPE_PERM_VSATHB_Rd_Rs:
	case Hexa_XTYPE_PERM_VSATHUB_Rd_Rs:
	case Hexa_XTYPE_PERM_VSPLATB_Rd_Rs:
	case Hexa_XTYPE_PERM_VRNDWH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VSPLATH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VSXTBH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VSXTHW_Rdd_Rs:
	case Hexa_XTYPE_PERM_VZXTBH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VZXTHW_Rdd_Rs:
	case Hexa_XTYPE_PERM_SAT_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATHB_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATHUB_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATWH_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATWUH_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATHB_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATHUB_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATWH_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATWUH_Rdd_Rss:
	case Hexa_XTYPE_PERM_VTRUNOHB_Rd_Rss:
	case Hexa_XTYPE_PERM_VTRUNEHB_Rd_Rss:
	case Hexa_XTYPE_PRED_MASK_Rdd_Pt:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		out_symbol(')');
		break;
	case Hexa_XTYPE_FP_SFMAKE_Rd_U10_neg:
	case Hexa_XTYPE_FP_DFMAKE_Rdd_U10_neg:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("):neg");
		break;
	case Hexa_XTYPE_FP_DFMAKE_Rdd_U10_pos:
	case Hexa_XTYPE_FP_SFMAKE_Rd_U10_pos:
		out_one_operand(0);
		out_symbol('=');
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("):pos");
		break;

		// XYZ (O0,O1)
	case Hexa_CR_LOOP0_R72_U10:
	case Hexa_CR_LOOP0_R72_Rs:
	case Hexa_CR_LOOP1_R72_U10:
	case Hexa_CR_LOOP1_R72_Rs:
	case Hexa_SYSTEM_L2FETCH_Rs_Rt:
	case Hexa_SYSTEM_L2FETCH_Rs_Rtt:
		OutMnem(1, "(");
		out_one_operand(0);
		out_symbol(',');
		out_one_operand(1);
		out_symbol(')');
		break;

		// O0 = O1
	case Hexa_ALU32_TransferImm_Rd_s16:
	case Hexa_ALU32_TransferReg_Rd_Rs:
	case Hexa_CR_TransferPred_Pd_Ps:
	case Hexa_CR_TransferPred_Cd_Rs:
	case Hexa_CR_TransferPred_Cdd_Rss:
	case Hexa_CR_TransferPred_Rd_Cs:
	case Hexa_CR_TransferPred_Rdd_Css:
	case Hexa_XTYPE_PRED_transfertPred_Rd_Pt:
	case Hexa_XTYPE_PRED_transfertPred_Pt_Rd:
		out_one_operand(0);
		OutLine("=");
		out_one_operand(1);
		break;

		// O0.H = O1
	case Hexa_ALU32_TransferImmHigh_Rd_u16:
		out_one_operand(0);
		OutLine(".H=");
		out_one_operand(1);
		break;

		// O0.L = O1
	case Hexa_ALU32_TransferImmLow_Rd_u16:
		out_one_operand(0);
		OutLine(".L=");
		out_one_operand(1);
		break;

		// P3 = XYZ(O0,O1)
	case Hexa_CR_SP1LOOP0_P3_R72_U10:
	case Hexa_CR_SP1LOOP0_P3_R72_Rs:
	case Hexa_CR_SP2LOOP0_P3_R72_U10:
	case Hexa_CR_SP2LOOP0_P3_R72_Rs:
	case Hexa_CR_SP3LOOP0_P3_R72_U10:
	case Hexa_CR_SP3LOOP0_P3_R72_Rs:
		OutLine("P3=");
		OutMnem(1, "(");
		out_one_operand(0);
		out_symbol(',');
		out_one_operand(1);
		out_symbol(')');
		break;

		// O0 = ADD(PC,O1)
	case Hexa_CR_ADD_Rd_Pc_U6:
		out_one_operand(0);
		OutLine("=ADD(PC,");
		out_one_operand(1);
		out_symbol(')');
		break;

		// IF O0 XYZ O1
	case Hexa_J_JR_C_CALLR_Pu_Rs:
	case Hexa_J_JR_C_JUMPR_Pu_Rs:
	case Hexa_J_JR_C_CALL_Pu_R152:
	case Hexa_J_JR_C_JUMP_Pu_R152:
		OutLine("IF (");
		out_one_operand(0);
		out_symbol(')');
		OutMnem(1, "");
		if ((cmd.auxpref & 0x03) == 1) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x03) == 2) {
			OutLine(":nt ");
		}
		out_one_operand(1);
		break;

		// IF (O0 XYZ) JUMP O1
	case Hexa_J_JR_C_differ_Rs_JUMP_R132:
	case Hexa_J_JR_C_lower_Rs_JUMP_R132:
	case Hexa_J_JR_C_equal_Rs_JUMP_R132:
	case Hexa_J_JR_C_greater_Rs_JUMP_R132:
		OutLine("if (");
		out_one_operand(0);
		OutMnem(1, ")");
		OutLine("  JUMP");
		if ((cmd.auxpref & 0x03) == 1) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x03) == 2) {
			OutLine(":nt ");
		}
		out_one_operand(1);
		break;

		// XYZ(O0+O1)
	case Hexa_SYSTEM_DCFETCH_Rs_U113:
		OutMnem(1, "(");
		out_one_operand(0);
		out_symbol('+');
		out_one_operand(1);
		out_symbol(')');
		break;

		// 1 operand
		// XYZ O0
	case Hexa_J_JR_CALLR_Rs:
	case Hexa_J_JR_JUMPR_Rs:
	case Hexa_J_JR_CALL_R222:
	case Hexa_J_JR_JUMP_R222:
		OutMnem(1, "");
		out_one_operand(0);
		break;

		// XYZ(O0)
	case Hexa_J_JR_HINTJ_Rs:
	case Hexa_ST_ALLOCFRAME_U113:
	case Hexa_SYSTEM_DCZEROA_Rs:
	case Hexa_SYSTEM_TRACE_Rs:
	case Hexa_SYSTEM_TRAP0_U8:
	case Hexa_SYSTEM_TRAP1_U8:
	case Hexa_SYSTEM_PAUSE_U8:
	case Hexa_SYSTEM_DCCLEANA_Rs:
	case Hexa_SYSTEM_DCCLEANINVA_Rs:
	case Hexa_SYSTEM_DCINVA_Rs:
	case Hexa_SYSTEM_ICINVA_Rs:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine(")");
		break;

		// IF (O0) XYZ{:t/:nt}
	case Hexa_LD_C_DEALLOC_RETURN_Ps:
		OutLine("if (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem();
		if ((cmd.auxpref & 0x03) == 1) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x03) == 2) {
			OutLine(":nt ");
		}
		break;

		// 0 operand
		// XYZ 
	case Hexa_ALU32_NOP:
	case Hexa_LD_DEALLOCFRAME:
	case Hexa_LD_DEALLOC_RETURN:
	case Hexa_SYSTEM_BARRIER:
	case Hexa_SYSTEM_BRKPT:
	case Hexa_SYSTEM_ISYNC:
	case Hexa_SYSTEM_SYNCHT:
		OutMnem();
		break;

		// LD
		// R = XYZ (R+R<<U2)
	case Hexa_LD_MEMD_Rdd_Rs_Rt_U2:
	case Hexa_LD_MEMW_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMH_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMB_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMUH_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMUB_Rd_Rs_Rt_U2:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine("<<");
		out_one_operand(3);
		out_symbol(')');
		break;

		// R=XYZ(GP+U16:X)
	case Hexa_LD_MEMB_Rd_GP_U160:
	case Hexa_LD_MEMUB_Rd_GP_U160:
	case Hexa_LD_MEMH_Rd_GP_U161:
	case Hexa_LD_MEMUH_Rd_GP_U161:
	case Hexa_LD_MEMW_Rd_GP_U162:
	case Hexa_LD_MEMD_Rdd_GP_U163:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(GP+");
		out_one_operand(1);
		out_symbol(')');
		break;

		// R=XYZ(R+S11:X)
	case Hexa_LD_MEMB_Rd_Rs_S110:
	case Hexa_LD_MEMUB_Rd_Rs_S110:
	case Hexa_LD_MEMH_Rd_Rs_S111:
	case Hexa_LD_MEMUH_Rd_Rs_S111:
	case Hexa_LD_MEMW_Rd_Rs_S112:
	case Hexa_LD_MEMD_Rdd_Rs_S113:
	case Hexa_LD_MEMH_FIFO_Ryy_Rs_S111:
	case Hexa_LD_MEMB_FIFO_Ryy_Rs_S110:
	case Hexa_LD_MEMBH_Rd_Rs_S111:
	case Hexa_LD_MEMUBH_Rd_Rs_S111:
	case Hexa_LD_MEMBH_Rdd_Rs_S112:
	case Hexa_LD_MEMUBH_Rdd_Rs_S112:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		out_symbol(')');
		break;

		// R=XYZ(R++S4:X:circ(MU))
	case Hexa_LD_MEMB_Rd_Rx_S40_circ_Mu:
	case Hexa_LD_MEMUB_Rd_Rx_S40_circ_Mu:
	case Hexa_LD_MEMH_Rd_Rx_S41_circ_Mu:
	case Hexa_LD_MEMUH_Rd_Rx_S41_circ_Mu:
	case Hexa_LD_MEMW_Rd_Rx_S42_circ_Mu:
	case Hexa_LD_MEMD_Rdd_Rx_S43_circ_Mu:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_S41_circ_Mu:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_S40_circ_Mu:
	case Hexa_LD_MEMBH_Rd_Rx_S41_circ_Mu:
	case Hexa_LD_MEMUBH_Rd_Rx_S41_circ_Mu:
	case Hexa_LD_MEMBH_Rdd_Rx_S42_circ_Mu:
	case Hexa_LD_MEMUBH_Rdd_Rx_S42_circ_Mu:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++");
		out_one_operand(2);
		OutLine(":circ(");
		out_one_operand(3);
		OutLine("))");
		break;

		// R=XYZ(R++I:circ(MU))
	case Hexa_LD_MEMB_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMUB_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMH_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMUH_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMW_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMD_Rdd_Rx_circ_Mu:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_circ_Mu:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_circ_Mu:
	case Hexa_LD_MEMBH_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMUBH_Rd_Rx_circ_Mu:
	case Hexa_LD_MEMBH_Rdd_Rx_circ_Mu:
	case Hexa_LD_MEMUBH_Rdd_Rx_circ_Mu:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++I:circ(");
		out_one_operand(2);
		OutLine("))");
		break;

		// R=XYZ(R=U6)
	case Hexa_LD_MEMB_Rd_Re_U6:
	case Hexa_LD_MEMUB_Rd_Re_U6:
	case Hexa_LD_MEMH_Rd_Re_U6:
	case Hexa_LD_MEMUH_Rd_Re_U6:
	case Hexa_LD_MEMW_Rd_Re_U6:
	case Hexa_LD_MEMD_Rdd_Re_U6:
	case Hexa_LD_MEMH_FIFO_Ryy_Re_U6:
	case Hexa_LD_MEMB_FIFO_Ryy_Re_U6:
	case Hexa_LD_MEMBH_Rd_Re_U6:
	case Hexa_LD_MEMUBH_Rd_Re_U6:
	case Hexa_LD_MEMBH_Rdd_Re_U6:
	case Hexa_LD_MEMUBH_Rdd_Re_U6:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("=");
		out_one_operand(2);
		out_symbol(')');
		break;

		// R=XYZ(R++S4:X)
	case Hexa_LD_MEMB_Rd_Rx_S40:
	case Hexa_LD_MEMUB_Rd_Rx_S40:
	case Hexa_LD_MEMH_Rd_Rx_S41:
	case Hexa_LD_MEMUH_Rd_Rx_S41:
	case Hexa_LD_MEMW_Rd_Rx_S42:
	case Hexa_LD_MEMD_Rdd_Rx_S43:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_S41:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_S40:
	case Hexa_LD_MEMBH_Rd_Rx_S41:
	case Hexa_LD_MEMUBH_Rd_Rx_S41:
	case Hexa_LD_MEMBH_Rdd_Rx_S42:
	case Hexa_LD_MEMUBH_Rdd_Rx_S42:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++");
		out_one_operand(2);
		out_symbol(')');
		break;

		// R=XYZ(R<<U2+U6)
	case Hexa_LD_MEMD_Rdd_Rt_U2_U6:
	case Hexa_LD_MEMW_Rd_Rt_U2_U6:
	case Hexa_LD_MEMH_Rd_Rt_U2_U6:
	case Hexa_LD_MEMUH_Rd_Rt_U2_U6:
	case Hexa_LD_MEMB_Rd_Rt_U2_U6:
	case Hexa_LD_MEMUB_Rd_Rt_U2_U6:
	case Hexa_LD_MEMH_FIFO_Ryy_Rt_U2_U6:
	case Hexa_LD_MEMB_FIFO_Ryy_Rt_U2_U6:
	case Hexa_LD_MEMBH_Rd_Rt_U2_U6:
	case Hexa_LD_MEMUBH_Rd_Rt_U2_U6:
	case Hexa_LD_MEMBH_Rdd_Rt_U2_U6:
	case Hexa_LD_MEMUBH_Rdd_Rt_U2_U6:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("<<");
		out_one_operand(2);
		OutLine("+");
		out_one_operand(3);
		out_symbol(')');
		break;

		// R=XYZ(R++Mu)
	case Hexa_LD_MEMD_Rdd_Rx_Mu:
	case Hexa_LD_MEMW_Rd_Rx_Mu:
	case Hexa_LD_MEMH_Rd_Rx_Mu:
	case Hexa_LD_MEMUH_Rd_Rx_Mu:
	case Hexa_LD_MEMB_Rd_Rx_Mu:
	case Hexa_LD_MEMUB_Rd_Rx_Mu:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu:
	case Hexa_LD_MEMBH_Rd_Rx_Mu:
	case Hexa_LD_MEMUBH_Rd_Rx_Mu:
	case Hexa_LD_MEMBH_Rdd_Rx_Mu:
	case Hexa_LD_MEMUBH_Rdd_Rx_Mu:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++");
		out_one_operand(2);
		out_symbol(')');
		break;

		// R=XYZ(R++Mu:brev)
	case Hexa_LD_MEMD_Rdd_Rx_Mu_brev:
	case Hexa_LD_MEMW_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMUH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMB_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMUB_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu_brev:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu_brev:
	case Hexa_LD_MEMBH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMUBH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMBH_Rdd_Rx_Mu_brev:
	case Hexa_LD_MEMUBH_Rdd_Rx_Mu_brev:
		out_one_operand(0);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++");
		out_one_operand(2);
		OutLine(":brev)");
		break;

		// IF (P) R=XYZ(U6)
	case Hexa_LD_C_MEMD_Rdd_U6:
	case Hexa_LD_C_MEMW_Rd_U6:
	case Hexa_LD_C_MEMH_Rd_U6:
	case Hexa_LD_C_MEMUH_Rd_U6:
	case Hexa_LD_C_MEMB_Rd_U6:
	case Hexa_LD_C_MEMUB_Rd_U6:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		out_one_operand(1);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(2);
		out_symbol(')');
		break;

		// IF (P) R=XYZ(R+U6:X)
	case Hexa_LD_C_MEMD_Rdd_Rs_U63:
	case Hexa_LD_C_MEMW_Rd_Rs_U62:
	case Hexa_LD_C_MEMH_Rd_Rs_U61:
	case Hexa_LD_C_MEMUH_Rd_Rs_U61:
	case Hexa_LD_C_MEMB_Rd_Rs_U60:
	case Hexa_LD_C_MEMUB_Rd_Rs_U60:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		out_one_operand(1);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(2);
		OutLine("+");
		out_one_operand(3);
		out_symbol(')');
		break;

		// IF (P) R=XYZ(R++S4:X)
	case Hexa_LD_C_MEMD_Rdd_Rx_S43:
	case Hexa_LD_C_MEMW_Rd_Rx_S42:
	case Hexa_LD_C_MEMH_Rd_Rx_S41:
	case Hexa_LD_C_MEMUH_Rd_Rx_S41:
	case Hexa_LD_C_MEMB_Rd_Rx_S40:
	case Hexa_LD_C_MEMUB_Rd_Rx_S40:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		out_one_operand(1);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(2);
		OutLine("++");
		out_one_operand(3);
		out_symbol(')');
		break;

		// IF (P) R=XYZ (R+X<<U2)
	case Hexa_LD_C_MEMD_Rdd_Rs_Rt_U2:
	case Hexa_LD_C_MEMW_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMH_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMB_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMUH_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMUB_Rd_Rs_Rt_U2:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		out_one_operand(1);
		OutLine("=");
		OutMnem(1, "(");
		out_one_operand(2);
		OutLine("+");
		out_one_operand(3);
		OutLine("<<");
		out_one_operand(4);
		out_symbol(')');
		break;

		// XYZ(R+U6X)=CLRBIT(U5)
	case Hexa_MEMOP_MEMB_Rs_U60_CLRBIT_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_CLRBIT_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_CLRBIT_U5:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")=CLRBIT(");
		out_one_operand(2);
		OutLine(")");
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_SETBIT_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_SETBIT_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_SETBIT_U5:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")=SETBIT(");
		out_one_operand(2);
		OutLine(")");
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_plus_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_plus_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_plus_U5:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")+=");
		out_one_operand(2);
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_less_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_less_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_less_U5:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")-=");
		out_one_operand(2);
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_plus_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_plus_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_plus_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")+=");
		out_one_operand(2);
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_less_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_less_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_less_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")-=");
		out_one_operand(2);
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_or_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_or_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_or_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")|=");
		out_one_operand(2);
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_and_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_and_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_and_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")&=");
		out_one_operand(2);
		break;

		// XYZ (R+R<<U2)=R
	case Hexa_ST_MEMD_Rs_Ru_U2_Rtt:
	case Hexa_ST_MEMW_Rs_Ru_U2_Rt:
	case Hexa_ST_MEMH_Rs_Ru_U2_Rt:
	case Hexa_ST_MEMB_Rs_Ru_U2_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine("<<");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		break;

		// XYZ(R+U6:X)=S8
	case Hexa_ST_MEMW_Rs_U62_S8:
	case Hexa_ST_MEMH_Rs_U61_S8:
	case Hexa_ST_MEMB_Rs_U60_S8:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

		// XYZ(GP+U16:X)=R
	case Hexa_ST_MEMD_GP_U163_Rtt:
	case Hexa_ST_MEMW_GP_U162_Rt:
	case Hexa_ST_MEMH_GP_U161_Rt:
	case Hexa_ST_MEMB_GP_U160_Rt:
		OutMnem(1, "(GP+");
		out_one_operand(0);
		OutLine(")=");
		out_one_operand(1);
		break;

		// XYZ(R+S11:X)=R
	case Hexa_ST_MEMD_Rs_S113_Rtt:
	case Hexa_ST_MEMW_Rs_S112_Rt:
	case Hexa_ST_MEMH_Rs_S111_Rt:
	case Hexa_ST_MEMB_Rs_S110_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

		// XYZ(R++I:circ(Mu))=R
	case Hexa_ST_MEMD_Rx_circ_Mu_Rtt:
	case Hexa_ST_MEMW_Rx_circ_Mu_Rt:
	case Hexa_ST_MEMH_Rx_circ_Mu_Rt:
	case Hexa_ST_MEMB_Rx_circ_Mu_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++I:circ(");
		out_one_operand(1);
		OutLine("))=");
		out_one_operand(2);
		break;

		// XYZ(R++S4:X:circ(Mu))=R
	case Hexa_ST_MEMD_Rx_S43_circ_Mu_Rtt:
	case Hexa_ST_MEMW_Rx_S42_circ_Mu_Rt:
	case Hexa_ST_MEMH_Rx_S41_circ_Mu_Rt:
	case Hexa_ST_MEMB_Rx_S40_circ_Mu_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(":circ(");
		out_one_operand(2);
		OutLine("))=");
		out_one_operand(3);
		break;

		// XYZ(R=U6)=R
	case Hexa_ST_MEMD_Re_U6_Rtt:
	case Hexa_ST_MEMW_Re_U6_Rt:
	case Hexa_ST_MEMH_Re_U6_Rt:
	case Hexa_ST_MEMB_Re_U6_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("=");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

		// XYZ(R++S4:X)=R
	case Hexa_ST_MEMD_Rx_S43_Rtt:
	case Hexa_ST_MEMW_Rx_S42_Rt:
	case Hexa_ST_MEMH_Rx_S41_Rt:
	case Hexa_ST_MEMB_Rx_S40_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

		// XYZ(R<<U2+U6)=R
	case Hexa_ST_MEMD_Ru_U2_U6_Rtt:
	case Hexa_ST_MEMW_Ru_U2_U6_Rt:
	case Hexa_ST_MEMH_Ru_U2_U6_Rt:
	case Hexa_ST_MEMB_Ru_U2_U6_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("<<");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		break;

		// XYZ(R++Mu)=R
	case Hexa_ST_MEMD_Rx_Mu_Rtt:
	case Hexa_ST_MEMW_Rx_Mu_Rt:
	case Hexa_ST_MEMH_Rx_Mu_Rt:
	case Hexa_ST_MEMB_Rx_Mu_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

		// XYZ(R++Mu:brev)=R
	case Hexa_ST_MEMD_Rx_Mu_brev_Rtt:
	case Hexa_ST_MEMW_Rx_Mu_brev_Rt:
	case Hexa_ST_MEMH_Rx_Mu_brev_Rt:
	case Hexa_ST_MEMB_Rx_Mu_brev_Rt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(":brev)=");
		out_one_operand(2);
		break;

		// IF (P) XYZ (R+R<<U2)=R
	case Hexa_ST_C_MEMD_Rs_Rt_U2_Rtt:
	case Hexa_ST_C_MEMW_Rs_Rt_U2_Rt:
	case Hexa_ST_C_MEMH_Rs_Rt_U2_Rt:
	case Hexa_ST_C_MEMB_Rs_Rt_U2_Rt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine("<<");
		out_one_operand(3);
		OutLine(")=");
		out_one_operand(4);
		break;

		// IF (P) XYZ (R+U6:X)=S6
	case Hexa_ST_C_MEMW_Rs_U62_S6:
	case Hexa_ST_C_MEMH_Rs_U61_S6:
	case Hexa_ST_C_MEMB_Rs_U60_S6:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		break;

		// IF (P) XYZ(R+U6:X)=R
	case Hexa_ST_C_MEMD_Rs_U63_Rtt:
	case Hexa_ST_C_MEMW_Rs_U62_Rt:
	case Hexa_ST_C_MEMH_Rs_U61_Rt:
	case Hexa_ST_C_MEMB_Rs_U60_Rt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		break;

		// IF (P) XYZ(R++S4:X)=R
	case Hexa_ST_C_MEMD_Rx_S43_Rtt:
	case Hexa_ST_C_MEMW_Rx_S42_Rt:
	case Hexa_ST_C_MEMH_Rx_S41_Rt:
	case Hexa_ST_C_MEMB_Rx_S40_Rt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		break;

		// IF (P) XYZ(U6)=R
	case Hexa_ST_C_MEMD_U6_Rtt:
	case Hexa_ST_C_MEMW_U6_Rt:
	case Hexa_ST_C_MEMH_U6_Rt:
	case Hexa_ST_C_MEMB_U6_Rt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		break;

	case Hexa_CONST_EXT:
		OutLine("// Constant extended (## next instruction) + ");
		out_one_operand(0);
		break;

	case Hexa_DUPLEX:
		OutLine("// Duplex not done yet");
		break;

	case Hexa_NV_MEMB_Rs_Ru_U2_Nt:
	case Hexa_NV_MEMH_Rs_Ru_U2_Nt:
	case Hexa_NV_MEMW_Rs_Ru_U2_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine("<<");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_GP_U160_Nt:
	case Hexa_NV_MEMH_GP_U161_Nt:
	case Hexa_NV_MEMW_GP_U162_Nt:
		OutMnem(1, "(GP+");
		out_one_operand(0);
		OutLine(")=");
		out_one_operand(1);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Rs_S110_Nt:
	case Hexa_NV_MEMH_Rs_S111_Nt:
	case Hexa_NV_MEMW_Rs_S112_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("+");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Rx_circ_Mu_Nt:
	case Hexa_NV_MEMH_Rx_circ_Mu_Nt:
	case Hexa_NV_MEMW_Rx_circ_Mu_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine(":circ(");
		out_one_operand(1);
		OutLine("))=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Rx_S40_circ_Mu_Nt:
	case Hexa_NV_MEMH_Rx_S41_circ_Mu_Nt:
	case Hexa_NV_MEMW_Rx_S42_circ_Mu_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(":circ(");
		out_one_operand(2);
		OutLine("))=");
		out_one_operand(3);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Re_U6_Nt:
	case Hexa_NV_MEMH_Re_U6_Nt:
	case Hexa_NV_MEMW_Re_U6_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("=");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Rx_S40_Nt:
	case Hexa_NV_MEMH_Rx_S41_Nt:
	case Hexa_NV_MEMW_Rx_S42_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Ru_U2_U6_Nt:
	case Hexa_NV_MEMH_Ru_U2_U6_Nt:
	case Hexa_NV_MEMW_Ru_U2_U6_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("<<");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Rx_Mu_Nt:
	case Hexa_NV_MEMH_Rx_Mu_Nt:
	case Hexa_NV_MEMW_Rx_Mu_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_MEMB_Rx_Mu_brev_Nt:
	case Hexa_NV_MEMH_Rx_Mu_brev_Nt:
	case Hexa_NV_MEMW_Rx_Mu_brev_Nt:
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine("++");
		out_one_operand(1);
		OutLine(":brew)=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_C_MEMB_Rs_Ru_U2_Nt:
	case Hexa_NV_C_MEMH_Rs_Ru_U2_Nt:
	case Hexa_NV_C_MEMW_Rs_Ru_U2_Nt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine("<<");
		out_one_operand(3);
		OutLine(")=");
		out_one_operand(4);
		OutLine(".new");
		break;

	case Hexa_NV_C_MEMB_Rs_U60_Nt:
	case Hexa_NV_C_MEMH_Rs_U61_Nt:
	case Hexa_NV_C_MEMW_Rs_U62_Nt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("+");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		OutLine(".new");
		break;

	case Hexa_NV_C_MEMB_Rx_S40_Nt:
	case Hexa_NV_C_MEMH_Rx_S41_Nt:
	case Hexa_NV_C_MEMW_Rx_S42_Nt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine("++");
		out_one_operand(2);
		OutLine(")=");
		out_one_operand(3);
		OutLine(".new");
		break;

	case Hexa_NV_C_MEMB_U6_Nt:
	case Hexa_NV_C_MEMH_U6_Nt:
	case Hexa_NV_C_MEMW_U6_Nt:
		OutLine("IF (");
		out_one_operand(0);
		OutLine(") ");
		OutMnem(1, "(");
		out_one_operand(1);
		OutLine(")=");
		out_one_operand(2);
		OutLine(".new");
		break;

	case Hexa_NV_C_JUMP_CMP_EQ_Ns_R92:
	case Hexa_NV_C_JUMP_CMP_GT_Ns_R92:
	case Hexa_NV_C_JUMP_CMP_TSTBIT_Ns_R92:
		OutLine("IF (");
		if ((cmd.auxpref & 0x0004) != 0) {
			OutLine("!");
		}
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine(".new,#-1");
		OutLine("))= JUMP");
		if ((cmd.auxpref & 0x0001) != 0) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x0002) != 0) {
			OutLine(":nt ");
		}
		out_one_operand(1);
		break;

	case Hexa_NV_C_JUMP_CMP_EQ_Ns_U5_R92:
	case Hexa_NV_C_JUMP_CMP_GT_Ns_U5_R92:
	case Hexa_NV_C_JUMP_CMP_GTU_Ns_U5_R92:
	case Hexa_NV_C_JUMP_CMP_EQ_Ns_Rt_R92:
	case Hexa_NV_C_JUMP_CMP_GT_Ns_Rt_R92:
	case Hexa_NV_C_JUMP_CMP_GTU_Ns_Rs_R92:
		OutLine("IF (");
		if ((cmd.auxpref & 0x0004) != 0) {
			OutLine("!");
		}
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine(".new,");
		out_one_operand(1);
		OutLine("))= JUMP");
		if ((cmd.auxpref & 0x0001) != 0) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x0002) != 0) {
			OutLine(":nt ");
		}
		out_one_operand(2);
		break;

	case Hexa_NV_C_JUMP_CMP_GT_Rt_Ns_R92:
	case Hexa_NV_C_JUMP_CMP_GTU_Rs_Ns_R92:
		OutLine("IF (");
		if ((cmd.auxpref & 0x0004) != 0) {
			OutLine("!");
		}
		OutMnem(1, "(");
		out_one_operand(0);
		OutLine(",");
		out_one_operand(1);
		OutLine(".new))= JUMP");
		if ((cmd.auxpref & 0x0001) != 0) {
			OutLine(":t ");
		}
		if ((cmd.auxpref & 0x0002) != 0) {
			OutLine(":nt ");
		}
		out_one_operand(2);
		break;

	default:
		OutLine("// Instruction not done yet");
		break;
	}

	if ((cmd.auxpref & 0x0400) != 0) {
		OutLine(":<<1");
	}
	if ((cmd.auxpref & 0x0010) != 0) {
		OutLine(":rnd");
	}
	if ((cmd.auxpref & 0x0020) != 0) {
		OutLine(":crnd");
	}
	if ((cmd.auxpref & 0x1000) != 0) {
		OutLine(":>>1");
	}
	if ((cmd.auxpref & 0x0008) != 0) {
		OutLine(":sat");
	}
	if ((cmd.auxpref & 0x0800) != 0) {
		OutLine(":<<16");
	}
	if ((cmd.auxpref & 0x2000) != 0) {
		OutLine(":deprecated");
	}
	if ((cmd.auxpref & 0x0040) != 0) {
		OutLine(":raw");
	}
	if ((cmd.auxpref & 0x0100) != 0) {
		OutLine(":hi");
	}
	if ((cmd.auxpref & 0x0200) != 0) {
		OutLine(":lo");
	}
	if ((cmd.auxpref & 0x0080) != 0) {
		OutLine(":chop");
	}

	if ((cmd.segpref & 0x03) == 2) {
		OutLine("  }");
		if ((cmd.segpref & 0x1C) == 4) {
			OutLine(":endloop0");
		}
		if ((cmd.segpref & 0x1C) == 8) {
			OutLine(":endloop1");
		}
		if ((cmd.segpref & 0x1C) == 16) {
			OutLine(":endloop0:endloop1");
		}
		OutLine(" ");
	}

	out_symbol(' ');
	term_output_buffer();
	MakeLine(buf, 0);
}

bool idaapi outop(op_t & op)
{
	uint16 reg = op.reg;
	switch (op.type) {
	case o_reg:
		if (op.specval & 0x01) {
			out_snprintf("R%d.H", op.reg);
		} else {
			if (op.specval & 0x02) {
				out_snprintf("R%d.L", op.reg);
			} else {
				out_snprintf("R%d", op.reg);
			}
		}
		break;

	case o_imm:
		if (op.specval & 0x01) {
			out_snprintf("##%d", op.value);
		} else {
			out_snprintf("#%d", op.value);
		}
		break;

	case o_near:
		if (op.specval & 0x01) {
			out_snprintf("##%d", op.addr);
		} else {
			char name[256];
			uint32 position = (cmd.segpref >> 8) && 0x03;
			size_t n =
			    get_name_expr(cmd.ea, op.n, cmd.ea + op.addr,
					  cmd.ea + op.addr, name, 256);
			if (n)
				out_snprintf("%s", name);
			else
				out_snprintf("#%d", op.addr);
		}
		break;

	case o_R64:
		out_snprintf("R%d:%d", op.reg + 1, op.reg);
		break;

	case o_CR:
		if (op.specval & 0x01) {
			out_snprintf("C%d:%d", op.reg + 1, op.reg);
		} else {
			if (op.specval & 0x02) {
				out_snprintf("M%d", op.reg);
			} else {
				out_snprintf("C%d", op.reg);
			}
		}
		break;

	case o_PR:
		switch (op.specval) {
		case 0x00:
			out_snprintf("P%d", op.reg);
			break;
		case 0x01:
			out_snprintf("!P%d", op.reg);
			break;
		case 0x02:
			out_snprintf("P%d.new", op.reg);
			break;
		case 0x03:
			out_snprintf("!P%d.new", op.reg);
			break;
		}
		break;

	case o_MR:
		out_snprintf("M%d", op.reg);
		break;

		// operand error
	default:
		out_line("op?", COLOR_REG);
		break;
	}
}

void idaapi header(void)
{
	gen_cmt_line("Processor       : %s", inf.procName);
	gen_cmt_line("Target assembler: %s", ash.name);
	gen_cmt_line("Byte sex        : %s", inf.mf ? "Big endian" : "Little endian");
	gen_cmt_line("Hexagon IDA Pro module (c) 2015 Thomas Cordier, 2015-2016 ANSSI");
}

void idaapi footer(void)
{
	gen_cmt_line("--- end ---");
}

void idaapi segstart(ea_t ea)
{
	gen_cmt_line("--- code segment start ---");
}

void idaapi segend(ea_t ea)
{
	gen_cmt_line("--- code segment end ---");
}
