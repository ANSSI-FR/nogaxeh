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

#include "emu.hpp"

int idaapi emu(void)
{
	// jump and function call
	switch (cmd.itype) {

		// straight call
	case Hexa_J_JR_CALL_R222:
		Context::getInstance().addCall(cmd.ea + cmd.Operands[0].addr);
		break;

		// conditionnal call
	case Hexa_J_JR_C_CALL_Pu_R152:
		Context::getInstance().addCall(cmd.ea + cmd.Operands[1].addr);
		break;

		// straight jump
	case Hexa_J_JR_JUMP_R222:
		Context::getInstance().addJump(cmd.ea + cmd.Operands[0].addr);
		Context::getInstance().stopFlow();
		break;

	case Hexa_J_JR_Transfer_Rd_U6_JUMP_R92:
	case Hexa_J_JR_Transfer_Rd_Rs_JUMP_R92:
		Context::getInstance().addJump(cmd.ea + cmd.Operands[2].addr);
		Context::getInstance().stopFlow();
		break;

		// conditionnal jump
	case Hexa_J_JR_C_differ_Rs_JUMP_R132:
	case Hexa_J_JR_C_lower_Rs_JUMP_R132:
	case Hexa_J_JR_C_equal_Rs_JUMP_R132:
	case Hexa_J_JR_C_greater_Rs_JUMP_R132:
	case Hexa_J_JR_C_JUMP_Pu_R152:
		Context::getInstance().addJump(cmd.ea + cmd.Operands[1].addr);
		break;

	case Hexa_J_JR_CMP_EQ_Pd_Rs_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_C_JUMP_R92:
	case Hexa_J_JR_TSTBIT_Pd_Rs_C_JUMP_R92:
		Context::getInstance().addJump(cmd.ea + cmd.Operands[2].addr);
		break;

	case Hexa_J_JR_CMP_EQ_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_EQ_Pd_Rs_Rt_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_Rt_C_JUMP_R92:
	case Hexa_J_JR_CMP_GTU_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_GTU_Pd_Rs_Rt_C_JUMP_R92:
		Context::getInstance().addJump(cmd.ea + cmd.Operands[3].addr);
		break;

		// return
	case Hexa_LD_DEALLOC_RETURN:
		Context::getInstance().stopFlow();
		break;
	case Hexa_J_JR_JUMPR_Rs:	// special case (jump R31)
		if (cmd.Operands[0].reg == 31) {
			Context::getInstance().stopFlow();
		}
		break;
	}

	// if packet end: apply jumps, optionally go to next packet
	if ((cmd.segpref & 0x02) == 2) {
		Context::getInstance().endPacket();
		if (!Context::getInstance().getAndResetFlowEnd()) {
			ua_add_cref(0, cmd.ea + cmd.size, fl_F);
		}
	} else {
		ua_add_cref(0, cmd.ea + cmd.size, fl_F);
	}

	return 1;
}
