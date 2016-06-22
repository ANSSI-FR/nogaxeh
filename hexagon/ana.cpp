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

#include "ana.hpp"

uint32 constantExtender = 1;
bool bNewValueAnalysis = false;

int idaapi ana(void)
{
	// detect packet start
	uint32 loopPacket = 0;
	uint32 precinstr = 0;
	uint32 precaddr = cmd.ea - 4;
	if (cmd.ea > 3) {
		get_many_bytes(precaddr, &precinstr, 4);
	}
	if ((((precinstr >> 14) & 0x03) == 0) | (((precinstr >> 14) & 0x03) ==
						 3)) {
		cmd.segpref |= 0x01;
	}

	// detect position of the instruction in the packet
	int position = 1;
	uint32 instr = 0;
	get_many_bytes(cmd.ea - 4 * position, &instr, 4);
	while ((position < 5) & (((instr >> 14) & 0x03) !=
				 0) & (((instr >> 14) & 0x03) != 3)) {
		position++;
		get_many_bytes(cmd.ea - 4 * position, &instr, 4);
	}
	position--;
	cmd.segpref |= (position << 5);

	instr = ua_next_long();
	uint32 parseBits = (instr >> 14) & 0x03;
	// detect end of packet
	switch (parseBits) {
	case 0x03:
		cmd.segpref |= 0x02;
		// detect loop
		loopPacket = parseBits;
		parseBits = (precinstr >> 14) & 0x03;
		while (parseBits != 0x03) {
			loopPacket = ((loopPacket << 2) | parseBits);
			precaddr -= 4;
			get_many_bytes(precaddr, &precinstr, 4);
			parseBits = (precinstr >> 14) & 0x03;
		}
		switch (loopPacket & 0x0F) {
		case 0x06:	// 10 01
		case 0x0E:	// 10 11
			addEndloop(0);
			break;
		case 0x09:	// 01 10
			addEndloop(1);
			break;
		case 0x0A:	// 10 10
			addEndloop(2);	// endloop 0&1
			break;
		}
	case 0x01:
	case 0x02:
		analyse_instruction(instr, &cmd);
		break;
	case 0x00:
		fill_struct(Hexa_DUPLEX, instr, &cmd);
		cmd.segpref |= 0x02;
		break;

	default:
		break;
	}

	return 4;
}

int analyse_instruction(uint32 instr, insn_t * instr_struct)
{
	switch ((instr >> 28) & 0x0F) {
	case 0x00:		// Constant extender
		fill_struct(Hexa_CONST_EXT, instr, instr_struct);
		break;

	case 0x01:		// Jump
		if ((instr >> 13) & 0x01) {
			instr_struct->auxpref = 1;
		} else {
			instr_struct->auxpref = 2;
		}
		switch ((instr >> 22) & 0x1F) {
		case 0x00:
		case 0x01:
		case 0x08:
		case 0x09:
			fill_struct(Hexa_J_JR_CMP_EQ_Pd_Rs_U5_C_JUMP_R92, instr,
				    instr_struct);
			break;
		case 0x02:
		case 0x03:
		case 0x0A:
		case 0x0B:
			fill_struct(Hexa_J_JR_CMP_GT_Pd_Rs_U5_C_JUMP_R92, instr,
				    instr_struct);
			break;
		case 0x04:
		case 0x05:
		case 0x0C:
		case 0x0D:
			fill_struct(Hexa_J_JR_CMP_GTU_Pd_Rs_U5_C_JUMP_R92,
				    instr, instr_struct);
			break;
		case 0x06:
		case 0x07:
		case 0x0E:
		case 0x0F:
			switch ((instr >> 8) & 0x03) {
			case 0x0:
				fill_struct(Hexa_J_JR_CMP_EQ_Pd_Rs_C_JUMP_R92,
					    instr, instr_struct);
				break;
			case 0x1:
				fill_struct(Hexa_J_JR_CMP_GT_Pd_Rs_C_JUMP_R92,
					    instr, instr_struct);
				break;
			case 0x3:
				fill_struct(Hexa_J_JR_TSTBIT_Pd_Rs_C_JUMP_R92,
					    instr, instr_struct);
				break;
			}
			break;
		case 0x10:
		case 0x11:
			fill_struct(Hexa_J_JR_CMP_EQ_Pd_Rs_Rt_C_JUMP_R92, instr,
				    instr_struct);
			break;
		case 0x12:
		case 0x13:
			fill_struct(Hexa_J_JR_CMP_GT_Pd_Rs_Rt_C_JUMP_R92, instr,
				    instr_struct);
			break;
		case 0x14:
		case 0x15:
			fill_struct(Hexa_J_JR_CMP_GTU_Pd_Rs_Rt_C_JUMP_R92,
				    instr, instr_struct);
			break;
		case 0x18:
		case 0x19:
		case 0x1A:
		case 0x1B:
			fill_struct(Hexa_J_JR_Transfer_Rd_U6_JUMP_R92, instr,
				    instr_struct);
			break;
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x1F:
			fill_struct(Hexa_J_JR_Transfer_Rd_Rs_JUMP_R92, instr,
				    instr_struct);
			break;
		}
		break;

	case 0x02:		// Jump
		switch ((instr >> 23) & 0x0F) {
		case 0x00:
			fill_struct(Hexa_NV_C_JUMP_CMP_EQ_Ns_Rt_R92, instr,
				    instr_struct);
			break;
		case 0x01:
			fill_struct(Hexa_NV_C_JUMP_CMP_GT_Ns_Rt_R92, instr,
				    instr_struct);
			break;
		case 0x02:
			fill_struct(Hexa_NV_C_JUMP_CMP_GTU_Ns_Rs_R92, instr,
				    instr_struct);
			break;
		case 0x03:
			fill_struct(Hexa_NV_C_JUMP_CMP_GT_Rt_Ns_R92, instr,
				    instr_struct);
			break;
		case 0x04:
			fill_struct(Hexa_NV_C_JUMP_CMP_GTU_Rs_Ns_R92, instr,
				    instr_struct);
			break;
		case 0x08:
			fill_struct(Hexa_NV_C_JUMP_CMP_EQ_Ns_U5_R92, instr,
				    instr_struct);
			break;
		case 0x09:
			fill_struct(Hexa_NV_C_JUMP_CMP_GT_Ns_U5_R92, instr,
				    instr_struct);
			break;
		case 0x0A:
			fill_struct(Hexa_NV_C_JUMP_CMP_GTU_Ns_U5_R92, instr,
				    instr_struct);
			break;
		case 0x0B:
			fill_struct(Hexa_NV_C_JUMP_CMP_TSTBIT_Ns_R92, instr,
				    instr_struct);
			break;
		case 0x0C:
			fill_struct(Hexa_NV_C_JUMP_CMP_EQ_Ns_R92, instr,
				    instr_struct);
			break;
		case 0x0D:
			fill_struct(Hexa_NV_C_JUMP_CMP_GT_Ns_R92, instr,
				    instr_struct);
			break;
		}
		break;

	case 0x03:		// Load/Store
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
		case 0x08:
		case 0x10:
		case 0x18:
			fill_struct(Hexa_LD_C_MEMB_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x01:
		case 0x09:
		case 0x11:
		case 0x19:
			fill_struct(Hexa_LD_C_MEMUB_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x02:
		case 0x0A:
		case 0x12:
		case 0x1A:
			fill_struct(Hexa_LD_C_MEMH_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x03:
		case 0x0B:
		case 0x13:
		case 0x1B:
			fill_struct(Hexa_LD_C_MEMUH_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x04:
		case 0x0C:
		case 0x14:
		case 0x1C:
			fill_struct(Hexa_LD_C_MEMW_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x06:
		case 0x0E:
		case 0x16:
		case 0x1E:
			fill_struct(Hexa_LD_C_MEMD_Rdd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x20:
		case 0x28:
		case 0x30:
		case 0x38:
			fill_struct(Hexa_ST_C_MEMB_Rs_Rt_U2_Rt, instr,
				    instr_struct);
			break;
		case 0x22:
		case 0x23:
		case 0x2A:
		case 0x2B:
		case 0x32:
		case 0x33:
		case 0x3A:
		case 0x3B:
			fill_struct(Hexa_ST_C_MEMH_Rs_Rt_U2_Rt, instr,
				    instr_struct);
			break;
		case 0x24:
		case 0x2C:
		case 0x34:
		case 0x3C:
			fill_struct(Hexa_ST_C_MEMW_Rs_Rt_U2_Rt, instr,
				    instr_struct);
			break;
		case 0x25:
		case 0x2D:
		case 0x35:
		case 0x3D:
			if (((instr >> 3) & 0x03) == 0) {
				fill_struct(Hexa_NV_C_MEMB_Rs_Ru_U2_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 3) & 0x03) == 1) {
				fill_struct(Hexa_NV_C_MEMH_Rs_Ru_U2_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 3) & 0x03) == 2) {
				fill_struct(Hexa_NV_C_MEMW_Rs_Ru_U2_Nt, instr,
					    instr_struct);
			}
			break;
		case 0x26:
		case 0x2E:
		case 0x36:
		case 0x3E:
			fill_struct(Hexa_ST_C_MEMD_Rs_Rt_U2_Rtt, instr,
				    instr_struct);
			break;
		case 0x40:
		case 0x44:
		case 0x48:
		case 0x4C:
			fill_struct(Hexa_ST_C_MEMB_Rs_U60_S6, instr,
				    instr_struct);
			break;
		case 0x41:
		case 0x45:
		case 0x49:
		case 0x4D:
			fill_struct(Hexa_ST_C_MEMH_Rs_U61_S6, instr,
				    instr_struct);
			break;
		case 0x42:
		case 0x46:
		case 0x4A:
		case 0x4E:
			fill_struct(Hexa_ST_C_MEMW_Rs_U62_S6, instr,
				    instr_struct);
			break;
		case 0x50:
			fill_struct(Hexa_LD_MEMB_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x51:
			fill_struct(Hexa_LD_MEMUB_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x52:
			fill_struct(Hexa_LD_MEMH_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x53:
			fill_struct(Hexa_LD_MEMUH_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x54:
			fill_struct(Hexa_LD_MEMW_Rd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x56:
			fill_struct(Hexa_LD_MEMD_Rdd_Rs_Rt_U2, instr,
				    instr_struct);
			break;
		case 0x58:
			fill_struct(Hexa_ST_MEMB_Rs_Ru_U2_Rt, instr,
				    instr_struct);
			break;
		case 0x5A:
		case 0x5B:
			fill_struct(Hexa_ST_MEMH_Rs_Ru_U2_Rt, instr,
				    instr_struct);
			break;
		case 0x5C:
			fill_struct(Hexa_ST_MEMW_Rs_Ru_U2_Rt, instr,
				    instr_struct);
			break;
		case 0x5D:
			if (((instr >> 3) & 0x03) == 0) {
				fill_struct(Hexa_NV_MEMB_Rs_Ru_U2_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 3) & 0x03) == 1) {
				fill_struct(Hexa_NV_MEMH_Rs_Ru_U2_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 3) & 0x03) == 2) {
				fill_struct(Hexa_NV_MEMW_Rs_Ru_U2_Nt, instr,
					    instr_struct);
			}
			break;
		case 0x5E:
			fill_struct(Hexa_ST_MEMD_Rs_Ru_U2_Rtt, instr,
				    instr_struct);
			break;
		case 0x60:
		case 0x64:
		case 0x68:
		case 0x6C:
			fill_struct(Hexa_ST_MEMB_Rs_U60_S8, instr,
				    instr_struct);
			break;
		case 0x61:
		case 0x65:
		case 0x69:
		case 0x6D:
			fill_struct(Hexa_ST_MEMH_Rs_U61_S8, instr,
				    instr_struct);
			break;
		case 0x62:
		case 0x66:
		case 0x6A:
		case 0x6E:
			fill_struct(Hexa_ST_MEMW_Rs_U62_S8, instr,
				    instr_struct);
			break;
		case 0x70:
		case 0x74:
			if (((instr >> 13) & 0x01) == 0) {
				switch ((instr >> 5) & 0x03) {
				case 0:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_plus_Rt,
					     instr, instr_struct);
					break;
				case 1:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_less_Rt,
					     instr, instr_struct);
					break;
				case 2:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_and_Rt,
					     instr, instr_struct);
					break;
				case 3:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_or_Rt,
					     instr, instr_struct);
					break;
				}
			}
			break;
		case 0x71:
		case 0x75:
			if (((instr >> 13) & 0x01) == 0) {
				switch ((instr >> 5) & 0x03) {
				case 0:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_plus_Rt,
					     instr, instr_struct);
					break;
				case 1:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_less_Rt,
					     instr, instr_struct);
					break;
				case 2:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_and_Rt,
					     instr, instr_struct);
					break;
				case 3:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_or_Rt,
					     instr, instr_struct);
					break;
				}
			}
			break;
		case 0x72:
		case 0x76:
			if (((instr >> 13) & 0x01) == 0) {
				switch ((instr >> 5) & 0x03) {
				case 0:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_plus_Rt,
					     instr, instr_struct);
					break;
				case 1:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_less_Rt,
					     instr, instr_struct);
					break;
				case 2:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_and_Rt,
					     instr, instr_struct);
					break;
				case 3:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_or_Rt,
					     instr, instr_struct);
					break;
				}
			}
			break;
		case 0x78:
		case 0x7C:
			if (((instr >> 13) & 0x01) == 0) {
				switch ((instr >> 5) & 0x03) {
				case 0:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_plus_U5,
					     instr, instr_struct);
					break;
				case 1:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_less_U5,
					     instr, instr_struct);
					break;
				case 2:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_CLRBIT_U5,
					     instr, instr_struct);
					break;
				case 3:
					fill_struct
					    (Hexa_MEMOP_MEMB_Rs_U60_SETBIT_U5,
					     instr, instr_struct);
					break;
				}
			}
			break;
		case 0x79:
		case 0x7D:
			if (((instr >> 13) & 0x01) == 0) {
				switch ((instr >> 5) & 0x03) {
				case 0:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_plus_U5,
					     instr, instr_struct);
					break;
				case 1:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_less_U5,
					     instr, instr_struct);
					break;
				case 2:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_CLRBIT_U5,
					     instr, instr_struct);
					break;
				case 3:
					fill_struct
					    (Hexa_MEMOP_MEMH_Rs_U61_SETBIT_U5,
					     instr, instr_struct);
					break;
				}
			}
			break;
		case 0x7A:
		case 0x7E:
			if (((instr >> 13) & 0x01) == 0) {
				switch ((instr >> 5) & 0x03) {
				case 0:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_plus_U5,
					     instr, instr_struct);
					break;
				case 1:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_less_U5,
					     instr, instr_struct);
					break;
				case 2:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_CLRBIT_U5,
					     instr, instr_struct);
					break;
				case 3:
					fill_struct
					    (Hexa_MEMOP_MEMW_Rs_U62_SETBIT_U5,
					     instr, instr_struct);
					break;
				}
			}
			break;
		}
		break;

	case 0x04:		// Load/Store
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
		case 0x10:
		case 0x20:
		case 0x30:
			if (((instr >> 2) & 0x01) == 0x00) {
				fill_struct(Hexa_ST_C_MEMB_Rs_U60_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x02:
		case 0x03:
		case 0x12:
		case 0x13:
		case 0x22:
		case 0x23:
		case 0x32:
		case 0x33:
			if (((instr >> 2) & 0x01) == 0x00) {
				fill_struct(Hexa_ST_C_MEMH_Rs_U61_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x04:
		case 0x14:
		case 0x24:
		case 0x34:
			if (((instr >> 2) & 0x01) == 0x00) {
				fill_struct(Hexa_ST_C_MEMW_Rs_U62_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x05:
		case 0x15:
		case 0x25:
		case 0x35:
			if (((instr >> 2) & 0x01) == 0x00) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct
					    (Hexa_NV_C_MEMB_Rs_U60_Nt,
					     instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct
					    (Hexa_NV_C_MEMH_Rs_U61_Nt,
					     instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct
					    (Hexa_NV_C_MEMW_Rs_U62_Nt,
					     instr, instr_struct);
				}
			}
			break;
		case 0x06:
		case 0x16:
		case 0x26:
		case 0x36:
			if (((instr >> 2) & 0x01) == 0x00) {
				fill_struct(Hexa_ST_C_MEMD_Rs_U63_Rtt, instr,
					    instr_struct);
			}
			break;
		case 0x08:
		case 0x18:
		case 0x28:
		case 0x38:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_LD_C_MEMB_Rd_Rs_U60, instr,
					    instr_struct);
			}
			break;
		case 0x09:
		case 0x19:
		case 0x29:
		case 0x39:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_LD_C_MEMUB_Rd_Rs_U60, instr,
					    instr_struct);
			}
			break;
		case 0x0A:
		case 0x1A:
		case 0x2A:
		case 0x3A:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_LD_C_MEMH_Rd_Rs_U61, instr,
					    instr_struct);
			}
			break;
		case 0x0B:
		case 0x1B:
		case 0x2B:
		case 0x3B:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_LD_C_MEMUH_Rd_Rs_U61, instr,
					    instr_struct);
			}
			break;
		case 0x0C:
		case 0x1C:
		case 0x2C:
		case 0x3C:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_LD_C_MEMW_Rd_Rs_U62, instr,
					    instr_struct);
			}
			break;
		case 0x0E:
		case 0x1E:
		case 0x2E:
		case 0x3E:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_LD_C_MEMD_Rdd_Rs_U63, instr,
					    instr_struct);
			}
			break;
		case 0x40:
		case 0x50:
		case 0x60:
		case 0x70:
			fill_struct(Hexa_ST_MEMB_GP_U160_Rt, instr,
				    instr_struct);
			break;
		case 0x42:
		case 0x43:
		case 0x52:
		case 0x53:
		case 0x62:
		case 0x63:
		case 0x72:
		case 0x73:
			fill_struct(Hexa_ST_MEMH_GP_U161_Rt, instr,
				    instr_struct);
			break;
		case 0x44:
		case 0x54:
		case 0x64:
		case 0x74:
			fill_struct(Hexa_ST_MEMW_GP_U162_Rt, instr,
				    instr_struct);
			break;
		case 0x45:
		case 0x55:
		case 0x65:
		case 0x75:
			if (((instr >> 11) & 0x03) == 0) {
				fill_struct(Hexa_NV_MEMB_GP_U160_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 11) & 0x03) == 1) {
				fill_struct(Hexa_NV_MEMH_GP_U161_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 11) & 0x03) == 2) {
				fill_struct(Hexa_NV_MEMW_GP_U162_Nt, instr,
					    instr_struct);
			}
			break;
		case 0x46:
		case 0x56:
		case 0x66:
		case 0x76:
			fill_struct(Hexa_ST_MEMD_GP_U163_Rtt, instr,
				    instr_struct);
			break;
		case 0x48:
		case 0x58:
		case 0x68:
		case 0x78:
			fill_struct(Hexa_LD_MEMB_Rd_GP_U160, instr,
				    instr_struct);
			break;
		case 0x49:
		case 0x59:
		case 0x69:
		case 0x79:
			fill_struct(Hexa_LD_MEMUB_Rd_GP_U160, instr,
				    instr_struct);
			break;
		case 0x4A:
		case 0x5A:
		case 0x6A:
		case 0x7A:
			fill_struct(Hexa_LD_MEMH_Rd_GP_U161, instr,
				    instr_struct);
			break;
		case 0x4B:
		case 0x5B:
		case 0x6B:
		case 0x7B:
			fill_struct(Hexa_LD_MEMUH_Rd_GP_U161, instr,
				    instr_struct);
			break;
		case 0x4C:
		case 0x5C:
		case 0x6C:
		case 0x7C:
			fill_struct(Hexa_LD_MEMW_Rd_GP_U162, instr,
				    instr_struct);
			break;
		case 0x4E:
		case 0x5E:
		case 0x6E:
		case 0x7E:
			fill_struct(Hexa_LD_MEMD_Rdd_GP_U163, instr,
				    instr_struct);
			break;
		}
		break;

	case 0x05:		// Jump
		switch ((instr >> 21) & 0x7F) {
		case 0x05:
			fill_struct(Hexa_J_JR_CALLR_Rs, instr, instr_struct);
			break;
		case 0x08:
		case 0x09:
			fill_struct(Hexa_J_JR_C_CALLR_Pu_Rs, instr,
				    instr_struct);
			break;
		case 0x14:
			fill_struct(Hexa_J_JR_JUMPR_Rs, instr, instr_struct);
			break;
		case 0x15:
			fill_struct(Hexa_J_JR_HINTJ_Rs, instr, instr_struct);
			break;
		case 0x1A:
		case 0x1B:
			fill_struct(Hexa_J_JR_C_JUMPR_Pu_Rs, instr,
				    instr_struct);
			break;
		case 0x20:
		case 0x21:
			fill_struct(Hexa_SYSTEM_TRAP0_U8, instr, instr_struct);
			break;
		case 0x22:
		case 0x23:
			fill_struct(Hexa_SYSTEM_PAUSE_U8, instr, instr_struct);
			break;
		case 0x24:
		case 0x25:
			fill_struct(Hexa_SYSTEM_TRAP1_U8, instr, instr_struct);
			break;
		case 0x36:
			if (((instr >> 11) & 0x07) == 0) {
				fill_struct(Hexa_SYSTEM_ICINVA_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x3E:
			if ((((instr >> 16) & 0x1F) == 0) &&
			    (((instr >> 13) & 0x01) == 0) &&
			    (((instr >> 0) & 0x01FF) == 2)) {
				fill_struct(Hexa_SYSTEM_ISYNC, instr,
					    instr_struct);
			}
			break;
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4A:
		case 0x4B:
		case 0x4C:
		case 0x4D:
		case 0x4E:
		case 0x4F:
			if (((instr >> 0) & 0x01) == 0) {
				fill_struct(Hexa_J_JR_JUMP_R222, instr,
					    instr_struct);
			}
			break;
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
		case 0x58:
		case 0x59:
		case 0x5A:
		case 0x5B:
		case 0x5C:
		case 0x5D:
		case 0x5E:
		case 0x5F:
			if (((instr >> 0) & 0x01) == 0) {
				fill_struct(Hexa_J_JR_CALL_R222, instr,
					    instr_struct);
			}
			break;
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
			fill_struct(Hexa_J_JR_C_JUMP_Pu_R152, instr,
				    instr_struct);
			break;
		case 0x68:
		case 0x69:
		case 0x6A:
		case 0x6B:
		case 0x6C:
		case 0x6D:
		case 0x6E:
		case 0x6F:
			if (((instr >> 11) & 0x01) == 0) {
				fill_struct(Hexa_J_JR_C_CALL_Pu_R152, instr,
					    instr_struct);
			}
			break;
		}
		break;

	case 0x06:		// Control Register
		switch ((instr >> 20) & 0xFF) {
		case 0x00:
		case 0x01:
			fill_struct(Hexa_CR_LOOP0_R72_Rs, instr, instr_struct);
			break;
		case 0x02:
		case 0x03:
			fill_struct(Hexa_CR_LOOP1_R72_Rs, instr, instr_struct);
			break;
		case 0x0A:
		case 0x0B:
			fill_struct(Hexa_CR_SP1LOOP0_P3_R72_Rs, instr,
				    instr_struct);
			break;
		case 0x0C:
		case 0x0D:
			fill_struct(Hexa_CR_SP2LOOP0_P3_R72_Rs, instr,
				    instr_struct);
			break;
		case 0x0E:
		case 0x0F:
			fill_struct(Hexa_CR_SP3LOOP0_P3_R72_Rs, instr,
				    instr_struct);
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
			fill_struct(Hexa_J_JR_C_differ_Rs_JUMP_R132, instr,
				    instr_struct);
			break;
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x17:
			fill_struct(Hexa_J_JR_C_greater_Rs_JUMP_R132, instr,
				    instr_struct);
			break;
		case 0x18:
		case 0x19:
		case 0x1A:
		case 0x1B:
			fill_struct(Hexa_J_JR_C_equal_Rs_JUMP_R132, instr,
				    instr_struct);
			break;
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x1F:
			fill_struct(Hexa_J_JR_C_lower_Rs_JUMP_R132, instr,
				    instr_struct);
			break;
		case 0x22:
		case 0x23:
			fill_struct(Hexa_CR_TransferPred_Cd_Rs, instr,
				    instr_struct);
			break;
		case 0x24:
		case 0x25:
			fill_struct(Hexa_SYSTEM_TRACE_Rs, instr, instr_struct);
			break;
		case 0x32:
		case 0x33:
			fill_struct(Hexa_CR_TransferPred_Cdd_Rss, instr,
				    instr_struct);
			break;
		case 0x80:
		case 0x81:
			fill_struct(Hexa_CR_TransferPred_Rdd_Css, instr,
				    instr_struct);
			break;
		case 0x90:
		case 0x91:
			fill_struct(Hexa_CR_LOOP0_R72_U10, instr, instr_struct);
			break;
		case 0x92:
		case 0x93:
			fill_struct(Hexa_CR_LOOP1_R72_U10, instr, instr_struct);
			break;
		case 0x9A:
		case 0x9B:
			fill_struct(Hexa_CR_SP1LOOP0_P3_R72_U10, instr,
				    instr_struct);
			break;
		case 0x9C:
		case 0x9D:
			fill_struct(Hexa_CR_SP2LOOP0_P3_R72_U10, instr,
				    instr_struct);
			break;
		case 0x9E:
		case 0x9F:
			fill_struct(Hexa_CR_SP3LOOP0_P3_R72_U10, instr,
				    instr_struct);
			break;
		case 0xA0:
		case 0xA1:
			fill_struct(Hexa_CR_TransferPred_Rd_Cs, instr,
				    instr_struct);
			break;
		case 0xA4:
			if (((instr >> 16) & 0x0F) == 0x09) {
				fill_struct(Hexa_CR_ADD_Rd_Pc_U6, instr,
					    instr_struct);
			}
			break;
		case 0xB0:
			if ((((instr >> 13) & 0x01) ==
			     1) & (((instr >> 7) & 0x01) == 1)) {
				fill_struct(Hexa_CR_FASTCORNER9_Pd_Ps_Pt, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_AND_Pd_Pt_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xB1:
			if ((((instr >> 13) & 0x01) ==
			     1) & (((instr >> 7) & 0x01) == 1)) {
				fill_struct(Hexa_CR_not_FASTCORNER9_Pd_Ps_Pt,
					    instr, instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_AND_Pd_Ps_AND_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xB2:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_OR_Pd_Pt_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xB3:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_AND_Pd_Ps_OR_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xB4:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_XOR_Pd_Ps_Pt, instr,
					    instr_struct);
			}
			break;
		case 0xB5:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_OR_Pd_Ps_AND_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xB6:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_AND_Pd_Pt_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xB7:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_OR_Pd_Ps_OR_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xB8:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_ANY8_Pd_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xB9:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_AND_Pd_Ps_AND_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xBA:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_ALL8_Pd_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xBB:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_AND_Pd_Ps_OR_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xBC:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_NOT_Pd_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xBD:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_OR_Pd_Ps_AND_Pt_Pu, instr,
					    instr_struct);
			}
			break;
		case 0xBE:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_OR_Pd_Pt_Ps, instr,
					    instr_struct);
			}
			break;
		case 0xBF:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_CR_OR_Pd_Ps_OR_Pt_Pu, instr,
					    instr_struct);
			}
			break;
			break;
		case 0xC2:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_SYSTEM_BRKPT, instr,
					    instr_struct);
			}
			break;
		}
		break;

	case 0x07:		// ALU32
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_ASLH_Rd_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_C_ASLH_Pu_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x01:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_ASRH_Rd_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_C_ASRH_Pu_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x03:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_TransferReg_Rd_Rs, instr,
					    instr_struct);
			}	// else {fill_struct(, instr, instr_struct);}
			break;
		case 0x04:
			if (((instr >> 13) & 0x01) == 0) {
				// fill_struct(, instr, instr_struct);
			} else {
				fill_struct(Hexa_ALU32_C_ZXTB_Pu_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x05:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_SXTB_Rd_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_C_SXTB_Pu_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x06:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_ZXTH_Rd_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_C_ZXTH_Pu_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x07:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_SXTH_Rd_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_C_SXTH_Pu_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x09:
		case 0x0B:
		case 0x0D:
		case 0x0F:
			fill_struct(Hexa_ALU32_TransferImmLow_Rd_u16, instr,
				    instr_struct);
			break;
		case 0x18:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_Rs_S8, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_COMBINE_Rdd_Rs_S8, instr,
					    instr_struct);
			}
			break;
		case 0x19:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_Rs_S8, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_COMBINE_Rdd_S8_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x1A:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_Rs_S8, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_CMP_eq_Rd_Rs_S8, instr,
					    instr_struct);
			}
			break;
		case 0x1B:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_Rs_S8, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_not_CMP_eq_Rd_Rs_S8,
					    instr, instr_struct);
			}
			break;
		case 0x1C:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_S8_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_COMBINE_Rdd_Rs_S8, instr,
					    instr_struct);
			}
			break;
		case 0x1D:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_S8_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x1E:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_S8_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_CMP_eq_Rd_Rs_S8, instr,
					    instr_struct);
			}
			break;
		case 0x1F:
			if (((instr >> 13) & 0x01) == 0) {
				fill_struct(Hexa_ALU32_MUX_Rd_Pu_S8_Rs, instr,
					    instr_struct);
			} else {
				fill_struct(Hexa_ALU32_not_CMP_eq_Rd_Rs_S8,
					    instr, instr_struct);
			}
			break;
		case 0x11:
		case 0x13:
		case 0x15:
		case 0x17:
			fill_struct(Hexa_ALU32_TransferImmHigh_Rd_u16, instr,
				    instr_struct);
			break;
		case 0x20:
		case 0x21:
		case 0x22:
		case 0x23:
		case 0x24:
		case 0x25:
		case 0x26:
		case 0x27:
			fill_struct(Hexa_ALU32_C_ADD_Pu_Rd_Rs_S8, instr,
				    instr_struct);
			break;
		case 0x28:
		case 0x29:
			if (((instr >> 2) & 0x03) == 0) {
				if (((instr >> 4) & 0x01) == 0) {
					fill_struct(Hexa_ALU32_CMP_eq_Pu_Rs_S10,
						    instr, instr_struct);
				} else {
					fill_struct
					    (Hexa_ALU32_not_CMP_eq_Pu_Rs_S10,
					     instr, instr_struct);
				}
			}
			break;
		case 0x2A:
		case 0x2B:
			if (((instr >> 2) & 0x03) == 0) {
				if (((instr >> 4) & 0x01) == 0) {
					fill_struct(Hexa_ALU32_CMP_gt_Pu_Rs_S10,
						    instr, instr_struct);
				} else {
					fill_struct
					    (Hexa_ALU32_not_CMP_gt_Pu_Rs_S10,
					     instr, instr_struct);
				}
			}
			break;
		case 0x2C:
			if (((instr >> 2) & 0x03) == 0) {
				if (((instr >> 4) & 0x01) == 0) {
					fill_struct(Hexa_ALU32_CMP_gtu_Pu_Rs_U9,
						    instr, instr_struct);
				} else {
					fill_struct
					    (Hexa_ALU32_not_CMP_gtu_Pu_Rs_U9,
					     instr, instr_struct);
				}
			}
			break;
		case 0x30:
		case 0x31:
			fill_struct(Hexa_ALU32_AND_Rd_Rs_s10, instr,
				    instr_struct);
			break;
		case 0x32:
		case 0x33:
			fill_struct(Hexa_ALU32_SUB_Rd_s10_Rs, instr,
				    instr_struct);
			break;
		case 0x34:
		case 0x35:
			fill_struct(Hexa_ALU32_OR_Rd_Rs_s10, instr,
				    instr_struct);
			break;
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
			fill_struct(Hexa_ALU32_TransferImm_Rd_s16, instr,
				    instr_struct);
			break;
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
		case 0x58:
		case 0x59:
		case 0x5A:
		case 0x5B:
		case 0x5C:
		case 0x5D:
		case 0x5E:
		case 0x5F:
			fill_struct(Hexa_ALU32_MUX_Rd_Pu_S8_S8, instr,
				    instr_struct);
			break;
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
			fill_struct(Hexa_ALU32_COMBINE_Rdd_S8_S8, instr,
				    instr_struct);
			break;
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
			fill_struct(Hexa_ALU32_COMBINE_Rdd_S8_U6, instr,
				    instr_struct);
			break;
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x76:
		case 0x77:
			fill_struct(Hexa_ALU32_C_TransferImm_Pu_Rd_S12, instr,
				    instr_struct);
			break;
		case 0x78:
		case 0x79:
		case 0x7A:
		case 0x7B:
		case 0x7C:
		case 0x7D:
		case 0x7E:
		case 0x7F:
			fill_struct(Hexa_ALU32_NOP, instr, instr_struct);
			break;
		}
		break;

	case 0x08:		// XTYPE
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_PRED_LSR_Rdd_Rss_U6,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_PRED_ASL_Rdd_Rss_U6,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PERM_VSATHUB_Rdd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_PERM_VSATWUH_Rdd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_PERM_VSATWH_Rdd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				fill_struct(Hexa_XTYPE_PERM_VSATHB_Rdd_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x01:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 12) & 0x03) == 0x00)) {
				addraw();
				fill_struct(Hexa_XTYPE_PRED_VASRH_Rdd_Rss_U4,
					    instr, instr_struct);
			}
			break;
		case 0x02:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASRW_Rdd_Rss_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASLW_Rdd_Rss_U5,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_ALU_VABSH_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VABSH_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_ALU_VABSW_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VABSW_Rdd_Rss, instr,
					    instr_struct);
			}
			break;
		case 0x04:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 12) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASRH_Rdd_Rss_U4,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 12) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_U4,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 12) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASLH_Rdd_Rss_U4,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_ALU_NOT_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_ALU_NEG_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_ALU_ABS_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_VCONJ_Rdd_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x06:
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_BIT_DEINTERLEAVE_Rdd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_BIT_INTERLEAVE_Rdd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_BIT_BREV_Rdd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				addrnd();
				fill_struct(Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6_rnd,
					    instr, instr_struct);
			}
			break;
		case 0x07:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2D_Rdd_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2UD_Rdd_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_UD2DF_Rdd_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_D2DF_Rdd_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2D_Rdd_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2UD_Rdd_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x08:
		case 0x09:
		case 0x0A:
		case 0x0B:
		case 0x0C:
		case 0x0D:
		case 0x0E:
		case 0x0F:
			fill_struct(Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_U6_U6,
				    instr, instr_struct);
			break;
		case 0x10:
		case 0x11:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_lesseq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_lesseq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_lesseq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_pluseq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_pluseq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_pluseq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			break;
		case 0x12:
		case 0x13:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_andeq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_andeq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_andeq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PRED_ASR_oreq_Rxx_Rss_U6,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_PRED_LSR_oreq_Rxx_Rss_U6,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_PRED_ASL_oreq_Rxx_Rss_U6,
					    instr, instr_struct);
			}
			break;
		case 0x14:
		case 0x15:
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_xoreq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_xoreq_Rxx_Rss_U6,
				     instr, instr_struct);
			}
			break;
		case 0x18:
		case 0x19:
		case 0x1A:
		case 0x1B:
		case 0x1C:
		case 0x1D:
		case 0x1E:
		case 0x1F:
			fill_struct(Hexa_XTYPE_BIT_INSERT_Rdd_Rss_U6_U6, instr,
				    instr_struct);
			break;
		case 0x20:
		case 0x21:
			if (((instr >> 6) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PERM_VSXTBH_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PERM_VZXTBH_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x02) {
				fill_struct(Hexa_XTYPE_PERM_VSXTHW_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x03) {
				fill_struct(Hexa_XTYPE_PERM_VZXTHW_Rdd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x22:
		case 0x23:
			if (((instr >> 6) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_ALU_SXTW_Rdd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PERM_VSPLATH_Rdd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x24:
		case 0x25:
		case 0x26:
		case 0x27:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2DF_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_UW2DF_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_W2DF_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x03) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2UD_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2D_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2UD_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2D_Rdd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x28:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x29:
			if (((instr >> 13) & 0x01) == 0x00) {
				addnot();
				fill_struct(Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x2A:
			fill_struct(Hexa_XTYPE_PRED_transfertPred_Pt_Rd, instr,
				    instr_struct);
			break;
		case 0x2C:
			fill_struct(Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_U6, instr,
				    instr_struct);
			break;
		case 0x2D:
			addnot();
			fill_struct(Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_U6, instr,
				    instr_struct);
			break;
		case 0x2F:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_SFCLASS_Pd_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x30:
		case 0x31:
		case 0x32:
		case 0x33:
		case 0x34:
		case 0x35:
		case 0x36:
		case 0x37:
			fill_struct(Hexa_XTYPE_PRED_MASK_Rdd_Pt, instr,
				    instr_struct);
			break;
		case 0x38:
		case 0x39:
			addraw();
			fill_struct(Hexa_XTYPE_BIT_TABLEIDXB_Rx_Rs_U4_S6_raw,
				    instr, instr_struct);
			break;
		case 0x3A:
		case 0x3B:
			addraw();
			fill_struct(Hexa_XTYPE_BIT_TABLEIDXH_Rx_Rs_U4_S6_raw,
				    instr, instr_struct);
			break;
		case 0x3C:
		case 0x3D:
			addraw();
			fill_struct(Hexa_XTYPE_BIT_TABLEIDXW_Rx_Rs_U4_S6_raw,
				    instr, instr_struct);
			break;
		case 0x3E:
		case 0x3F:
			addraw();
			fill_struct(Hexa_XTYPE_BIT_TABLEIDXD_Rx_Rs_U4_S6_raw,
				    instr, instr_struct);
			break;
		case 0x40:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_PERM_VSATHUB_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2SF_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_PERM_VSATWH_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PERM_VSATWUH_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_PERM_VSATHB_Rd_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x41:
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_UD2SF_Rd_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x42:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_CLB_Rd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_D2SF_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_BIT_CL0_Rd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_BIT_CL1_Rd_Rss, instr,
					    instr_struct);
			}
			break;
		case 0x43:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_NORMAMT_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2UW_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_BIT_ADD_Rd_CLB_Rss_S6,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x03) {
				fill_struct(Hexa_XTYPE_BIT_POPCOUNT_Rd_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 12) & 0x03) == 0x00)) {
				addraw();
				fill_struct(Hexa_XTYPE_PRED_VASRHUB_Rdd_Rss_U4,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 12) & 0x03) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_PRED_VASRHUB_Rdd_Rss_U4,
					    instr, instr_struct);
			}
			break;
		case 0x44:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_PERM_VTRUNOHB_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2W_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_PERM_VTRUNEHB_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PERM_VRNDWH_Rdd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				addsat();
				fill_struct(Hexa_XTYPE_PERM_VRNDWH_Rdd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x45:
			if (((instr >> 5) & 0x07) == 0x01) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2UW_Rd_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x46:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_PERM_SAT_Rd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_ROUND_Rdd_Rss_sat,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASRW_Rd_Rss_U5,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x47:
			if (((instr >> 5) & 0x07) == 0x01) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_DF2W_Rd_Rss,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_BIT_CT0_Rd_Rss, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_BIT_CT1_Rd_Rss, instr,
					    instr_struct);
			}
			break;
		case 0x48:
		case 0x4C:
			fill_struct(Hexa_XTYPE_PRED_VITPACK_Rd_Ps_Pt, instr,
				    instr_struct);
			break;
		case 0x4A:
		case 0x4B:
		case 0x4E:
		case 0x4F:
			fill_struct(Hexa_XTYPE_PRED_transfertPred_Rd_Pt, instr,
				    instr_struct);
			break;
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			fill_struct(Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_U6_U6, instr,
				    instr_struct);
			break;
		case 0x59:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_UW2SF_Rd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x5A:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_W2SF_Rd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x5B:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2UW_Rd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2UW_Rd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x5C:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2W_Rd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				addchop();
				fill_struct(Hexa_XTYPE_FP_CONVERT_SF2W_Rd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x5D:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_SFFIXUPR_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x5F:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_SFINVSQRTA_Rd_Pe_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x60:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_ASR_Rd_Rs_U5, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_PRED_LSR_Rd_Rs_U5, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_PRED_ASL_Rd_Rs_U5, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_BIT_CLB_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_BIT_CL0_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_BIT_CL1_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				fill_struct(Hexa_XTYPE_BIT_NORMAMT_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x61:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_ADD_Rd_CLB_Rs_S6,
					    instr, instr_struct);
			}
			break;
		case 0x62:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				fill_struct(Hexa_XTYPE_PRED_ASR_Rd_Rs_U5, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_PRED_ASL_Rd_Rs_U5, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_BIT_CT0_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_BIT_CT1_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_BIT_BREV_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				fill_struct(Hexa_XTYPE_PERM_VSPLATB_Rd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x64:
			if (((instr >> 6) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PERM_VSATHB_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PERM_VSATHUB_Rd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_ALU_ABS_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_ABS_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_NEG_Rd_Rs_sat, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				fill_struct(Hexa_XTYPE_PERM_SWIZ_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x65:
			if (((instr >> 6) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PERM_VSATHB_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PERM_VSATHUB_Rd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x66:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_SETBIT_Rd_Rs_U5,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_U5,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_U5,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PERM_SATH_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_PERM_SATUH_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_PERM_SATUB_Rd_Rs, instr,
					    instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				fill_struct(Hexa_XTYPE_PERM_SATB_Rd_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x67:
			if ((((instr >> 6) & 0x03) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_CROUND_Rd_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_ROUND_Rd_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_ROUND_Rd_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x68:
		case 0x69:
		case 0x6A:
		case 0x6B:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_U5_U5,
					    instr, instr_struct);
			}
			break;
		case 0x6C:
		case 0x6D:
		case 0x6E:
		case 0x6F:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_U5_U5,
					    instr, instr_struct);
			}
			break;
		case 0x70:
		case 0x71:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_lesseq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_lesseq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_lesseq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x04)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_pluseq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_pluseq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x06)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_pluseq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x72:
		case 0x73:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_andeq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_andeq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_andeq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x04)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_oreq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_oreq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x06)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_oreq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x74:
		case 0x75:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_xoreq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_xoreq_Rx_Rs_U5,
					    instr, instr_struct);
			}
			break;
		case 0x78:
		case 0x79:
		case 0x7A:
		case 0x7B:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_BIT_INSERT_Rdd_Rss_U6_U6,
					    instr, instr_struct);
			}
			break;
		}
		break;

	case 0x09:		// Load
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
			if ((((instr >> 16) & 0x1F) == 0x1E) &&
			    (((instr >> 13) & 0x01) == 0x00) &&
			    ((instr & 0x1F) == 0x1E)) {
				fill_struct(Hexa_LD_DEALLOCFRAME, instr,
					    instr_struct);
			}
			break;
		case 0x10:
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_SYSTEM_MEMW_LOCKED_Rd_Rs,
					    instr, instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_SYSTEM_MEMD_LOCKED_Rdd_Rs,
					    instr, instr_struct);
			}
			break;
		case 0x20:
			if (((instr >> 13) & 0x01) == 0x00) {
				fill_struct(Hexa_SYSTEM_DCFETCH_Rs_U113, instr,
					    instr_struct);
			}
			break;
		case 0x30:
			if ((((instr >> 16) & 0x1F) == 0x1E) &&
			    ((instr & 0x1F) == 0x1E)) {
				switch ((instr >> 10) & 0x0F) {
				case 0x00:
					fill_struct(Hexa_LD_DEALLOC_RETURN,
						    instr, instr_struct);
					break;
				case 0x02:
				case 0x04:
				case 0x06:
				case 0x0A:
				case 0x0C:
				case 0x0E:
					fill_struct(Hexa_LD_C_DEALLOC_RETURN_Ps,
						    instr, instr_struct);
					break;
				}
				break;
			}
			break;
		case 0x01:
		case 0x11:
		case 0x21:
		case 0x31:
			fill_struct(Hexa_LD_MEMBH_Rd_Rs_S111, instr,
				    instr_struct);
			break;
		case 0x02:
		case 0x12:
		case 0x22:
		case 0x32:
			fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Rs_S111, instr,
				    instr_struct);
			break;
		case 0x03:
		case 0x13:
		case 0x23:
		case 0x33:
			fill_struct(Hexa_LD_MEMUBH_Rd_Rs_S111, instr,
				    instr_struct);
			break;
		case 0x04:
		case 0x14:
		case 0x24:
		case 0x34:
			fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Rs_S110, instr,
				    instr_struct);
			break;
		case 0x05:
		case 0x15:
		case 0x25:
		case 0x35:
			fill_struct(Hexa_LD_MEMUBH_Rdd_Rs_S112, instr,
				    instr_struct);
			break;
		case 0x07:
		case 0x17:
		case 0x27:
		case 0x37:
			fill_struct(Hexa_LD_MEMBH_Rdd_Rs_S112, instr,
				    instr_struct);
			break;
		case 0x08:
		case 0x18:
		case 0x28:
		case 0x38:
			fill_struct(Hexa_LD_MEMB_Rd_Rs_S110, instr,
				    instr_struct);
			break;
		case 0x09:
		case 0x19:
		case 0x29:
		case 0x39:
			fill_struct(Hexa_LD_MEMUB_Rd_Rs_S110, instr,
				    instr_struct);
			break;
		case 0x0A:
		case 0x1A:
		case 0x2A:
		case 0x3A:
			fill_struct(Hexa_LD_MEMH_Rd_Rs_S111, instr,
				    instr_struct);
			break;
		case 0x0B:
		case 0x1B:
		case 0x2B:
		case 0x3B:
			fill_struct(Hexa_LD_MEMUH_Rd_Rs_S111, instr,
				    instr_struct);
			break;
		case 0x0C:
		case 0x1C:
		case 0x2C:
		case 0x3C:
			fill_struct(Hexa_LD_MEMW_Rd_Rs_S112, instr,
				    instr_struct);
			break;
		case 0x0E:
		case 0x1E:
		case 0x2E:
		case 0x3E:
			fill_struct(Hexa_LD_MEMD_Rdd_Rs_S113, instr,
				    instr_struct);
			break;
		case 0x41:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMBH_Rd_Rx_S41_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMBH_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x42:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct
				    (Hexa_LD_MEMH_FIFO_Ryy_Rx_S41_circ_Mu,
				     instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Rx_circ_Mu,
					    instr, instr_struct);
			}
			break;
		case 0x43:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Rx_S41_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x44:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct
				    (Hexa_LD_MEMB_FIFO_Ryy_Rx_S40_circ_Mu,
				     instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Rx_circ_Mu,
					    instr, instr_struct);
			}
			break;
		case 0x45:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Rx_S42_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Rx_circ_Mu,
					    instr, instr_struct);
			}
			break;
		case 0x47:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Rx_S42_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x48:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMB_Rd_Rx_S40_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMB_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x49:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMUB_Rd_Rx_S40_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMUB_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x4A:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMH_Rd_Rx_S41_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMH_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x4B:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMUH_Rd_Rx_S41_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMUH_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x4C:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMW_Rd_Rx_S42_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMW_Rd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x4E:
			if (!(((instr >> 9) & 0x01) | ((instr >> 12) & 0x01))) {
				fill_struct(Hexa_LD_MEMD_Rdd_Rx_S43_circ_Mu,
					    instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0)
			    && (((instr >> 9) & 0x01) == 1)
			    && (((instr >> 12) & 0x01) == 0)) {
				fill_struct(Hexa_LD_MEMD_Rdd_Rx_circ_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x51:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMBH_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMBH_Rd_Rx_S41, instr,
					    instr_struct);
			}
			break;
		case 0x52:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Rx_S41, instr,
					    instr_struct);
			}
			break;
		case 0x53:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Rx_S41, instr,
					    instr_struct);
			}
			break;
		case 0x54:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Rx_S40, instr,
					    instr_struct);
			}
			break;
		case 0x55:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Rx_S42, instr,
					    instr_struct);
			}
			break;
		case 0x57:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Rx_S42, instr,
					    instr_struct);
			}
			break;
		case 0x58:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMB_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMB_Rd_Rx_S40, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_C_MEMB_Rd_Rx_S40, instr,
					    instr_struct);
			}
			break;
		case 0x59:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMUB_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMUB_Rd_Rx_S40, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_C_MEMUB_Rd_Rx_S40, instr,
					    instr_struct);
			}
			break;
		case 0x5A:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMH_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMH_Rd_Rx_S41, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_C_MEMH_Rd_Rx_S41, instr,
					    instr_struct);
			}
			break;
		case 0x5B:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMUH_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMUH_Rd_Rx_S41, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_C_MEMUH_Rd_Rx_S41, instr,
					    instr_struct);
			}
			break;
		case 0x5C:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMW_Rd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMW_Rd_Rx_S42, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_C_MEMW_Rd_Rx_S42, instr,
					    instr_struct);
			}
			break;
		case 0x5E:
			if (((instr >> 12) & 0x03) == 0x01) {
				fill_struct(Hexa_LD_MEMD_Rdd_Re_U6, instr,
					    instr_struct);
			}
			if (((instr >> 12) & 0x03) == 0x00) {
				fill_struct(Hexa_LD_MEMD_Rdd_Rx_S43, instr,
					    instr_struct);
			}
			if (((instr >> 13) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_C_MEMD_Rdd_Rx_S43, instr,
					    instr_struct);
			}
			break;
		case 0x61:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMBH_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMBH_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x62:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Rt_U2_U6,
					    instr, instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x63:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x64:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Rt_U2_U6,
					    instr, instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x65:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x67:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x68:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMB_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMB_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x69:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMUB_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUB_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x6A:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMH_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMH_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x6B:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMUH_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUH_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x6C:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMW_Rd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMW_Rd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x6E:
			if (((instr >> 12) & 0x01) == 0x01) {
				fill_struct(Hexa_LD_MEMD_Rdd_Rt_U2_U6, instr,
					    instr_struct);
			}
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMD_Rdd_Rx_Mu, instr,
					    instr_struct);
			}
			break;
		case 0x71:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMBH_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			break;
		case 0x72:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu_brev,
					    instr, instr_struct);
			}
			break;
		case 0x73:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUBH_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			break;
		case 0x74:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu_brev,
					    instr, instr_struct);
			}
			break;
		case 0x75:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUBH_Rdd_Rx_Mu_brev,
					    instr, instr_struct);
			}
			break;
		case 0x77:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMBH_Rdd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			break;
		case 0x78:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMB_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_LD_C_MEMB_Rd_U6, instr,
					    instr_struct);
			}
			break;
		case 0x79:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUB_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_LD_C_MEMUB_Rd_U6, instr,
					    instr_struct);
			}
			break;
		case 0x7A:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMH_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_LD_C_MEMH_Rd_U6, instr,
					    instr_struct);
			}
			break;
		case 0x7B:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMUH_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_LD_C_MEMUH_Rd_U6, instr,
					    instr_struct);
			}
			break;
		case 0x7C:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMW_Rd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_LD_C_MEMW_Rd_U6, instr,
					    instr_struct);
			}
			break;
		case 0x7E:
			if ((((instr >> 12) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_LD_MEMD_Rdd_Rx_Mu_brev, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_LD_C_MEMD_Rdd_U6, instr,
					    instr_struct);
			}
			break;
		}
		break;

	case 0x0A:		// Store
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
			fill_struct(Hexa_SYSTEM_DCCLEANA_Rs, instr,
				    instr_struct);
			break;
		case 0x01:
			fill_struct(Hexa_SYSTEM_DCINVA_Rs, instr, instr_struct);
			break;
		case 0x02:
			fill_struct(Hexa_SYSTEM_DCCLEANINVA_Rs, instr,
				    instr_struct);
			break;
		case 0x04:
			if ((((instr >> 16) & 0x1F) == 0x1D)
			    && (((instr >> 11) & 0x07) == 0x00)) {
				fill_struct(Hexa_ST_ALLOCFRAME_U113, instr,
					    instr_struct);
			}
			break;
		case 0x05:
			fill_struct(Hexa_SYSTEM_MEMW_LOCKED_Rs_Pd_Rt, instr,
				    instr_struct);
			break;
		case 0x06:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_SYSTEM_DCZEROA_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x07:
			fill_struct(Hexa_SYSTEM_MEMD_LOCKED_Rs_Pd_Rtt, instr,
				    instr_struct);
			break;
		case 0x30:
			fill_struct(Hexa_SYSTEM_L2FETCH_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x34:
			fill_struct(Hexa_SYSTEM_L2FETCH_Rs_Rtt, instr,
				    instr_struct);
			break;
		case 0x08:
		case 0x18:
		case 0x28:
		case 0x38:
			fill_struct(Hexa_ST_MEMB_Rs_S110_Rt, instr,
				    instr_struct);
			break;
		case 0x0A:
		case 0x0B:
		case 0x1A:
		case 0x1B:
		case 0x2A:
		case 0x2B:
		case 0x3A:
		case 0x3B:
			fill_struct(Hexa_ST_MEMH_Rs_S111_Rt, instr,
				    instr_struct);
			break;
		case 0x0C:
		case 0x1C:
		case 0x2C:
		case 0x3C:
			fill_struct(Hexa_ST_MEMW_Rs_S112_Rt, instr,
				    instr_struct);
			break;
		case 0x0D:
		case 0x1D:
		case 0x2D:
		case 0x3D:
			if (((instr >> 11) & 0x03) == 0) {
				fill_struct(Hexa_NV_MEMB_Rs_S110_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 11) & 0x03) == 1) {
				fill_struct(Hexa_NV_MEMH_Rs_S111_Nt, instr,
					    instr_struct);
			}
			if (((instr >> 11) & 0x03) == 2) {
				fill_struct(Hexa_NV_MEMW_Rs_S112_Nt, instr,
					    instr_struct);
			}
			break;
		case 0x0E:
		case 0x1E:
		case 0x2E:
		case 0x3E:
			fill_struct(Hexa_ST_MEMD_Rs_S113_Rtt, instr,
				    instr_struct);
			break;
		case 0x40:
			fill_struct(Hexa_SYSTEM_BARRIER, instr, instr_struct);
			break;
		case 0x42:
			fill_struct(Hexa_SYSTEM_SYNCHT, instr, instr_struct);
			break;
		case 0x48:
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMB_Rx_circ_Mu_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMB_Rx_S40_circ_Mu_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x4A:
		case 0x4B:
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMH_Rx_circ_Mu_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMH_Rx_S41_circ_Mu_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x4C:
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMW_Rx_circ_Mu_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMW_Rx_S42_circ_Mu_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x4D:
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x01)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Rs_S110_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Rs_S111_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Rs_S112_Nt,
						    instr, instr_struct);
				}
			}
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x00)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Rx_circ_Mu_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Rx_circ_Mu_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Rx_circ_Mu_Nt,
						    instr, instr_struct);
				}
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct
					    (Hexa_NV_MEMB_Rx_S40_circ_Mu_Nt,
					     instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct
					    (Hexa_NV_MEMH_Rx_S41_circ_Mu_Nt,
					     instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct
					    (Hexa_NV_MEMW_Rx_S42_circ_Mu_Nt,
					     instr, instr_struct);
				}
			}
			break;
		case 0x4E:
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMD_Rx_circ_Mu_Rtt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMD_Rx_S43_circ_Mu_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x58:
			if ((((instr >> 13) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMB_Rx_S40_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMB_Re_U6_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 2) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMB_Rx_S40_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x5A:
		case 0x5B:
			if ((((instr >> 13) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMH_Rx_S41_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMH_Re_U6_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 2) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMH_Rx_S41_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x5C:
			if ((((instr >> 13) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMW_Rx_S42_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMW_Re_U6_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 2) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMW_Rx_S42_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x5D:
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Re_U6_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Re_U6_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Re_U6_Nt,
						    instr, instr_struct);
				}
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 1) & 0x01) == 0x00)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Rx_S40_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Rx_S41_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Rx_S42_Nt,
						    instr, instr_struct);
				}
			}
			if ((((instr >> 13) & 0x01) == 0x01)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_C_MEMB_Rx_S40_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_C_MEMH_Rx_S41_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_C_MEMW_Rx_S42_Nt,
						    instr, instr_struct);
				}
			}
			break;
		case 0x5E:
			if ((((instr >> 13) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMD_Rx_S43_Rtt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMD_Re_U6_Rtt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00)
			    && (((instr >> 7) & 0x01) == 0x00)
			    && (((instr >> 2) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMD_Rx_S43_Rtt, instr,
					    instr_struct);
			}
			break;
		case 0x68:
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMB_Ru_U2_U6_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMB_Rx_Mu_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x6A:
		case 0x6B:
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMH_Ru_U2_U6_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMH_Rx_Mu_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x6C:
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMW_Ru_U2_U6_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMW_Rx_Mu_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x6D:
			if ((((instr >> 7) & 0x01) == 0x01)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Ru_U2_U6_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Ru_U2_U6_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Ru_U2_U6_Nt,
						    instr, instr_struct);
				}
			}
			if ((((instr >> 7) & 0x01) == 0x00)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Rx_Mu_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Rx_Mu_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Rx_Mu_Nt,
						    instr, instr_struct);
				}
			}
			break;
		case 0x6E:
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_MEMD_Ru_U2_U6_Rtt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMD_Rx_Mu_Rtt, instr,
					    instr_struct);
			}
			break;
		case 0x78:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMB_Rx_Mu_brev_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMB_U6_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x7A:
		case 0x7B:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMH_Rx_Mu_brev_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMH_U6_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x7C:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMW_Rx_Mu_brev_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMW_U6_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x7D:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_MEMB_Rx_Mu_brev_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_MEMH_Rx_Mu_brev_Nt,
						    instr, instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_MEMW_Rx_Mu_brev_Nt,
						    instr, instr_struct);
				}
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				if (((instr >> 11) & 0x03) == 0) {
					fill_struct(Hexa_NV_C_MEMB_U6_Nt, instr,
						    instr_struct);
				}
				if (((instr >> 11) & 0x03) == 1) {
					fill_struct(Hexa_NV_C_MEMH_U6_Nt, instr,
						    instr_struct);
				}
				if (((instr >> 11) & 0x03) == 2) {
					fill_struct(Hexa_NV_C_MEMW_U6_Nt, instr,
						    instr_struct);
				}
			}
			break;
		case 0x7E:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_ST_MEMD_Rx_Mu_brev_Rtt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_ST_C_MEMD_U6_Rtt, instr,
					    instr_struct);
			}
			break;
		}
		break;

	case 0x0B:		// ALU32
		fill_struct(Hexa_ALU32_ADD_Rd_Rs_s16, instr, instr_struct);
		break;

	case 0x0C:		// XTYPE
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
			fill_struct(Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_U3,
				    instr, instr_struct);
			break;
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			fill_struct(Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_U3,
				    instr, instr_struct);
			break;
		case 0x08:
		case 0x09:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PERM_SHUFFEB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PERM_SHUFFOB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PERM_SHUFFEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x0A:
		case 0x0B:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VXADDSUBW_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_ALU_VADDHUB_Rd_Rss_Rtt_sat,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VXSUBADDW_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VXADDSUBH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VXSUBADDH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x0C:
		case 0x0D:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PERM_SHUFFOH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_PERM_VTRUNEWH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct
				    (Hexa_XTYPE_PERM_VTRUNOWH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_BIT_LFS_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x0E:
		case 0x0F:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				addrnd();
				addinc1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VXADDSUBH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				addrnd();
				addinc1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VXSUBADDH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PERM_DECBIN_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
			fill_struct(Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_Pu,
				    instr, instr_struct);
			break;
		case 0x14:
		case 0x15:
			fill_struct(Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_Pu,
				    instr, instr_struct);
			break;
		case 0x16:
			fill_struct(Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt_Px_carry,
				    instr, instr_struct);
			break;
		case 0x17:
			fill_struct(Hexa_XTYPE_ALU_SUB_Rdd_Rss_Rtt_Px_carry,
				    instr, instr_struct);
			break;
		case 0x18:
		case 0x19:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASRW_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_VASLW_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_VLSLW_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x1A:
		case 0x1B:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VASRH_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_VASLH_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_VLSLH_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x1C:
		case 0x1D:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x1E:
		case 0x1F:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VCROTATE_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_VCNEGH_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCROTATE_Rdd_Rss_Rt_U2,
				     instr, instr_struct);
			}
			break;
		case 0x20:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ADDASL_Rd_Rs_Rt_U3,
					    instr, instr_struct);
			}
			break;
		case 0x28:
		case 0x29:
		case 0x2A:
		case 0x2B:
		case 0x2C:
		case 0x2D:
		case 0x2E:
		case 0x2F:
			if ((((instr >> 6) & 0x03) == 0x01)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_PRED_VASRW_Rd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rtet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rtet,
				     instr, instr_struct);
			}
			break;
		case 0x30:
		case 0x31:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				addsat();
				fill_struct(Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt, instr,
					    instr_struct);
			}
		case 0x32:
		case 0x33:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x34:
		case 0x35:
			if (((instr >> 6) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_BIT_SETBIT_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x02) {
				fill_struct(Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_Rd_S6_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x36:
		case 0x37:
			if (((instr >> 6) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_ALU_CROUND_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x02) {
				fill_struct(Hexa_XTYPE_ALU_ROUND_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 6) & 0x03) == 0x03) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_ROUND_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x38:
			fill_struct(Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x39:
			addnot();
			fill_struct(Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x3A:
			fill_struct(Hexa_XTYPE_PRED_BITSSET_Pd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x3B:
			addnot();
			fill_struct(Hexa_XTYPE_PRED_BITSSET_Pd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x3C:
			fill_struct(Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x3D:
			addnot();
			fill_struct(Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x3E:
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x03) {
				fill_struct(Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x05) {
				fill_struct(Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x06) {
				fill_struct(Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x07) {
				fill_struct(Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x3F:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_SFCMPGE_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_SFCMPUO_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x03) {
				fill_struct(Hexa_XTYPE_FP_SFCMPEQ_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_FP_SFCMPGT_Pd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
			fill_struct(Hexa_XTYPE_BIT_INSERT_Rd_Rs_Rtt, instr,
				    instr_struct);
			break;
		case 0x48:
		case 0x49:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_BIT_INSERT_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_ALU_xoreq_XOR_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x58:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_oreq_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_oreq_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_oreq_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_oreq_Rdd_Rss_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x59:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_VRMAXH_Rdd_Rtt_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_VRMAXUH_Rdd_Rtt_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VRMAXW_Rdd_Rtt_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VRMAXUW_Rdd_Rtt_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_ALU_VRMINH_Rdd_Rss_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01) &&
			    (((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_ALU_VRMINUH_Rdd_Rss_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x06)) {
				fill_struct(Hexa_XTYPE_ALU_VRMINW_Rdd_Rtt_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01) &&
			    (((instr >> 5) & 0x07) == 0x06)) {
				fill_struct(Hexa_XTYPE_ALU_VRMINUW_Rdd_Rtt_Ru,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x01) &&
			    (((instr >> 5) & 0x07) == 0x07)) {
				fill_struct
				    (Hexa_XTYPE_ALU_pluseq_VRCNEGH_Rxx_Rss_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x5A:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_andeq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_andeq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_andeq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSL_andeq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x5B:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_xoreq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_xoreq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_xoreq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSL_xoreq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x5C:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_lesseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_lesseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_lesseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSL_lesseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x5D:
			fill_struct
			    (Hexa_XTYPE_COMPLEX_pluseq_VRCROTATE_Rdd_Rss_Rt_U2,
			     instr, instr_struct);
			break;
		case 0x5E:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASR_pluseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSR_pluseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ASL_pluseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct
				    (Hexa_XTYPE_PRED_LSL_pluseq_Rdd_Rss_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x60:
		case 0x61:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_oreq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_oreq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_oreq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_oreq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x62:
		case 0x63:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_andeq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_andeq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_andeq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_andeq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x64:
		case 0x65:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_lesseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_lesseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_lesseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_lesseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x66:
		case 0x67:
			if ((((instr >> 6) & 0x03) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ASR_pluseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_LSR_pluseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_PRED_ASL_pluseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				fill_struct(Hexa_XTYPE_PRED_LSL_pluseq_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		}
		break;

	case 0x0D:		// XTYPE
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			fill_struct(Hexa_XTYPE_BIT_PARITY_Rdd_Rss_Rtt, instr,
				    instr_struct);
			break;
		case 0x08:
		case 0x09:
		case 0x0A:
		case 0x0B:
		case 0x0C:
		case 0x0D:
		case 0x0E:
		case 0x0F:
			fill_struct(Hexa_XTYPE_PRED_VMUX_Rd_Pu_Rss_Rtt, instr,
				    instr_struct);
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_PRED_ANY8_VCMPB_EQ_Pd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03) &&
			    (((instr >> 13) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_TLBMATCH_Pd_Rss_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x01)) {
				addraw();
				addlo();
				fill_struct
				    (Hexa_XTYPE_PRED_BOUNDSCHECK_Pd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x01)) {
				addraw();
				addhi();
				fill_struct
				    (Hexa_XTYPE_PRED_BOUNDSCHECK_Pd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x14:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_CMP_EQ_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_PRED_CMP_GT_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x04) {
				fill_struct(Hexa_XTYPE_PRED_CMP_GTU_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x17:
			if (((instr >> 5) & 0x07) == 0x00) {
				fill_struct(Hexa_XTYPE_FP_DFCMPEQ_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x01) {
				fill_struct(Hexa_XTYPE_FP_DFCMPGT_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x02) {
				fill_struct(Hexa_XTYPE_FP_DFCMPGE_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			if (((instr >> 5) & 0x07) == 0x03) {
				fill_struct(Hexa_XTYPE_FP_DFCMPUO_Pd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x18:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VADDUB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VADDUB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VADDH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VADDH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_ALU_VADDUH_Rdd_Rss_Rtt_sat,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				fill_struct
				    (Hexa_XTYPE_ALU_VADDW_Rdd_Rss_Rtt_sat,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_ALU_VADDW_Rdd_Rss_Rtt_sat,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07)) {
				fill_struct(Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x19:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VSUBUB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VSUBUB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VSUBH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VSUBH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_ALU_VSUBUH_Rdd_Rtt_Rss_sat,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_ALU_VSUBW_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_VSUBW_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07)) {
				fill_struct(Hexa_XTYPE_ALU_SUB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x1A:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VAVGUB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGUB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VAVGH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				addcrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_ALU_VAVGUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x1B:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VAVGW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				addcrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_VAVGUW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VAVGUW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				addsat();
				fill_struct(Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				addraw();
				addlo();
				fill_struct(Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07)) {
				addraw();
				addhi();
				fill_struct(Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x1C:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VNAVGH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				addsat();
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VNAVGH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				addsat();
				addcrnd();
				fill_struct(Hexa_XTYPE_ALU_VNAVGH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_VNAVGW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x02)) {
				addsat();
				addrnd();
				fill_struct(Hexa_XTYPE_ALU_VNAVGW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 6) & 0x03) == 0x03)) {
				addsat();
				addcrnd();
				fill_struct(Hexa_XTYPE_ALU_VNAVGW_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x1D:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VMINUB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_VMINH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VMINUH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_VMINW_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				fill_struct(Hexa_XTYPE_ALU_VMINUW_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_ALU_VMAXUW_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				fill_struct(Hexa_XTYPE_ALU_MIN_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07)) {
				fill_struct(Hexa_XTYPE_ALU_MINU_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x1E:
			if ((((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VMAXUB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_VMAXH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_VMAXUH_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_VMAXW_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04)) {
				fill_struct(Hexa_XTYPE_ALU_MAX_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_ALU_MAXU_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06)) {
				fill_struct(Hexa_XTYPE_ALU_VMAXB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07)) {
				fill_struct(Hexa_XTYPE_ALU_VMINB_Rdd_Rtt_Rss,
					    instr, instr_struct);
			}
			break;
		case 0x1F:
			switch ((instr >> 5) & 0x07) {
			case 0x00:
				fill_struct(Hexa_XTYPE_ALU_AND_Rdd_Rss_Rtt,
					    instr, instr_struct);
				break;
			case 0x01:
				fill_struct(Hexa_XTYPE_ALU_AND_Rdd_Rtt_n_Rss,
					    instr, instr_struct);
				break;
			case 0x02:
				fill_struct(Hexa_XTYPE_ALU_OR_Rdd_Rss_Rtt,
					    instr, instr_struct);
				break;
			case 0x03:
				fill_struct(Hexa_XTYPE_ALU_OR_Rdd_Rtt_n_Rss,
					    instr, instr_struct);
				break;
			case 0x04:
				fill_struct(Hexa_XTYPE_ALU_XOR_Rdd_Rss_Rtt,
					    instr, instr_struct);
				break;
			case 0x07:
				fill_struct(Hexa_XTYPE_ALU_MODWRAP_Rd_Rs_Rt,
					    instr, instr_struct);
				break;
			}
			break;
		case 0x21:
		case 0x23:
		case 0x25:
		case 0x27:
			fill_struct(Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x28:
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			// instr[5]:=instr[6]
			instr &= ~((instr >> 1) & 0x20);
			instr |= ((instr >> 1) & 0x20);
			// instr[6]=0
			instr ^= (instr & 0x40);
			fill_struct(Hexa_XTYPE_ALU_ADDh_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x29:
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			// instr[5]:=instr[6]
			instr &= ~((instr >> 1) & 0x20);
			instr |= ((instr >> 1) & 0x20);
			// instr[6]=0
			instr ^= (instr & 0x40);
			fill_struct(Hexa_XTYPE_ALU_SUBh_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x2A:
			adddec16();
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			fill_struct(Hexa_XTYPE_ALU_ADDh_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x2B:
			adddec16();
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			fill_struct(Hexa_XTYPE_ALU_SUBh_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x2C:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				addsat();
				adddeprecated();
				fill_struct
				    (Hexa_XTYPE_ALU_ADD_Rd_Rs_Rt_sat_deprecated,
				     instr, instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				addsat();
				adddeprecated();
				fill_struct(Hexa_XTYPE_ALU_SUB_Rd_Rt_Rs, instr,
					    instr_struct);
			}
			break;
		case 0x2D:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_MIN_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_MINU_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x2E:
			if ((((instr >> 7) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_MAX_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 7) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_MAXU_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x2F:
			fill_struct(Hexa_XTYPE_BIT_PARITY_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x30:
		case 0x31:
			fill_struct(Hexa_XTYPE_FP_SFMAKE_Rd_U10_pos, instr,
				    instr_struct);
			break;
		case 0x32:
		case 0x33:
			fill_struct(Hexa_XTYPE_FP_SFMAKE_Rd_U10_neg, instr,
				    instr_struct);
			break;
		case 0x38:
		case 0x39:
		case 0x3A:
		case 0x3B:
			fill_struct(Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x46:
		case 0x47:
			fill_struct(Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_U6, instr,
				    instr_struct);
			break;
		case 0x48:
		case 0x49:
			fill_struct(Hexa_XTYPE_FP_DFMAKE_Rdd_U10_pos, instr,
				    instr_struct);
			break;
		case 0x4A:
		case 0x4B:
			fill_struct(Hexa_XTYPE_FP_DFMAKE_Rdd_U10_neg, instr,
				    instr_struct);
			break;
		case 0x50:
		case 0x51:
			fill_struct(Hexa_XTYPE_ALU_oreq_AND_Rs_S10, instr,
				    instr_struct);
			break;
		case 0x52:
		case 0x53:
			fill_struct(Hexa_XTYPE_ALU_OR_Rx_Ru_AND_Rx_S10, instr,
				    instr_struct);
			break;
		case 0x54:
		case 0x55:
			fill_struct(Hexa_XTYPE_ALU_oreq_OR_Rs_S10, instr,
				    instr_struct);
			break;
		case 0x58:
		case 0x59:
		case 0x5A:
		case 0x5B:
			fill_struct(Hexa_XTYPE_ALU_ADD_Rd_Rs_ADD_Ru_S6, instr,
				    instr_struct);
			break;
		case 0x5C:
		case 0x5D:
		case 0x5E:
		case 0x5F:
			fill_struct(Hexa_XTYPE_ALU_ADD_Rd_Rs_SUB_S6_Ru, instr,
				    instr_struct);
			break;
		case 0x60:
			if (((instr >> 3) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_U8,
					    instr, instr_struct);
			}
			if (((instr >> 3) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_U8,
					    instr, instr_struct);
			}
			if (((instr >> 3) & 0x03) == 0x02) {
				fill_struct(Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_U8,
					    instr, instr_struct);
			}
			break;
		case 0x61:
			if (((instr >> 3) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_S8,
					    instr, instr_struct);
			}
			if (((instr >> 3) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_S8,
					    instr, instr_struct);
			}
			if (((instr >> 3) & 0x03) == 0x02) {
				fill_struct(Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_S8,
					    instr, instr_struct);
			}
			break;
		case 0x62:
			if ((((instr >> 3) & 0x03) == 0x00) &&
			    (((instr >> 12) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_U7,
					    instr, instr_struct);
			}
			if ((((instr >> 3) & 0x03) == 0x01) &&
			    (((instr >> 12) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_U7,
					    instr, instr_struct);
			}
			if ((((instr >> 3) & 0x03) == 0x02) &&
			    (((instr >> 12) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_U7,
					    instr, instr_struct);
			}
			break;
		case 0x64:
			if ((((instr >> 10) & 0x07) == 0x00) &&
			    (((instr >> 3) & 0x03) == 0x02)) {
				fill_struct(Hexa_XTYPE_FP_DFCLASS_Pd_Rss_U5,
					    instr, instr_struct);
			}
			break;
		case 0x68:
		case 0x6C:
			if (((instr >> 3) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_U8,
					    instr, instr_struct);
			}
			if (((instr >> 3) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_U8,
					    instr, instr_struct);
			}
			break;
		case 0x69:
		case 0x6D:
			if (((instr >> 3) & 0x03) == 0x00) {
				fill_struct(Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_S8,
					    instr, instr_struct);
			}
			if (((instr >> 3) & 0x03) == 0x01) {
				fill_struct(Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_S8,
					    instr, instr_struct);
			}
			break;
		case 0x6A:
		case 0x6E:
			if ((((instr >> 3) & 0x03) == 0x00) &&
			    (((instr >> 12) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_U7,
					    instr, instr_struct);
			}
			if ((((instr >> 3) & 0x03) == 0x01) &&
			    (((instr >> 12) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_U7,
					    instr, instr_struct);
			}
			break;
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x76:
		case 0x77:
			if ((((instr >> 1) & 0x03) == 0x00) &&
			    (((instr >> 4) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_AND_Rx_U8_ASL_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x01) &&
			    (((instr >> 4) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_OR_Rx_U8_ASL_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x02) &&
			    (((instr >> 4) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_ADD_Rx_U8_ASL_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x03) &&
			    (((instr >> 4) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_PRED_SUB_Rx_U8_ASL_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x00) &&
			    (((instr >> 4) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_AND_Rx_U8_LSR_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x01) &&
			    (((instr >> 4) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_OR_Rx_U8_LSR_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x02) &&
			    (((instr >> 4) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_ADD_Rx_U8_LSR_Rx_U5,
					    instr, instr_struct);
			}
			if ((((instr >> 1) & 0x03) == 0x03) &&
			    (((instr >> 4) & 0x01) == 0x01)) {
				fill_struct(Hexa_XTYPE_PRED_SUB_Rx_U8_LSR_Rx_U5,
					    instr, instr_struct);
			}
			break;
		case 0x78:
		case 0x79:
		case 0x7A:
		case 0x7B:
			fill_struct(Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_U62_Rs, instr,
				    instr_struct);
			break;
		case 0x7C:
		case 0x7D:
		case 0x7E:
		case 0x7F:
			fill_struct(Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_Rs_U6, instr,
				    instr_struct);
			break;
		}
		break;

	case 0x0E:		// XTYPE
		switch ((instr >> 21) & 0x7F) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_eqplus_MPYI_Rd_Rs_U8,
					    instr, instr_struct);
			}
			break;
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_eqless_MPYI_Rd_Rs_U8,
					    instr, instr_struct);
			}
			break;
		case 0x08:
		case 0x09:
		case 0x0A:
		case 0x0B:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_U8,
					    instr, instr_struct);
			}
			break;
		case 0x0C:
		case 0x0D:
		case 0x0E:
		case 0x0F:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_lesseq_MPYI_Rd_Rs_U8,
					    instr, instr_struct);
			}
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_S8,
					    instr, instr_struct);
			}
			break;
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x17:
			if ((((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_S8,
					    instr, instr_struct);
			}
			break;
		case 0x18:
			fill_struct(Hexa_XTYPE_MPY_ADD_Ry_Ru_MPYI_Ry_Rt, instr,
				    instr_struct);
			break;
		case 0x24:
			adddec1();
		case 0x20:
			fill_struct(Hexa_XTYPE_MPY_MPYh_Rdd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x25:
			adddec1();
		case 0x21:
			addrnd();
			fill_struct(Hexa_XTYPE_MPY_MPYh_Rdd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x26:
			adddec1();
		case 0x22:
			fill_struct(Hexa_XTYPE_MPY_MPYUh_Rdd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x28:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_MPY_Rdd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_COMPLEX_CMPYI_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_COMPLEX_CMPYR_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYH_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYHSU_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x2A:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_MPYU_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VMPYBSU_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rtet,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_PMPYW_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x2C:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VMPYBU_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYH_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYHSU_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x2E:
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rtet,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VPMPYH_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x34:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x30:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_MPYh_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x35:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x31:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_MPY_lesseq_MPYh_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x36:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x32:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_MPYUh_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x37:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x33:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_MPY_lesseq_MPYUh_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x38:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_pluseq_MPY_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_CMPYI_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_CMPYR_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYH_pluseq_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x39:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_lesseq_MPY_Rdd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYH_pluseq_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_xoreq_PMPYW_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x3A:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_MPYU_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rtet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rtet,
				     instr, instr_struct);
			}
			break;
		case 0x3B:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_lesseq_MPYU_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYHSU_pluseq_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x3C:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYBU_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYH_pluseq_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x3D:
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_xoreq_VPMPYH_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x3E:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYBSU_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rtet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rtet,
				     instr, instr_struct);
			}
			break;
		case 0x3F:
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYHSU_pluseq_Rdd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x40:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VRMPYH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPY_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x41:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_ALU_VABSDIFFW_Rdd_Rtt_Rss,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VRMPYWOH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VCMPYR_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x42:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rttet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VRADDUB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VRSADUB_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VRMPYWEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VCMPYI_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x43:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_ALU_VABSDIFFH_Rdd_Rtt_Rss,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rttet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x44:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VRMPYBU_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPY_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x45:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPYBSU_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				fill_struct(Hexa_XTYPE_MPY_VRMPYWOH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				addraw();
				addhi();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VCMPYR_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x46:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_VRMPYBSU_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				fill_struct(Hexa_XTYPE_MPY_VRMPYWEH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VCMPYI_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x47:
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				addraw();
				addlo();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x48:
		case 0x4A:
			if ((((instr >> 5) & 0x03) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x03) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VRADDUH_Rd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x49:
		case 0x4B:
			if ((((instr >> 5) & 0x03) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VRADDH_Rd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x4C:
		case 0x4E:
			if ((((instr >> 5) & 0x03) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt,
					    instr, instr_struct);
			}
			break;
		case 0x4D:
		case 0x4F:
			if ((((instr >> 5) & 0x03) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				addraw();
				addhi();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				addraw();
				addlo();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x50:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VDMPY_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYEH_pluseq_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x51:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VDMPYBSU_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYEH_pluseq_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VCMPYR_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYWEH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x52:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rttet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_ALU_pluseq_VRADDUB_Rxx_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_ALU_pluseg_VRSADUB_Rxx_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VCMPYI_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x53:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rttet,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYWOH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x54:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYBU_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VDMPY_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_VMPYEH_pluseq_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x55:
			if ((((instr >> 7) & 0x01) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_VACSH_Rxx_Pe_Rss_Rtt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				addraw();
				addhi();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYWEH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x56:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYBSU_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x57:
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				addraw();
				addlo();
				fill_struct
				    (Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x05) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VRMPYWOH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt,
				     instr, instr_struct);
			}
			break;
		case 0x58:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFADD_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFSUB_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x5A:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFMPY_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x5C:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFMAX_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFMIN_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x5E:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFFIXUPN_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFFIXUPD_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x5F:
			if ((((instr >> 7) & 0x01) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_FP_SFRECIPA_Rd_Pe_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x64:
			adddec1();
		case 0x60:
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			fill_struct(Hexa_XTYPE_MPY_MPYh_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x65:
			adddec1();
		case 0x61:
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			addrnd();
			fill_struct(Hexa_XTYPE_MPY_MPYh_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x66:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x62:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct(Hexa_XTYPE_MPY_MPYUh_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x68:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_MPYI_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x69:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				fill_struct(Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYH_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x6A:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_MPYU_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			break;
		case 0x6B:
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_MPYSU_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rtet,
					    instr, instr_struct);
			}
			break;
		case 0x6D:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_MPYur_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x01) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_MPYur_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x02) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				fill_struct(Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_MPYur_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x07) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_VMPYH_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x6F:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x04) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_MPYur_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 5) & 0x07) == 0x06) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				adddec1();
				addrnd();
				addsat();
				fill_struct(Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rtet,
					    instr, instr_struct);
			}
			break;
		case 0x74:
			adddec1();
		case 0x70:
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			fill_struct(Hexa_XTYPE_MPY_pluseq_MPYh_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x75:
			adddec1();
		case 0x71:
			if (((instr >> 7) & 0x01) == 0x01) {
				addsat();
			}
			fill_struct(Hexa_XTYPE_MPY_lesseq_MPYh_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x76:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x72:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_MPY_pluseq_MPYUh_Rd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x77:
			if (((instr >> 7) & 0x01) == 0x00) {
				adddec1();
			}
		case 0x73:
			if (((instr >> 7) & 0x01) == 0x00) {
				fill_struct
				    (Hexa_XTYPE_MPY_lesseq_MPYUh_Rd_Rs_Rt,
				     instr, instr_struct);
			}
			break;
		case 0x78:
			if ((((instr >> 5) & 0x07) == 0x00) &&
			    (((instr >> 13) & 0x01) == 0x00)) {
				fill_struct(Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_pluseq_SUB_Rd_Rt_Rs,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x04)) {
				fill_struct(Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x05)) {
				fill_struct(Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x06)) {
				fill_struct
				    (Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_lib,
				     instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x07)) {
				fill_struct
				    (Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt_lib,
				     instr, instr_struct);
			}
			break;
		case 0x79:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_oreq_AND_Rs_n_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_andeq_AND_Rs_n_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_xoreq_AND_Rs_n_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x7A:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_andeq_AND_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_andeq_OR_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_andeq_XOR_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_oreq_AND_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x7B:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x00)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_pluseq_MPY_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				adddec1();
				addsat();
				fill_struct(Hexa_XTYPE_MPY_lesseq_MPY_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 7) & 0x01) == 0x01)) {
				fill_struct
				    (Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_Pu_scale,
				     instr, instr_struct);
			}
			break;
		case 0x7C:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_xoreq_XOR_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		case 0x7E:
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x00)) {
				fill_struct(Hexa_XTYPE_ALU_oreq_OR_Rs_Rt, instr,
					    instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x01)) {
				fill_struct(Hexa_XTYPE_ALU_oreq_XOR_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x02)) {
				fill_struct(Hexa_XTYPE_ALU_xoreq_AND_Rs_Rt,
					    instr, instr_struct);
			}
			if ((((instr >> 13) & 0x01) == 0x00) &&
			    (((instr >> 5) & 0x07) == 0x03)) {
				fill_struct(Hexa_XTYPE_ALU_xoreq_OR_Rs_Rt,
					    instr, instr_struct);
			}
			break;
		}
		break;

	case 0x0F:		// ALU32
		switch ((instr >> 21) & 0x7F) {
		case 0x08:
			fill_struct(Hexa_ALU32_AND_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x09:
			fill_struct(Hexa_ALU32_OR_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x0B:
			fill_struct(Hexa_ALU32_XOR_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x0C:
			fill_struct(Hexa_ALU32_ANDnot_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x0D:
			fill_struct(Hexa_ALU32_ORnot_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x10:
		case 0x14:
			if (((instr >> 2) & 0x03) == 0) {
				if (((instr >> 4) & 0x01) == 0) {
					fill_struct(Hexa_ALU32_CMP_eq_Pu_Rs_Rt,
						    instr, instr_struct);
				} else {
					fill_struct
					    (Hexa_ALU32_not_CMP_eq_Pu_Rs_Rt,
					     instr, instr_struct);
				}
			}
			break;
		case 0x12:
		case 0x16:
			if (((instr >> 2) & 0x03) == 0) {
				if (((instr >> 4) & 0x01) == 0) {
					fill_struct(Hexa_ALU32_CMP_gt_Pu_Rs_Rt,
						    instr, instr_struct);
				} else {
					fill_struct
					    (Hexa_ALU32_not_CMP_gt_Pu_Rs_Rt,
					     instr, instr_struct);
				}
			}
			break;
		case 0x13:
		case 0x17:
			if (((instr >> 2) & 0x03) == 0) {
				if (((instr >> 4) & 0x01) == 0) {
					fill_struct(Hexa_ALU32_CMP_gtu_Pu_Rs_Rt,
						    instr, instr_struct);
				} else {
					fill_struct
					    (Hexa_ALU32_not_CMP_gtu_Pu_Rs_Rt,
					     instr, instr_struct);
				}
			}
			break;
		case 0x18:
			fill_struct(Hexa_ALU32_ADD_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x19:
			fill_struct(Hexa_ALU32_SUB_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x1A:
			fill_struct(Hexa_ALU32_CMP_eq_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x1B:
			fill_struct(Hexa_ALU32_not_CMP_eq_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x1C:
			fill_struct(Hexa_ALU32_COMBINE_Rd_RsH_RtH, instr,
				    instr_struct);
			break;
		case 0x1D:
			fill_struct(Hexa_ALU32_COMBINE_Rd_RsH_RtL, instr,
				    instr_struct);
			break;
		case 0x1E:
			fill_struct(Hexa_ALU32_COMBINE_Rd_RsL_RtH, instr,
				    instr_struct);
			break;
		case 0x1F:
			fill_struct(Hexa_ALU32_COMBINE_Rd_RsL_RtL, instr,
				    instr_struct);
			break;
		case 0x20:
		case 0x21:
		case 0x22:
		case 0x23:
		case 0x24:
		case 0x25:
		case 0x26:
		case 0x27:
			fill_struct(Hexa_ALU32_MUX_Rd_Pu_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x28:
		case 0x29:
		case 0x2A:
		case 0x2B:
			fill_struct(Hexa_ALU32_COMBINE_Rdd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x2C:
		case 0x2D:
		case 0x2E:
		case 0x2F:
			fill_struct(Hexa_ALU32_PACKHL_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x30:
			fill_struct(Hexa_ALU32_VADDH_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x31:
			fill_struct(Hexa_ALU32_VADDHsat_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x32:
			fill_struct(Hexa_ALU32_ADDsat_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x33:
			fill_struct(Hexa_ALU32_VADDUHsat_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x34:
			fill_struct(Hexa_ALU32_VSUBH_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x35:
			fill_struct(Hexa_ALU32_VSUBHsat_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x36:
			fill_struct(Hexa_ALU32_SUBsat_Rd_Rt_Rs, instr,
				    instr_struct);
			break;
		case 0x37:
			fill_struct(Hexa_ALU32_VSUBUHsat_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x38:
		case 0x3C:
			fill_struct(Hexa_ALU32_VAVGH_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x39:
		case 0x3D:
			fill_struct(Hexa_ALU32_VAVGHrnd_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x3B:
		case 0x3F:
			fill_struct(Hexa_ALU32_VNAVGH_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x48:
		case 0x4C:
			fill_struct(Hexa_ALU32_C_AND_Pu_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x49:
		case 0x4D:
			fill_struct(Hexa_ALU32_C_OR_Pu_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x4B:
		case 0x4F:
			fill_struct(Hexa_ALU32_C_XOR_Pu_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x58:
		case 0x5A:
			fill_struct(Hexa_ALU32_C_ADD_Pu_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x59:
		case 0x5B:
			fill_struct(Hexa_ALU32_C_SUB_Pu_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
			fill_struct(Hexa_ALU32_COMBINE_Rdd_S8_S8, instr,
				    instr_struct);
			break;
		case 0x64:
		case 0x65:
		case 0x66:
		case 0x67:
			fill_struct(Hexa_ALU32_COMBINE_Rdd_S8_U6, instr,
				    instr_struct);
			break;
		case 0x68:
		case 0x69:
		case 0x6A:
		case 0x6B:
		case 0x6C:
		case 0x6D:
		case 0x6E:
		case 0x6F:
			fill_struct(Hexa_ALU32_C_COMBINE_Pu_Rd_Rs_Rt, instr,
				    instr_struct);
			break;
		}
		break;
	}
	return 1;
}

void fill_struct(uint16 id, uint32 instr, insn_t * instr_struct)
{
	instr_struct->itype = id;
	instr_struct->size = 4;
	uint32 temp;
	// extract operands depending on instruction
	switch (id) {
		// 4 operands
		// R = XYZ (P,R,R)
	case Hexa_ALU32_MUX_Rd_Pu_Rs_Rt:
	case Hexa_XTYPE_FP_SFRECIPA_Rd_Pe_Rs_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,R,P)
	case Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_Pu_scale:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_PR;
		instr_struct->Operands[3].reg = ((instr >> 5) & 0x03);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64,R64,P)
	case Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt_Px_carry:
	case Hexa_XTYPE_ALU_SUB_Rdd_Rss_Rtt_Px_carry:
	case Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_Pu:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_PR;
		instr_struct->Operands[3].reg = ((instr >> 5) & 0x03);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R64,P) (inv)
	case Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_Pu:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_PR;
		instr_struct->Operands[3].reg = ((instr >> 5) & 0x03);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R64,U3)
	case Hexa_XTYPE_PERM_VSPLICEB_Rdd_Rss_Rtt_U3:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		instr_struct->Operands[3].value = ((instr >> 5) & 0x07);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R64,U3)
	case Hexa_XTYPE_PRED_ADDASL_Rd_Rs_Rt_U3:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		instr_struct->Operands[3].value = ((instr >> 5) & 0x07);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R64,U3) (inv)
	case Hexa_XTYPE_PERM_VALIGNB_Rdd_Rtt_Rss_U3:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		instr_struct->Operands[3].value = ((instr >> 5) & 0x07);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64,P = XYZ (R64,R64)
	case Hexa_XTYPE_ALU_VACSH_Rxx_Pe_Rss_Rtt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_R64;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (P,R,S8)
	case Hexa_ALU32_MUX_Rd_Pu_Rs_S8:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 21) & 0x03);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (P,S8,R)
	case Hexa_ALU32_MUX_Rd_Pu_S8_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 21) & 0x03);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (P,S8,S8)
	case Hexa_ALU32_MUX_Rd_Pu_S8_S8:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 21) & 0x03);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_imm;
		temp = (((instr >> 13) & 0x01) | ((instr >> 16) & 0x007F) << 1);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// if([!]P[.new]) R=XYZ(R,R)
	case Hexa_ALU32_C_ADD_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_AND_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_OR_Pu_Rd_Rs_Rt:
	case Hexa_ALU32_C_XOR_Pu_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |=
		    ((instr >> 7) & 0x01) | ((instr >> 12) & 0x02);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[1].reg);
		break;

		// if([!]P[.new]) R=XYZ(R,R) (inverse)
	case Hexa_ALU32_C_SUB_Pu_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |=
		    ((instr >> 7) & 0x01) | ((instr >> 12) & 0x02);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[1].reg);
		break;

		// if([!]P[.new]) R64=XYZ(R,R)
	case Hexa_ALU32_C_COMBINE_Pu_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |=
		    ((instr >> 7) & 0x01) | ((instr >> 12) & 0x02);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// if([!]P[.new]) R=XYZ(R,S8)
	case Hexa_ALU32_C_ADD_Pu_Rd_Rs_S8:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 21) & 0x03);
		instr_struct->Operands[0].specval |=
		    ((instr >> 23) & 0x01) | ((instr >> 12) & 0x02);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[1].reg);
		break;

		// P = XYZ (P, XYZ(P,P))
	case Hexa_CR_AND_Pd_Ps_AND_Pt_Pu:
	case Hexa_CR_AND_Pd_Ps_OR_Pt_Pu:
	case Hexa_CR_OR_Pd_Ps_AND_Pt_Pu:
	case Hexa_CR_OR_Pd_Ps_OR_Pt_Pu:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x03);
		instr_struct->Operands[2].type = o_PR;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x03);
		instr_struct->Operands[3].type = o_PR;
		instr_struct->Operands[3].reg = ((instr >> 6) & 0x03);
		instr_struct->Operands[3].specval |= ((instr >> 23) & 0x01);
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ(R,U5); if (P.new) JUMP R9:2
	case Hexa_J_JR_CMP_EQ_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_U5_C_JUMP_R92:
	case Hexa_J_JR_CMP_GTU_Pd_Rs_U5_C_JUMP_R92:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 25) & 0x01);
		instr_struct->Operands[0].specval |= ((instr >> 22) & 0x01) | 2;	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x0F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_near;
		temp =
		    (((instr >> 1) & 0x7F) << 2) | (((instr >> 20) & 0x03) <<
						    9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		instr_struct->Operands[3].addr = temp;
		break;

		// P = XYZ(R,R); if (P.new) JUMP R9:2
	case Hexa_J_JR_CMP_EQ_Pd_Rs_Rt_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_Rt_C_JUMP_R92:
	case Hexa_J_JR_CMP_GTU_Pd_Rs_Rt_C_JUMP_R92:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 12) & 0x01);
		instr_struct->Operands[0].specval |= ((instr >> 22) & 0x01) | 2;	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x0F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x0F);
		instr_struct->Operands[3].type = o_near;
		temp =
		    (((instr >> 1) & 0x7F) << 2) | (((instr >> 20) & 0x03) <<
						    9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		instr_struct->Operands[3].addr = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R,XYZ(R,S6))
	case Hexa_XTYPE_ALU_ADD_Rd_Rs_ADD_Ru_S6:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp =
		    (((instr >> 5) & 0x07)) | (((instr >> 13) & 0x01) << 3) |
		    (((instr >> 21) & 0x03) << 4);
		if (temp & (1 << 5)) {
			temp |= (0xFFFFFFFF << 5);
		}		// sign extension
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,XYZ(S6,R))
	case Hexa_XTYPE_ALU_ADD_Rd_Rs_SUB_S6_Ru:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp =
		    (((instr >> 5) & 0x07)) | (((instr >> 13) & 0x01) << 3) |
		    (((instr >> 21) & 0x03) << 4);
		if (temp & (1 << 5)) {
			temp |= (0xFFFFFFFF << 5);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 00) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64,U6,U6)
	case Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_U6_U6:
	case Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_U6_U6:
	case Hexa_XTYPE_BIT_INSERT_Rdd_Rss_U6_U6:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x003F);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_imm;
		temp = (((instr >> 5) & 0x07)) | (((instr >> 21) & 0x07) << 3);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R,U5,U5)
	case Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_U5_U5:
	case Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_U5_U5:
	case Hexa_XTYPE_BIT_INSERT_Rd_Rs_U5_U5:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_imm;
		temp = (((instr >> 5) & 0x07)) | (((instr >> 21) & 0x03) << 3);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,U4,S6)
	case Hexa_XTYPE_BIT_TABLEIDXD_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_BIT_TABLEIDXW_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_BIT_TABLEIDXH_Rx_Rs_U4_S6_raw:
	case Hexa_XTYPE_BIT_TABLEIDXB_Rx_Rs_U4_S6_raw:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = (((instr >> 5) & 0x07)) | (((instr >> 21) & 0x01) << 3);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 8) & 0x003F);
		if (temp & (1 << 5)) {
			temp |= (0xFFFFFFFF << 5);
		}		// sign extension
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64,R,U2)
	case Hexa_XTYPE_COMPLEX_VRCROTATE_Rdd_Rss_Rt_U2:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCROTATE_Rdd_Rss_Rt_U2:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 5) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (U6,XYZ(R,U6))
	case Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_U6:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    (((instr >> 5) & 0x07)) | (((instr >> 13) & 0x01) << 3) |
		    (((instr >> 21) & 0x03) << 4);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = (((instr >> 0) & 0x01F)) | (((instr >> 23) & 0x01) << 5);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

	case Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    (((instr >> 5) & 0x07)) | (((instr >> 13) & 0x01) << 3) |
		    (((instr >> 21) & 0x03) << 4);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

	case Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_U62_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp =
		    (((instr >> 5) & 0x07)) | (((instr >> 13) & 0x01) << 3) |
		    (((instr >> 21) & 0x03) << 4);
		temp <<= 2;
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

	case Hexa_XTYPE_MPY_ADD_Rd_Ru_MPYI_Rs_U6:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp =
		    (((instr >> 5) & 0x07)) | (((instr >> 13) & 0x01) << 3) |
		    (((instr >> 21) & 0x03) << 4);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (P,R64,R64)
	case Hexa_XTYPE_PRED_VMUX_Rd_Pu_Rss_Rtt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_R64;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// 3 operands
		// R = XYZ (R,R) (classic : rd,rs,rt)
	case Hexa_ALU32_ADD_Rd_Rs_Rt:
	case Hexa_ALU32_ADDsat_Rd_Rs_Rt:
	case Hexa_ALU32_AND_Rd_Rs_Rt:
	case Hexa_ALU32_OR_Rd_Rs_Rt:
	case Hexa_ALU32_XOR_Rd_Rs_Rt:
	case Hexa_ALU32_VADDH_Rd_Rs_Rt:
	case Hexa_ALU32_VADDHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VADDUHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VAVGH_Rd_Rs_Rt:
	case Hexa_ALU32_VAVGHrnd_Rd_Rs_Rt:
	case Hexa_ALU32_CMP_eq_Rd_Rs_Rt:
	case Hexa_ALU32_not_CMP_eq_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_ADD_Rd_Rs_Rt_sat_deprecated:
	case Hexa_XTYPE_ALU_andeq_AND_Rs_Rt:
	case Hexa_XTYPE_ALU_oreq_AND_Rs_Rt:
	case Hexa_XTYPE_ALU_xoreq_AND_Rs_Rt:
	case Hexa_XTYPE_ALU_andeq_AND_Rs_n_Rt:
	case Hexa_XTYPE_ALU_oreq_AND_Rs_n_Rt:
	case Hexa_XTYPE_ALU_xoreq_AND_Rs_n_Rt:
	case Hexa_XTYPE_ALU_andeq_OR_Rs_Rt:
	case Hexa_XTYPE_ALU_oreq_OR_Rs_Rt:
	case Hexa_XTYPE_ALU_xoreq_OR_Rs_Rt:
	case Hexa_XTYPE_ALU_andeq_XOR_Rs_Rt:
	case Hexa_XTYPE_ALU_oreq_XOR_Rs_Rt:
	case Hexa_XTYPE_ALU_xoreq_XOR_Rs_Rt:
	case Hexa_XTYPE_ALU_MAX_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MAXU_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MODWRAP_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_CROUND_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_ROUND_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_PARITY_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_BREV_Rd_Rs:
	case Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_SETBIT_Rd_Rs_Rt:
	case Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPY_Rd_Rs_Rtet:
	case Hexa_XTYPE_FP_SFADD_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFFIXUPD_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFFIXUPN_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_pluseq_SFMPY_Rd_Rs_Rt_lib:
	case Hexa_XTYPE_FP_lesseq_SFMPY_Rd_Rs_Rt_lib:
	case Hexa_XTYPE_FP_SFMAX_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFMIN_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFMPY_Rd_Rs_Rt:
	case Hexa_XTYPE_FP_SFSUB_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYI_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYSU_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYU_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPY_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYH_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASR_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSL_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_andeq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_LSR_oreq_Rd_Rs_Rt:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_Rt_sat:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_Rt_sat:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

	case Hexa_XTYPE_MPY_ADD_Ry_Ru_MPYI_Ry_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,R) (inverted : rd,rt,rs)
	case Hexa_ALU32_SUB_Rd_Rt_Rs:
	case Hexa_ALU32_SUBsat_Rd_Rt_Rs:
	case Hexa_ALU32_VSUBH_Rd_Rs_Rt:
	case Hexa_ALU32_VSUBHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VSUBUHsat_Rd_Rs_Rt:
	case Hexa_ALU32_VNAVGH_Rd_Rs_Rt:
	case Hexa_ALU32_COMBINE_Rd_RsH_RtH:
	case Hexa_ALU32_COMBINE_Rd_RsL_RtH:
	case Hexa_ALU32_COMBINE_Rd_RsH_RtL:
	case Hexa_ALU32_COMBINE_Rd_RsL_RtL:
	case Hexa_ALU32_ORnot_Rd_Rs_Rt:
	case Hexa_ALU32_ANDnot_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_SUB_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_pluseq_SUB_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_MIN_Rd_Rs_Rt:
	case Hexa_XTYPE_ALU_MINU_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R[.H/.L],R[.H/.L])
	case Hexa_XTYPE_ALU_ADDh_Rd_Rt_Rs:
	case Hexa_XTYPE_ALU_SUBh_Rd_Rt_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		if (instr & 0x40) {
			instr_struct->Operands[1].specval = 0x01;
		} else {
			instr_struct->Operands[1].specval = 0x02;
		}
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		if (instr & 0x20) {
			instr_struct->Operands[2].specval = 0x01;
		} else {
			instr_struct->Operands[2].specval = 0x02;
		}
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R[.H/.L],R[.H/.L])
	case Hexa_XTYPE_MPY_MPYh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYUh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYUh_Rd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYUh_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		if (instr & 0x40) {
			instr_struct->Operands[1].specval = 0x01;
		} else {
			instr_struct->Operands[1].specval = 0x02;
		}
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		if (instr & 0x20) {
			instr_struct->Operands[2].specval = 0x01;
		} else {
			instr_struct->Operands[2].specval = 0x02;
		}
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,R[.H/.L])
	case Hexa_XTYPE_MPY_MPYur_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		if (instr & 0x00400020) {
			instr_struct->Operands[2].specval = 0x02;
		} else {
			instr_struct->Operands[2].specval = 0x01;
		}
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R[.H/.L],R[.H/.L])
	case Hexa_XTYPE_MPY_pluseq_MPYh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYUh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYUh_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYUh_Rdd_Rs_Rt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		if (instr & 0x40) {
			instr_struct->Operands[1].specval = 0x01;
		} else {
			instr_struct->Operands[1].specval = 0x02;
		}
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		if (instr & 0x20) {
			instr_struct->Operands[2].specval = 0x01;
		} else {
			instr_struct->Operands[2].specval = 0x02;
		}
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R,R64)
	case Hexa_XTYPE_BIT_EXTRACT_Rd_Rs_Rtt:
	case Hexa_XTYPE_BIT_EXTRACTU_Rd_Rs_Rtt:
	case Hexa_XTYPE_BIT_INSERT_Rd_Rs_Rtt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R64, R)
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYRWH_Rdd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYIWH_Rdd_Rs_Rtet:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R64,R64)
	case Hexa_XTYPE_ALU_VRADDH_Rd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VRADDUH_Rd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDHUB_Rd_Rss_Rtt_sat:
	case Hexa_XTYPE_BIT_PARITY_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VDMPY_Rd_Rss_Rtt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64,R64)
	case Hexa_XTYPE_ALU_ADD_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_AND_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_OR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_XOR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_xoreq_XOR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MAX_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MAXU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VADDUH_Rdd_Rss_Rtt_sat:
	case Hexa_XTYPE_ALU_VADDW_Rdd_Rss_Rtt_sat:
	case Hexa_XTYPE_ALU_VRADDUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_pluseq_VRADDUB_Rxx_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VAVGUW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VRSADUB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_pluseg_VRSADUB_Rxx_Rss_Rtt:
	case Hexa_XTYPE_BIT_EXTRACT_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_EXTRACTU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_INSERT_Rdd_Rss_Rtt:
	case Hexa_XTYPE_BIT_LFS_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXADDSUBH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXSUBADDH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXADDSUBW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VXSUBADDW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYI_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VRCMPYR_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYI_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYR_Rdd_Rss_Rttet:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_VCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VCMPYI_Rdd_Rss_Rtt:
	case Hexa_XTYPE_COMPLEX_pluseq_VCMPYR_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWEUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYWOUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWEUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VMPYWOUH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYWEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYWOH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VDMPY_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VDMPY_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYBU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYBU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VDMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VDMPYBSU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VMPYEH_pluseq_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_VRMPYH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_MPY_pluseq_VRMPYH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_DECBIN_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_SHUFFEB_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_SHUFFEH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_VTRUNEWH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_PERM_VTRUNOWH_Rdd_Rss_Rtt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R64) (inv)
	case Hexa_XTYPE_ALU_VABSDIFFH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VABSDIFFW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXUH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMAXUW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_MIN_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_MINU_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VMINB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINUH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VMINUW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VNAVGH_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VNAVGW_Rdd_Rss_Rtt:
	case Hexa_XTYPE_ALU_VSUBUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VSUBH_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_VSUBUH_Rdd_Rtt_Rss_sat:
	case Hexa_XTYPE_ALU_VSUBW_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_SUB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_ALU_AND_Rdd_Rtt_n_Rss:
	case Hexa_XTYPE_ALU_OR_Rdd_Rtt_n_Rss:
	case Hexa_XTYPE_PERM_SHUFFOB_Rdd_Rtt_Rss:
	case Hexa_XTYPE_PERM_SHUFFOH_Rdd_Rtt_Rss:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R)
	case Hexa_XTYPE_ALU_VCNEGH_Rdd_Rss_Rt:
	case Hexa_XTYPE_ALU_pluseq_VRCNEGH_Rxx_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_VCROTATE_Rdd_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_VRCMPYS_Rdd_Rss_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_VRCMPYS_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_andeq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_oreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASL_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_ASR_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSL_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_LSR_xoreq_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASLH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASRH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSLH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASLW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VASRW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSLW_Rdd_Rss_Rt:
	case Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_Rt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,R) (inv)
	case Hexa_XTYPE_ALU_VRMAXH_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMAXUH_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMAXW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMAXUW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMINH_Rdd_Rss_Ru:
	case Hexa_XTYPE_ALU_VRMINUH_Rdd_Rss_Ru:
	case Hexa_XTYPE_ALU_VRMINW_Rdd_Rtt_Ru:
	case Hexa_XTYPE_ALU_VRMINUW_Rdd_Rtt_Ru:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 0) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R,R)
	case Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPY_Rdd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPY_Rdd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_lesseq_CMPY_Rdd_Rs_Rtet:
	case Hexa_XTYPE_COMPLEX_CMPYI_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_CMPYR_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPYI_Rdd_Rs_Rt:
	case Hexa_XTYPE_COMPLEX_pluseq_CMPYR_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_PMPYW_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_xoreq_PMPYW_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_MPYU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_MPYU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPY_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_lesseq_MPYU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYH_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYH_pluseq_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYHSU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYHSU_pluseq_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYBSU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VMPYBU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_VMPYBSU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_pluseq_VMPYBU_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_VPMPYH_Rdd_Rs_Rt:
	case Hexa_XTYPE_MPY_xoreq_VPMPYH_Rdd_Rs_Rt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

	case Hexa_XTYPE_PRED_VASRW_Rd_Rss_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,S16)
	case Hexa_ALU32_ADD_Rd_Rs_s16:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp =
		    (((instr >> 5) & 0x01FF) | ((instr >> 21) & 0x007F) << 9);
		if (temp & (1 << 15)) {
			temp |= (0xFFFFFFFF << 15);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,S10)
	case Hexa_ALU32_AND_Rd_Rs_s10:
	case Hexa_ALU32_OR_Rd_Rs_s10:
	case Hexa_XTYPE_ALU_OR_Rx_Ru_AND_Rx_S10:
	case Hexa_XTYPE_ALU_oreq_AND_Rs_S10:
	case Hexa_XTYPE_ALU_oreq_OR_Rs_S10:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = (((instr >> 5) & 0x01FF) | ((instr >> 21) & 0x01) << 9);
		if (temp & (1 << 9)) {
			temp |= (0xFFFFFFFF << 9);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R,S8)
	case Hexa_ALU32_CMP_eq_Rd_Rs_S8:
	case Hexa_ALU32_not_CMP_eq_Rd_Rs_S8:
	case Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_S8:
	case Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_S8:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (S6,R)
	case Hexa_XTYPE_PRED_LSL_Rd_S6_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 5) & 0x001) | ((instr >> 16) & 0x001F) << 1;
		if (temp & (1 << 5)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,U8)
	case Hexa_XTYPE_MPY_eqplus_MPYI_Rd_Rs_U8:
	case Hexa_XTYPE_MPY_eqless_MPYI_Rd_Rs_U8:
	case Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_U8:
	case Hexa_XTYPE_MPY_lesseq_MPYI_Rd_Rs_U8:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (R,U5)
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_andeq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_oreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_andeq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_oreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_andeq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_oreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_xoreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_LSR_xoreq_Rx_Rs_U5:
	case Hexa_XTYPE_PRED_ASR_Rd_Rs_U5_rnd:
	case Hexa_XTYPE_PRED_ASRRND_Rd_Rs_U5:
	case Hexa_XTYPE_PRED_ASL_Rd_Rs_U5_sat:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64,U6)
	case Hexa_XTYPE_PRED_ASL_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_Rdd_Rss_U6:
	case Hexa_XTYPE_PRED_ASL_pluseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASL_lesseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_pluseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_lesseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_pluseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_lesseq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASL_andeq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASL_oreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_andeq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_oreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_andeq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_oreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASL_xoreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_LSR_xoreq_Rxx_Rss_U6:
	case Hexa_XTYPE_PRED_ASR_Rdd_Rss_U6_rnd:
	case Hexa_XTYPE_PRED_ASRRND_Rdd_Rss_U6:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x003F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R64,U5)
	case Hexa_XTYPE_PRED_VASLW_Rdd_Rss_U5:
	case Hexa_XTYPE_PRED_VASRW_Rdd_Rss_U5:
	case Hexa_XTYPE_PRED_VLSRW_Rdd_Rss_U5:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x01F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R64,U5)
	case Hexa_XTYPE_PRED_VASRW_Rd_Rss_U5:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x01F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64,U4)
	case Hexa_XTYPE_PRED_VASLH_Rdd_Rss_U4:
	case Hexa_XTYPE_PRED_VASRH_Rdd_Rss_U4:
	case Hexa_XTYPE_PRED_VLSRH_Rdd_Rss_U4:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x0F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

	case Hexa_XTYPE_PRED_VASRHUB_Rdd_Rss_U4:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x0F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (U8, xx(R',U5)
	case Hexa_XTYPE_PRED_ADD_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_ADD_Rx_U8_LSR_Rx_U5:
	case Hexa_XTYPE_PRED_SUB_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_SUB_Rx_U8_LSR_Rx_U5:
	case Hexa_XTYPE_PRED_AND_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_AND_Rx_U8_LSR_Rx_U5:
	case Hexa_XTYPE_PRED_OR_Rx_U8_ASL_Rx_U5:
	case Hexa_XTYPE_PRED_OR_Rx_U8_LSR_Rx_U5:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((((instr >> 3) & 0x01) << 0) |
			(((instr >> 5) & 0x07) << 1) |
			(((instr >> 13) & 0x01) << 4) |
			(((instr >> 21) & 0x07) << 5));
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (S10,R)
	case Hexa_ALU32_SUB_Rd_s10_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = (((instr >> 5) & 0x01FF) | ((instr >> 21) & 0x01) << 9);
		if (temp & (1 << 9)) {
			temp |= (0xFFFFFFFF << 9);
		}		// sign extension
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R,R)
	case Hexa_ALU32_COMBINE_Rdd_Rs_Rt:
	case Hexa_ALU32_PACKHL_Rd_Rs_Rt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (R,S8)
	case Hexa_ALU32_COMBINE_Rdd_Rs_S8:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R,S6)
	case Hexa_XTYPE_BIT_ADD_Rd_CLB_Rs_S6:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x003F);
		if (temp & (1 << 5)) {
			temp |= (0xFFFFFFFF << 5);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// P = XYZ (R64,U5)
	case Hexa_XTYPE_FP_DFCLASS_Pd_Rss_U5:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,U5)
	case Hexa_XTYPE_FP_SFCLASS_Pd_Rs_U5:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R64,S6)
	case Hexa_XTYPE_BIT_ADD_Rd_CLB_Rss_S6:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x003F);
		if (temp & (1 << 5)) {
			temp |= (0xFFFFFFFF << 5);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (S8,R)
	case Hexa_ALU32_COMBINE_Rdd_S8_Rs:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (S8,S8)
	case Hexa_ALU32_COMBINE_Rdd_S8_S8:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = (((instr >> 13) & 0x01) | ((instr >> 16) & 0x7F) << 1);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (S8,U6)
	case Hexa_ALU32_COMBINE_Rdd_S8_U6:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = (((instr >> 13) & 0x01) | ((instr >> 16) & 0x1F) << 1);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// if([!]P[.new]) R=XYZ(R)
	case Hexa_ALU32_C_ASLH_Pu_Rd_Rs:
	case Hexa_ALU32_C_ASRH_Pu_Rd_Rs:
	case Hexa_ALU32_C_SXTH_Pu_Rd_Rs:
	case Hexa_ALU32_C_SXTB_Pu_Rd_Rs:
	case Hexa_ALU32_C_ZXTB_Pu_Rd_Rs:
	case Hexa_ALU32_C_ZXTH_Pu_Rd_Rs:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x03);
		instr_struct->Operands[0].specval |=
		    ((instr >> 11) & 0x01) | ((instr >> 9) & 0x02);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[1].reg);
		break;

		// if([!]P[.new]) R=XYZ(S12)
	case Hexa_ALU32_C_TransferImm_Pu_Rd_S12:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 21) & 0x03);
		instr_struct->Operands[0].specval |=
		    ((instr >> 23) & 0x01) | ((instr >> 12) & 0x02);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = (((instr >> 5) & 0x00FF) | ((instr >> 16) & 0x0F) << 8);
		if (temp & (1 << 11)) {
			temp |= (0xFFFFFFFF << 11);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[1].reg);
		break;

		// P = XYZ (R,R)
	case Hexa_ALU32_CMP_eq_Pu_Rs_Rt:
	case Hexa_ALU32_not_CMP_eq_Pu_Rs_Rt:
	case Hexa_ALU32_CMP_gt_Pu_Rs_Rt:
	case Hexa_ALU32_not_CMP_gt_Pu_Rs_Rt:
	case Hexa_ALU32_CMP_gtu_Pu_Rs_Rt:
	case Hexa_ALU32_not_CMP_gtu_Pu_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPEQ_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPGE_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPGT_Pd_Rs_Rt:
	case Hexa_XTYPE_FP_SFCMPUO_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_BITSSET_Pd_Rs_Rt:
	case Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

	case Hexa_XTYPE_PRED_VITPACK_Rd_Ps_Pt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x01F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x03);
		instr_struct->Operands[2].type = o_PR;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x03);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// P = XYZ (R64,R64)
	case Hexa_XTYPE_FP_DFCMPEQ_Pd_Rss_Rtt:
	case Hexa_XTYPE_FP_DFCMPGE_Pd_Rss_Rtt:
	case Hexa_XTYPE_FP_DFCMPGT_Pd_Rss_Rtt:
	case Hexa_XTYPE_FP_DFCMPUO_Pd_Rss_Rtt:
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
	case Hexa_XTYPE_PRED_ANY8_VCMPB_EQ_Pd_Rss_Rtt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R64,R)
	case Hexa_XTYPE_PRED_TLBMATCH_Pd_Rss_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ (R,P) = R
	case Hexa_SYSTEM_MEMW_LOCKED_Rs_Pd_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R,P = XYZ(R)
	case Hexa_XTYPE_FP_SFINVSQRTA_Rd_Pe_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// XYZ (R,P) = R64
	case Hexa_SYSTEM_MEMD_LOCKED_Rs_Pd_Rtt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[2].type = o_R64;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,S10)
	case Hexa_ALU32_CMP_eq_Pu_Rs_S10:
	case Hexa_ALU32_not_CMP_eq_Pu_Rs_S10:
	case Hexa_ALU32_CMP_gt_Pu_Rs_S10:
	case Hexa_ALU32_not_CMP_gt_Pu_Rs_S10:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = (((instr >> 5) & 0x01FF) | ((instr >> 21) & 0x01) << 9);
		if (temp & (1 << 9)) {
			temp |= (0xFFFFFFFF << 9);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,U9)
	case Hexa_ALU32_CMP_gtu_Pu_Rs_U9:
	case Hexa_ALU32_not_CMP_gtu_Pu_Rs_U9:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x01FF);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,S8)
	case Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_S8:
	case Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_S8:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		break;
	case Hexa_XTYPE_PRED_VCMPB_GT_Pd_Rss_S8:
	case Hexa_XTYPE_PRED_VCMPH_GT_Pd_Rss_S8:
	case Hexa_XTYPE_PRED_VCMPW_GT_Pd_Rss_S8:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,U8)
	case Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_U8:
	case Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_U8:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		instr_struct->Operands[2].value = temp;
		break;
	case Hexa_XTYPE_PRED_VCMPB_EQ_Pd_Rss_U8:
	case Hexa_XTYPE_PRED_VCMPH_EQ_Pd_Rss_U8:
	case Hexa_XTYPE_PRED_VCMPW_EQ_Pd_Rss_U8:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x00FF);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,U7)
	case Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_U7:
	case Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_U7:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x007F);
		instr_struct->Operands[2].value = temp;
		break;
	case Hexa_XTYPE_PRED_VCMPB_GTU_Pd_Rss_U7:
	case Hexa_XTYPE_PRED_VCMPH_GTU_Pd_Rss_U7:
	case Hexa_XTYPE_PRED_VCMPW_GTU_Pd_Rss_U7:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x007F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,U6)
	case Hexa_XTYPE_PRED_BITSCLR_Pd_Rs_U6:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x003F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (R,U5)
	case Hexa_XTYPE_PRED_TSTBIT_Pd_Rs_U5:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R,U5)
	case Hexa_XTYPE_ALU_CROUND_Rd_Rs_U5:
	case Hexa_XTYPE_ALU_ROUND_Rd_Rs_U5:
	case Hexa_XTYPE_BIT_CLRBIT_Rd_Rs_U5:
	case Hexa_XTYPE_BIT_SETBIT_Rd_Rs_U5:
	case Hexa_XTYPE_BIT_TOGGLEBIT_Rd_Rs_U5:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R,U5)
	case Hexa_XTYPE_BIT_BITSPLIT_Rdd_Rs_U5:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x01F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x001F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (P,P)
	case Hexa_CR_FASTCORNER9_Pd_Ps_Pt:
	case Hexa_CR_not_FASTCORNER9_Pd_Ps_Pt:
	case Hexa_CR_XOR_Pd_Ps_Pt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x03);
		instr_struct->Operands[2].type = o_PR;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x03);
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ (P,P) (inverse)
	case Hexa_CR_AND_Pd_Pt_Ps:
	case Hexa_CR_OR_Pd_Pt_Ps:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x03);
		instr_struct->Operands[2].type = o_PR;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x03);
		instr_struct->Operands[2].specval |= ((instr >> 22) & 0x01);
		setDestinationRegister(instr_struct, -1);
		break;

		// P = XYZ R; if (P.new) JUMP R9:2
	case Hexa_J_JR_CMP_EQ_Pd_Rs_C_JUMP_R92:
	case Hexa_J_JR_CMP_GT_Pd_Rs_C_JUMP_R92:
	case Hexa_J_JR_TSTBIT_Pd_Rs_C_JUMP_R92:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 25) & 0x01);
		instr_struct->Operands[0].specval |= ((instr >> 22) & 0x01) | 2;	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x0F);
		instr_struct->Operands[2].type = o_near;
		temp =
		    (((instr >> 1) & 0x7F) << 2) | (((instr >> 20) & 0x03) <<
						    9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		instr_struct->Operands[2].addr = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = U6; JUMP R9:2
	case Hexa_J_JR_Transfer_Rd_U6_JUMP_R92:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x0F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 8) & 0x3F);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_near;
		temp =
		    (((instr >> 1) & 0x7F) << 2) | (((instr >> 20) & 0x03) <<
						    9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		instr_struct->Operands[2].addr = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = R; JUMP R9:2
	case Hexa_J_JR_Transfer_Rd_Rs_JUMP_R92:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x0F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x0F);
		instr_struct->Operands[2].type = o_near;
		temp =
		    (((instr >> 1) & 0x7F) << 2) | (((instr >> 20) & 0x03) <<
						    9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		instr_struct->Operands[2].addr = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// 2 operands
		// R = XYZ (R)
	case Hexa_ALU32_SXTB_Rd_Rs:
	case Hexa_ALU32_SXTH_Rd_Rs:
	case Hexa_ALU32_TransferReg_Rd_Rs:
	case Hexa_ALU32_ASLH_Rd_Rs:
	case Hexa_ALU32_ASRH_Rd_Rs:
	case Hexa_ALU32_ZXTH_Rd_Rs:
	case Hexa_SYSTEM_MEMW_LOCKED_Rd_Rs:
	case Hexa_XTYPE_ALU_ABS_Rd_Rs:
	case Hexa_XTYPE_ALU_NEG_Rd_Rs_sat:
	case Hexa_XTYPE_BIT_CL0_Rd_Rs:
	case Hexa_XTYPE_BIT_CL1_Rd_Rs:
	case Hexa_XTYPE_BIT_CLB_Rd_Rs:
	case Hexa_XTYPE_BIT_NORMAMT_Rd_Rs:
	case Hexa_XTYPE_BIT_CT0_Rd_Rs:
	case Hexa_XTYPE_BIT_CT1_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_W2SF_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_UW2SF_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2UW_Rd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2W_Rd_Rs:
	case Hexa_XTYPE_FP_SFFIXUPR_Rd_Rs:
	case Hexa_XTYPE_PERM_SATB_Rd_Rs:
	case Hexa_XTYPE_PERM_SATH_Rd_Rs:
	case Hexa_XTYPE_PERM_SATUB_Rd_Rs:
	case Hexa_XTYPE_PERM_SATUH_Rd_Rs:
	case Hexa_XTYPE_PERM_SWIZ_Rd_Rs:
	case Hexa_XTYPE_PERM_VSATHB_Rd_Rs:
	case Hexa_XTYPE_PERM_VSATHUB_Rd_Rs:
	case Hexa_XTYPE_PERM_VSPLATB_Rd_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R)
	case Hexa_SYSTEM_MEMD_LOCKED_Rdd_Rs:
	case Hexa_XTYPE_ALU_SXTW_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2DF_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_W2DF_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_UW2DF_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2UD_Rdd_Rs:
	case Hexa_XTYPE_FP_CONVERT_SF2D_Rdd_Rs:
	case Hexa_XTYPE_PERM_VSPLATH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VSXTBH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VSXTHW_Rdd_Rs:
	case Hexa_XTYPE_PERM_VZXTBH_Rdd_Rs:
	case Hexa_XTYPE_PERM_VZXTHW_Rdd_Rs:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = P
	case Hexa_XTYPE_PRED_transfertPred_Rd_Pt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x03);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// P = R
	case Hexa_XTYPE_PRED_transfertPred_Pt_Rd:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x01F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R64 = XYZ (P)
	case Hexa_XTYPE_PRED_MASK_Rdd_Pt:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x03);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (R64)
	case Hexa_XTYPE_ALU_ROUND_Rdd_Rss_sat:
	case Hexa_XTYPE_BIT_CL0_Rd_Rss:
	case Hexa_XTYPE_BIT_CL1_Rd_Rss:
	case Hexa_XTYPE_BIT_CLB_Rd_Rss:
	case Hexa_XTYPE_BIT_NORMAMT_Rd_Rss:
	case Hexa_XTYPE_BIT_POPCOUNT_Rd_Rss:
	case Hexa_XTYPE_BIT_CT0_Rd_Rss:
	case Hexa_XTYPE_BIT_CT1_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2SF_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_D2SF_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_UD2SF_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2UW_Rd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2W_Rd_Rss:
	case Hexa_XTYPE_PERM_SAT_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATHB_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATHUB_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATWH_Rd_Rss:
	case Hexa_XTYPE_PERM_VSATWUH_Rd_Rss:
	case Hexa_XTYPE_PERM_VTRUNOHB_Rd_Rss:
	case Hexa_XTYPE_PERM_VTRUNEHB_Rd_Rss:
	case Hexa_XTYPE_PERM_VRNDWH_Rdd_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (R64)
	case Hexa_XTYPE_ALU_ABS_Rdd_Rss:
	case Hexa_XTYPE_ALU_NOT_Rdd_Rss:
	case Hexa_XTYPE_ALU_VABSH_Rdd_Rss:
	case Hexa_XTYPE_ALU_VABSW_Rdd_Rss:
	case Hexa_XTYPE_ALU_NEG_Rdd_Rss:
	case Hexa_XTYPE_BIT_DEINTERLEAVE_Rdd_Rss:
	case Hexa_XTYPE_BIT_INTERLEAVE_Rdd_Rss:
	case Hexa_XTYPE_BIT_BREV_Rdd_Rss:
	case Hexa_XTYPE_COMPLEX_VCONJ_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_D2DF_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_UD2DF_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2UD_Rdd_Rss:
	case Hexa_XTYPE_FP_CONVERT_DF2D_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATHB_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATHUB_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATWH_Rdd_Rss:
	case Hexa_XTYPE_PERM_VSATWUH_Rdd_Rss:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ (R,R)
	case Hexa_SYSTEM_L2FETCH_Rs_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ (R,R64)
	case Hexa_SYSTEM_L2FETCH_Rs_Rtt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_R64;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (U16)
	case Hexa_ALU32_TransferImmHigh_Rd_u16:
	case Hexa_ALU32_TransferImmLow_Rd_u16:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    ((instr >> 0) & 0x3FFF) | (((instr >> 22) & 0x0003) << 14);
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R = XYZ (U10)
	case Hexa_XTYPE_FP_SFMAKE_Rd_U10_neg:
	case Hexa_XTYPE_FP_SFMAKE_Rd_U10_pos:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    ((instr >> 5) & 0x01FF) | (((instr >> 21) & 0x0001) << 9);
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// R64 = XYZ (U10)
	case Hexa_XTYPE_FP_DFMAKE_Rdd_U10_neg:
	case Hexa_XTYPE_FP_DFMAKE_Rdd_U10_pos:
		instr_struct->Operands[0].type = o_R64;
		instr_struct->Operands[0].reg = ((instr) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    ((instr >> 5) & 0x01FF) | (((instr >> 21) & 0x0001) << 9);
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ (R+U11:3)
	case Hexa_SYSTEM_DCFETCH_Rs_U113:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 0) & 0x07FF);
		temp <<= 3;
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (S16)
	case Hexa_ALU32_TransferImm_Rd_s16:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    ((instr >> 5) & 0x01FF) | (((instr >> 16) & 0x001F) << 9) |
		    (((instr >> 22) & 0x0003) << 14);
		if (temp & (1 << 15)) {
			temp |= (0xFFFFFFFF << 15);
		}		// sign extension
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// P = XYZ (P)
	case Hexa_CR_ALL8_Pd_Ps:
	case Hexa_CR_ANY8_Pd_Ps:
	case Hexa_CR_NOT_Pd_Ps:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[1].type = o_PR;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x03);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = ADD(PC, U6)
	case Hexa_CR_ADD_Rd_Pc_U6:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x0F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 7) & 0x003F);
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// XYZ (R7:2,Rs)
	case Hexa_CR_LOOP0_R72_Rs:
	case Hexa_CR_LOOP1_R72_Rs:
	case Hexa_CR_SP1LOOP0_P3_R72_Rs:
	case Hexa_CR_SP2LOOP0_P3_R72_Rs:
	case Hexa_CR_SP3LOOP0_P3_R72_Rs:
		instr_struct->Operands[0].type = o_near;
		temp = (((instr >> 3) & 0x003) | (((instr >> 8) & 0x001F) << 2)) << 2;	//R7:2
		if (temp & (1 << 8)) {
			temp |= (0xFFFFFFFF << 8);
		}		// sign extension
		instr_struct->Operands[0].addr = temp;
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x05);
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ (R7:2,U10)
	case Hexa_CR_LOOP0_R72_U10:
	case Hexa_CR_LOOP1_R72_U10:
	case Hexa_CR_SP1LOOP0_P3_R72_U10:
	case Hexa_CR_SP2LOOP0_P3_R72_U10:
	case Hexa_CR_SP3LOOP0_P3_R72_U10:
		instr_struct->Operands[0].type = o_near;
		temp = (((instr >> 3) & 0x003) | (((instr >> 8) & 0x001F) << 2)) << 2;	//R7:2
		if (temp & (1 << 8)) {
			temp |= (0xFFFFFFFF << 8);
		}		// sign extension
		instr_struct->Operands[0].addr = temp;
		instr_struct->Operands[1].type = o_imm;
		temp =
		    ((instr >> 0) & 0x0003) | (((instr >> 5) & 0x007) << 2) |
		    (((instr >> 16) & 0x001F) << 5);
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// CR = XYZ (R)
	case Hexa_CR_TransferPred_Cd_Rs:
	case Hexa_CR_TransferPred_Cdd_Rss:
		instr_struct->Operands[0].type = o_CR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		if ((instr >> 24) & 0x01) {
			instr_struct->Operands[0].specval |= 1;
			instr_struct->Operands[1].type = o_R64;
		} else {
			instr_struct->Operands[1].type = o_reg;
		}
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// R = XYZ (CR)
	case Hexa_CR_TransferPred_Rd_Cs:
	case Hexa_CR_TransferPred_Rdd_Css:
		if (((instr) >> 25) & 0x01) {
			instr_struct->Operands[0].type = o_reg;
		} else {
			instr_struct->Operands[0].type = o_R64;
			instr_struct->Operands[1].specval |= 1;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_CR;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct,
				       instr_struct->Operands[0].reg);
		break;

		// if (P) XYZ R
	case Hexa_J_JR_C_CALLR_Pu_Rs:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 21) & 0x01);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// if (P) XYZ R
	case Hexa_J_JR_C_JUMPR_Pu_Rs:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x03);
		if ((instr >> 11) & 0x01) {
			instr_struct->Operands[0].specval |= 2;	//new
			if ((instr >> 12) & 0x01) {
				instr_struct->auxpref = 1;	//t
			} else {
				instr_struct->auxpref = 2;	//nt
			}
		}
		instr_struct->Operands[0].specval |= ((instr >> 21) & 0x01);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// if (P) XYZ R15:2
	case Hexa_J_JR_C_JUMP_Pu_R152:
		if ((instr >> 11) & 0x01) {
			instr_struct->Operands[0].specval |= 2;	//new
			if ((instr >> 12) & 0x01) {
				instr_struct->auxpref = 1;	//t
			} else {
				instr_struct->auxpref = 2;	//nt
			}
		}
	case Hexa_J_JR_C_CALL_Pu_R152:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 21) & 0x01);	//not
		instr_struct->Operands[1].type = o_near;
		temp =
		    (((instr >> 1) & 0x7F) << 2) | (((instr >> 13) & 0x01) << 9)
		    | (((instr >> 16) & 0x1F) << 10) | (((instr >> 22) & 0x03)
							<< 15);
		if (temp & (1 << 16)) {
			temp |= (0xFFFFFFFF << 16);
		}		// sign extension
		instr_struct->Operands[1].addr = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// if (R XYZ) JUMP R13:2
	case Hexa_J_JR_C_differ_Rs_JUMP_R132:
	case Hexa_J_JR_C_lower_Rs_JUMP_R132:
	case Hexa_J_JR_C_equal_Rs_JUMP_R132:
	case Hexa_J_JR_C_greater_Rs_JUMP_R132:
		if ((instr >> 12) & 0x01) {
			instr_struct->auxpref = 1;	//t
		} else {
			instr_struct->auxpref = 2;	//nt
		}
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_near;
		temp =
		    (((instr >> 1) & 0x07FF) << 2) | (((instr >> 13) & 0x01) <<
						      13) | (((instr >> 21) &
							      0x01) << 14);
		if (temp & (1 << 14)) {
			temp |= (0xFFFFFFFF << 14);
		}		// sign extension
		instr_struct->Operands[1].addr = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// 1 operande
		// XYZ R
	case Hexa_J_JR_CALLR_Rs:
	case Hexa_J_JR_HINTJ_Rs:
	case Hexa_J_JR_JUMPR_Rs:
	case Hexa_SYSTEM_DCZEROA_Rs:
	case Hexa_SYSTEM_DCINVA_Rs:
	case Hexa_SYSTEM_DCCLEANA_Rs:
	case Hexa_SYSTEM_DCCLEANINVA_Rs:
	case Hexa_SYSTEM_ICINVA_Rs:
	case Hexa_SYSTEM_TRACE_Rs:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ R22:2
	case Hexa_J_JR_CALL_R222:
	case Hexa_J_JR_JUMP_R222:
		instr_struct->Operands[0].type = o_near;
		temp =
		    (((instr >> 1) & 0x1FFF) | (((instr >> 16) & 0x01FF) << 13))
		    << 2;
		if (temp & (1 << 24)) {
			temp |= (0xFFFFFFFF << 24);
		}		// sign extension
		instr_struct->Operands[0].addr = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// if (P) DEALLOC_RETURN
	case Hexa_LD_C_DEALLOC_RETURN_Ps:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x03);
		switch ((instr >> 11) & 0x07) {
		case 0x01:
			instr_struct->Operands[0].specval |= 0x02;	//new
			instr_struct->auxpref = 2;	//nt
			break;
		case 0x02:
			break;
		case 0x03:
			instr_struct->Operands[0].specval |= 0x02;	//new
			instr_struct->auxpref = 1;	//t
			break;
		case 0x05:
			instr_struct->Operands[0].specval |= 0x03;	//new+not
			instr_struct->auxpref = 2;	//nt
			break;
		case 0x06:
			instr_struct->Operands[0].specval |= 0x01;	//not
			break;
		case 0x07:
			instr_struct->Operands[0].specval |= 0x03;	//new+not
			instr_struct->auxpref = 1;	//t
			break;
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(U8)
	case Hexa_SYSTEM_PAUSE_U8:
	case Hexa_SYSTEM_TRAP0_U8:
	case Hexa_SYSTEM_TRAP1_U8:
		instr_struct->Operands[0].type = o_imm;
		instr_struct->Operands[0].value =
		    ((instr >> 2) & 0x07) | (((instr >> 8) & 0x1F) << 3);
		setDestinationRegister(instr_struct, -1);
		break;

		// 0 operande
		// XYZ 
	case Hexa_ALU32_NOP:
	case Hexa_LD_DEALLOCFRAME:
	case Hexa_LD_DEALLOC_RETURN:
	case Hexa_SYSTEM_BARRIER:
	case Hexa_SYSTEM_BRKPT:
	case Hexa_SYSTEM_ISYNC:
	case Hexa_SYSTEM_SYNCHT:
		// nothing to do
		setDestinationRegister(instr_struct, -1);
		break;

		// LD
		// R = XYZ (R+R<<U2)
	case Hexa_LD_MEMD_Rdd_Rs_Rt_U2:
	case Hexa_LD_MEMW_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMH_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMB_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMUH_Rd_Rs_Rt_U2:
	case Hexa_LD_MEMUB_Rd_Rs_Rt_U2:
		if (id == Hexa_LD_MEMD_Rdd_Rs_Rt_U2) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 7) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) R = XYZ (R+R<<U2)
	case Hexa_LD_C_MEMD_Rdd_Rs_Rt_U2:
	case Hexa_LD_C_MEMW_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMH_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMB_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMUH_Rd_Rs_Rt_U2:
	case Hexa_LD_C_MEMUB_Rd_Rs_Rt_U2:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 24) & 0x03);	//new+!
		if (id == Hexa_LD_C_MEMD_Rdd_Rs_Rt_U2) {
			instr_struct->Operands[1].type = o_R64;
		} else {
			instr_struct->Operands[1].type = o_reg;
		}
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[4].type = o_imm;
		temp = ((instr >> 7) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[4].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R=XYZ(GP+U16:X)
	case Hexa_LD_MEMB_Rd_GP_U160:
	case Hexa_LD_MEMUB_Rd_GP_U160:
	case Hexa_LD_MEMH_Rd_GP_U161:
	case Hexa_LD_MEMUH_Rd_GP_U161:
	case Hexa_LD_MEMW_Rd_GP_U162:
	case Hexa_LD_MEMD_Rdd_GP_U163:
		if (id == Hexa_LD_MEMD_Rdd_GP_U163) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp =
		    ((instr >> 5) & 0x01FF) | (((instr >> 16) & 0x01F) << 9) |
		    (((instr >> 25) & 0x03) << 14);
		switch (id) {
		case Hexa_LD_MEMH_Rd_GP_U161:
		case Hexa_LD_MEMUH_Rd_GP_U161:
			temp <<= 1;
			break;
		case Hexa_LD_MEMW_Rd_GP_U162:
			temp <<= 2;
			break;
		case Hexa_LD_MEMD_Rdd_GP_U163:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[1].value = temp;
		setDestinationRegister(instr_struct, -1);
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
		if ((id == Hexa_LD_MEMD_Rdd_Rs_S113) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rs_S111) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rs_S110) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rs_S112) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rs_S112)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x01FF) | (((instr >> 25) & 0x03) << 9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		switch (id) {
		case Hexa_LD_MEMH_Rd_Rs_S111:
		case Hexa_LD_MEMUH_Rd_Rs_S111:
		case Hexa_LD_MEMH_FIFO_Ryy_Rs_S111:
		case Hexa_LD_MEMBH_Rd_Rs_S111:
		case Hexa_LD_MEMUBH_Rd_Rs_S111:
			temp <<= 1;
			break;
		case Hexa_LD_MEMW_Rd_Rs_S112:
		case Hexa_LD_MEMBH_Rdd_Rs_S112:
		case Hexa_LD_MEMUBH_Rdd_Rs_S112:
			temp <<= 2;
			break;
		case Hexa_LD_MEMD_Rdd_Rs_S113:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) R=XYZ(R+U6:X)
	case Hexa_LD_C_MEMD_Rdd_Rs_U63:
	case Hexa_LD_C_MEMW_Rd_Rs_U62:
	case Hexa_LD_C_MEMH_Rd_Rs_U61:
	case Hexa_LD_C_MEMUH_Rd_Rs_U61:
	case Hexa_LD_C_MEMB_Rd_Rs_U60:
	case Hexa_LD_C_MEMUB_Rd_Rs_U60:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 11) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 26) & 0x01) | ((instr >> 24) & 0x02);	//new+!
		if (id == Hexa_LD_C_MEMD_Rdd_Rs_U63) {
			instr_struct->Operands[1].type = o_R64;
		} else {
			instr_struct->Operands[1].type = o_reg;
		}
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 5) & 0x03F);
		switch (id) {
		case Hexa_LD_C_MEMH_Rd_Rs_U61:
		case Hexa_LD_C_MEMUH_Rd_Rs_U61:
			temp <<= 1;
			break;
		case Hexa_LD_C_MEMW_Rd_Rs_U62:
			temp <<= 2;
			break;
		case Hexa_LD_C_MEMD_Rdd_Rs_U63:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
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
		if ((id == Hexa_LD_MEMD_Rdd_Rx_S43_circ_Mu) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rx_S41_circ_Mu) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rx_S40_circ_Mu) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rx_S42_circ_Mu) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rx_S42_circ_Mu)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_LD_MEMH_Rd_Rx_S41_circ_Mu:
		case Hexa_LD_MEMUH_Rd_Rx_S41_circ_Mu:
		case Hexa_LD_MEMH_FIFO_Ryy_Rx_S41_circ_Mu:
		case Hexa_LD_MEMBH_Rd_Rx_S41_circ_Mu:
		case Hexa_LD_MEMUBH_Rd_Rx_S41_circ_Mu:
			temp <<= 1;
			break;
		case Hexa_LD_MEMW_Rd_Rx_S42_circ_Mu:
		case Hexa_LD_MEMBH_Rdd_Rx_S42_circ_Mu:
		case Hexa_LD_MEMUBH_Rdd_Rx_S42_circ_Mu:
			temp <<= 2;
			break;
		case Hexa_LD_MEMD_Rdd_Rx_S43_circ_Mu:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_CR;
		instr_struct->Operands[3].specval |= 0x02;
		instr_struct->Operands[3].reg = ((instr >> 13) & 0x01);
		setDestinationRegister(instr_struct, -1);
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
		if ((id == Hexa_LD_MEMD_Rdd_Rx_circ_Mu) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rx_circ_Mu) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rx_circ_Mu) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rx_circ_Mu) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rx_circ_Mu)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_CR;
		instr_struct->Operands[2].specval |= 0x02;
		instr_struct->Operands[2].reg = ((instr >> 13) & 0x01);
		setDestinationRegister(instr_struct, -1);
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
		if ((id == Hexa_LD_MEMD_Rdd_Re_U6) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Re_U6) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Re_U6) ||
		    (id == Hexa_LD_MEMBH_Rdd_Re_U6) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Re_U6)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x03) | (((instr >> 8) & 0x0F) << 2);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
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
		if ((id == Hexa_LD_MEMD_Rdd_Rx_S43) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rx_S40) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rx_S41) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rx_S42) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rx_S42)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 5) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_LD_MEMH_Rd_Rx_S41:
		case Hexa_LD_MEMUH_Rd_Rx_S41:
		case Hexa_LD_MEMH_FIFO_Ryy_Rx_S41:
		case Hexa_LD_MEMBH_Rd_Rx_S41:
		case Hexa_LD_MEMUBH_Rd_Rx_S41:
			temp <<= 1;
			break;
		case Hexa_LD_MEMW_Rd_Rx_S42:
		case Hexa_LD_MEMBH_Rdd_Rx_S42:
		case Hexa_LD_MEMUBH_Rdd_Rx_S42:
			temp <<= 2;
			break;
		case Hexa_LD_MEMD_Rdd_Rx_S43:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
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
		if ((id == Hexa_LD_MEMD_Rdd_Rt_U2_U6) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rt_U2_U6) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rt_U2_U6) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rt_U2_U6) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rt_U2_U6)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 7) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 5) & 0x03) | (((instr >> 8) & 0x0F) << 2);
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// R=XYZ(R++Mu{ |:brev})
	case Hexa_LD_MEMD_Rdd_Rx_Mu:
	case Hexa_LD_MEMD_Rdd_Rx_Mu_brev:
	case Hexa_LD_MEMW_Rd_Rx_Mu:
	case Hexa_LD_MEMW_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMH_Rd_Rx_Mu:
	case Hexa_LD_MEMH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMUH_Rd_Rx_Mu:
	case Hexa_LD_MEMUH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMB_Rd_Rx_Mu:
	case Hexa_LD_MEMB_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMUB_Rd_Rx_Mu:
	case Hexa_LD_MEMUB_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu:
	case Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu_brev:
	case Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu_brev:
	case Hexa_LD_MEMBH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMUBH_Rd_Rx_Mu_brev:
	case Hexa_LD_MEMBH_Rdd_Rx_Mu_brev:
	case Hexa_LD_MEMUBH_Rdd_Rx_Mu_brev:
	case Hexa_LD_MEMBH_Rd_Rx_Mu:
	case Hexa_LD_MEMUBH_Rd_Rx_Mu:
	case Hexa_LD_MEMBH_Rdd_Rx_Mu:
	case Hexa_LD_MEMUBH_Rdd_Rx_Mu:
		if ((id == Hexa_LD_MEMD_Rdd_Rx_Mu) ||
		    (id == Hexa_LD_MEMD_Rdd_Rx_Mu_brev) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu) ||
		    (id == Hexa_LD_MEMB_FIFO_Ryy_Rx_Mu_brev) ||
		    (id == Hexa_LD_MEMH_FIFO_Ryy_Rx_Mu_brev) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rx_Mu_brev) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rx_Mu_brev) ||
		    (id == Hexa_LD_MEMBH_Rdd_Rx_Mu) ||
		    (id == Hexa_LD_MEMUBH_Rdd_Rx_Mu)) {
			instr_struct->Operands[0].type = o_R64;
		} else {
			instr_struct->Operands[0].type = o_reg;
		}
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_CR;
		instr_struct->Operands[2].specval |= 0x02;
		instr_struct->Operands[2].reg = ((instr >> 13) & 0x01);
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) R=XYZ(R++S4:X)
	case Hexa_LD_C_MEMD_Rdd_Rx_S43:
	case Hexa_LD_C_MEMW_Rd_Rx_S42:
	case Hexa_LD_C_MEMH_Rd_Rx_S41:
	case Hexa_LD_C_MEMUH_Rd_Rx_S41:
	case Hexa_LD_C_MEMB_Rd_Rx_S40:
	case Hexa_LD_C_MEMUB_Rd_Rx_S40:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 9) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 11) & 0x03);	//new+!
		if (id == Hexa_LD_C_MEMD_Rdd_Rx_S43) {
			instr_struct->Operands[1].type = o_R64;
		} else {
			instr_struct->Operands[1].type = o_reg;
		}
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 5) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_LD_C_MEMH_Rd_Rx_S41:
		case Hexa_LD_C_MEMUH_Rd_Rx_S41:
			temp <<= 1;
			break;
		case Hexa_LD_C_MEMW_Rd_Rx_S42:
			temp <<= 2;
			break;
		case Hexa_LD_C_MEMD_Rdd_Rx_S43:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) R=XYZ(U6)
	case Hexa_LD_C_MEMD_Rdd_U6:
	case Hexa_LD_C_MEMW_Rd_U6:
	case Hexa_LD_C_MEMH_Rd_U6:
	case Hexa_LD_C_MEMUH_Rd_U6:
	case Hexa_LD_C_MEMB_Rd_U6:
	case Hexa_LD_C_MEMUB_Rd_U6:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 9) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 11) & 0x03);	//new+!
		if (id == Hexa_LD_C_MEMD_Rdd_U6) {
			instr_struct->Operands[1].type = o_R64;
		} else {
			instr_struct->Operands[1].type = o_reg;
		}
		instr_struct->Operands[1].reg = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 8) & 0x01) | (((instr >> 16) & 0x01F) << 1);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// MEMOP 
	case Hexa_MEMOP_MEMB_Rs_U60_plus_Rt:
	case Hexa_MEMOP_MEMB_Rs_U60_less_Rt:
	case Hexa_MEMOP_MEMB_Rs_U60_or_Rt:
	case Hexa_MEMOP_MEMB_Rs_U60_and_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_plus_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_less_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_or_Rt:
	case Hexa_MEMOP_MEMH_Rs_U61_and_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_plus_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_less_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_or_Rt:
	case Hexa_MEMOP_MEMW_Rs_U62_and_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 7) & 0x03F);
		switch (id) {
		case Hexa_MEMOP_MEMH_Rs_U61_plus_Rt:
		case Hexa_MEMOP_MEMH_Rs_U61_less_Rt:
		case Hexa_MEMOP_MEMH_Rs_U61_or_Rt:
		case Hexa_MEMOP_MEMH_Rs_U61_and_Rt:
			temp <<= 1;
			break;
		case Hexa_MEMOP_MEMW_Rs_U62_plus_Rt:
		case Hexa_MEMOP_MEMW_Rs_U62_less_Rt:
		case Hexa_MEMOP_MEMW_Rs_U62_or_Rt:
		case Hexa_MEMOP_MEMW_Rs_U62_and_Rt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 0) & 0x1F);
		setDestinationRegister(instr_struct, -1);
		break;

	case Hexa_MEMOP_MEMB_Rs_U60_CLRBIT_U5:
	case Hexa_MEMOP_MEMB_Rs_U60_SETBIT_U5:
	case Hexa_MEMOP_MEMB_Rs_U60_plus_U5:
	case Hexa_MEMOP_MEMB_Rs_U60_less_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_CLRBIT_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_SETBIT_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_plus_U5:
	case Hexa_MEMOP_MEMH_Rs_U61_less_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_CLRBIT_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_SETBIT_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_plus_U5:
	case Hexa_MEMOP_MEMW_Rs_U62_less_U5:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 7) & 0x03F);
		switch (id) {
		case Hexa_MEMOP_MEMH_Rs_U61_CLRBIT_U5:
		case Hexa_MEMOP_MEMH_Rs_U61_SETBIT_U5:
		case Hexa_MEMOP_MEMH_Rs_U61_plus_U5:
		case Hexa_MEMOP_MEMH_Rs_U61_less_U5:
			temp <<= 1;
			break;
		case Hexa_MEMOP_MEMW_Rs_U62_CLRBIT_U5:
		case Hexa_MEMOP_MEMW_Rs_U62_SETBIT_U5:
		case Hexa_MEMOP_MEMW_Rs_U62_plus_U5:
		case Hexa_MEMOP_MEMW_Rs_U62_less_U5:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 0) & 0x1F);
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// ST
		// XYZ (R+R<<U2)=R
	case Hexa_ST_MEMD_Rs_Ru_U2_Rtt:
	case Hexa_ST_MEMW_Rs_Ru_U2_Rt:
	case Hexa_ST_MEMH_Rs_Ru_U2_Rt:
	case Hexa_ST_MEMB_Rs_Ru_U2_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 7) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[2].value = temp;
		if (id == Hexa_ST_MEMD_Rs_Ru_U2_Rtt) {
			instr_struct->Operands[3].type = o_R64;
		} else {
			instr_struct->Operands[3].type = o_reg;
		}
		instr_struct->Operands[3].reg = ((instr >> 0) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[3].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R+U6:X)=S8
	case Hexa_ST_MEMW_Rs_U62_S8:
	case Hexa_ST_MEMH_Rs_U61_S8:
	case Hexa_ST_MEMB_Rs_U60_S8:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 7) & 0x03F);
		switch (id) {
		case Hexa_ST_MEMH_Rs_U61_S8:
			temp <<= 1;
			break;
		case Hexa_ST_MEMW_Rs_U62_S8:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 0) & 0x07F) | (((instr >> 13) & 0x01) << 7);
		if (temp & (1 << 7)) {
			temp |= (0xFFFFFFFF << 7);
		}		// sign extension
		instr_struct->Operands[2].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(GP+U16:X)=R
	case Hexa_ST_MEMD_GP_U163_Rtt:
	case Hexa_ST_MEMW_GP_U162_Rt:
	case Hexa_ST_MEMH_GP_U161_Rt:
	case Hexa_ST_MEMB_GP_U160_Rt:
		instr_struct->Operands[0].type = o_imm;
		temp = ((instr >> 0) & 0x0FF) | (((instr >> 13) & 0x01) << 8)
		    | (((instr >> 16) & 0x01F) << 9) | (((instr >> 25) & 0x03)
							<< 14);
		switch (id) {
		case Hexa_ST_MEMH_GP_U161_Rt:
			temp <<= 1;
			break;
		case Hexa_ST_MEMW_GP_U162_Rt:
			temp <<= 2;
			break;
		case Hexa_ST_MEMD_GP_U163_Rtt:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[0].value = temp;
		if (id == Hexa_ST_MEMD_GP_U163_Rtt) {
			instr_struct->Operands[1].type = o_R64;
		} else {
			instr_struct->Operands[1].type = o_reg;
		}
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[1].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R+S11:X)=R
	case Hexa_ST_MEMD_Rs_S113_Rtt:
	case Hexa_ST_MEMW_Rs_S112_Rt:
	case Hexa_ST_MEMH_Rs_S111_Rt:
	case Hexa_ST_MEMB_Rs_S110_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 0) & 0x0FF) | (((instr >> 13) & 0x01) << 8)
		    | (((instr >> 25) & 0x03) << 9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		switch (id) {
		case Hexa_ST_MEMH_Rs_S111_Rt:
			temp <<= 1;
			break;
		case Hexa_ST_MEMW_Rs_S112_Rt:
			temp <<= 2;
			break;
		case Hexa_ST_MEMD_Rs_S113_Rtt:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[1].value = temp;
		if (id == Hexa_ST_MEMD_Rs_S113_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R++I:circ(Mu))=R
	case Hexa_ST_MEMD_Rx_circ_Mu_Rtt:
	case Hexa_ST_MEMW_Rx_circ_Mu_Rt:
	case Hexa_ST_MEMH_Rx_circ_Mu_Rt:
	case Hexa_ST_MEMB_Rx_circ_Mu_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_CR;
		instr_struct->Operands[1].specval |= 0x02;
		instr_struct->Operands[1].reg = ((instr >> 13) & 0x01);
		if (id == Hexa_ST_MEMD_Rx_circ_Mu_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R++S4:X:circ(Mu))=R
	case Hexa_ST_MEMD_Rx_S43_circ_Mu_Rtt:
	case Hexa_ST_MEMW_Rx_S42_circ_Mu_Rt:
	case Hexa_ST_MEMH_Rx_S41_circ_Mu_Rt:
	case Hexa_ST_MEMB_Rx_S40_circ_Mu_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 3) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_ST_MEMH_Rx_S41_circ_Mu_Rt:
			temp <<= 1;
			break;
		case Hexa_ST_MEMW_Rx_S42_circ_Mu_Rt:
			temp <<= 2;
			break;
		case Hexa_ST_MEMD_Rx_S43_circ_Mu_Rtt:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_CR;
		instr_struct->Operands[2].specval |= 0x02;
		instr_struct->Operands[2].reg = ((instr >> 13) & 0x01);
		if (id == Hexa_ST_MEMD_Rx_S43_circ_Mu_Rtt) {
			instr_struct->Operands[3].type = o_R64;
		} else {
			instr_struct->Operands[3].type = o_reg;
		}
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[3].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R=U6)=R
	case Hexa_ST_MEMD_Re_U6_Rtt:
	case Hexa_ST_MEMW_Re_U6_Rt:
	case Hexa_ST_MEMH_Re_U6_Rt:
	case Hexa_ST_MEMB_Re_U6_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 0) & 0x03F);
		instr_struct->Operands[1].value = temp;
		if (id == Hexa_ST_MEMD_Re_U6_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R++S4:X)=R
	case Hexa_ST_MEMD_Rx_S43_Rtt:
	case Hexa_ST_MEMW_Rx_S42_Rt:
	case Hexa_ST_MEMH_Rx_S41_Rt:
	case Hexa_ST_MEMB_Rx_S40_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 3) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_ST_MEMH_Rx_S41_Rt:
			temp <<= 1;
			break;
		case Hexa_ST_MEMW_Rx_S42_Rt:
			temp <<= 2;
			break;
		case Hexa_ST_MEMD_Rx_S43_Rtt:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[1].value = temp;
		if (id == Hexa_ST_MEMD_Rx_S43_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R<<U2+U6)=R
	case Hexa_ST_MEMD_Ru_U2_U6_Rtt:
	case Hexa_ST_MEMW_Ru_U2_U6_Rt:
	case Hexa_ST_MEMH_Ru_U2_U6_Rt:
	case Hexa_ST_MEMB_Ru_U2_U6_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 6) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 0) & 0x3F);
		instr_struct->Operands[2].value = temp;
		if (id == Hexa_ST_MEMD_Ru_U2_U6_Rtt) {
			instr_struct->Operands[3].type = o_R64;
		} else {
			instr_struct->Operands[3].type = o_reg;
		}
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[3].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R++Mu)=R
	case Hexa_ST_MEMD_Rx_Mu_Rtt:
	case Hexa_ST_MEMW_Rx_Mu_Rt:
	case Hexa_ST_MEMH_Rx_Mu_Rt:
	case Hexa_ST_MEMB_Rx_Mu_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_CR;
		instr_struct->Operands[1].specval |= 0x02;
		instr_struct->Operands[1].reg = ((instr >> 13) & 0x01);
		if (id == Hexa_ST_MEMD_Rx_Mu_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// XYZ(R++Mu:brev)=R
	case Hexa_ST_MEMD_Rx_Mu_brev_Rtt:
	case Hexa_ST_MEMW_Rx_Mu_brev_Rt:
	case Hexa_ST_MEMH_Rx_Mu_brev_Rt:
	case Hexa_ST_MEMB_Rx_Mu_brev_Rt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_CR;
		instr_struct->Operands[1].specval |= 0x02;
		instr_struct->Operands[1].reg = ((instr >> 13) & 0x01);
		if (id == Hexa_ST_MEMD_Rx_Mu_brev_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) XYZ (R+R<<U2) = R
	case Hexa_ST_C_MEMD_Rs_Rt_U2_Rtt:
	case Hexa_ST_C_MEMW_Rs_Rt_U2_Rt:
	case Hexa_ST_C_MEMH_Rs_Rt_U2_Rt:
	case Hexa_ST_C_MEMB_Rs_Rt_U2_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 24) & 0x03);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 7) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[3].value = temp;
		if (id == Hexa_ST_C_MEMD_Rs_Rt_U2_Rtt) {
			instr_struct->Operands[4].type = o_R64;
		} else {
			instr_struct->Operands[4].type = o_reg;
		}
		instr_struct->Operands[4].reg = ((instr >> 0) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[4].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) XYZ (R+U6:X)=S6
	case Hexa_ST_C_MEMW_Rs_U62_S6:
	case Hexa_ST_C_MEMH_Rs_U61_S6:
	case Hexa_ST_C_MEMB_Rs_U60_S6:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 23) & 0x03);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 7) & 0x03F);
		switch (id) {
		case Hexa_ST_C_MEMH_Rs_U61_S6:
			temp <<= 1;
			break;
		case Hexa_ST_C_MEMW_Rs_U62_S6:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_imm;
		temp = ((instr >> 0) & 0x1F) | (((instr >> 13) & 0x01) << 5);	// sign extension
		instr_struct->Operands[3].value = temp;
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) XYZ(R++U6:X)=R
	case Hexa_ST_C_MEMD_Rs_U63_Rtt:
	case Hexa_ST_C_MEMW_Rs_U62_Rt:
	case Hexa_ST_C_MEMH_Rs_U61_Rt:
	case Hexa_ST_C_MEMB_Rs_U60_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 26) & 0x01) | (((instr >> 25) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 3) & 0x01F) | (((instr >> 13) & 0x01) << 5);
		switch (id) {
		case Hexa_ST_C_MEMH_Rs_U61_Rt:
			temp <<= 1;
			break;
		case Hexa_ST_C_MEMW_Rs_U62_Rt:
			temp <<= 2;
			break;
		case Hexa_ST_C_MEMD_Rs_U63_Rtt:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[2].value = temp;
		if (id == Hexa_ST_C_MEMD_Rs_U63_Rtt) {
			instr_struct->Operands[3].type = o_R64;
		} else {
			instr_struct->Operands[3].type = o_reg;
		}
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[3].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) XYZ(R++S4:X)=R
	case Hexa_ST_C_MEMD_Rx_S43_Rtt:
	case Hexa_ST_C_MEMW_Rx_S42_Rt:
	case Hexa_ST_C_MEMH_Rx_S41_Rt:
	case Hexa_ST_C_MEMB_Rx_S40_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 2) & 0x01) | (((instr >> 7) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 3) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_ST_C_MEMH_Rx_S41_Rt:
			temp <<= 1;
			break;
		case Hexa_ST_C_MEMW_Rx_S42_Rt:
			temp <<= 2;
			break;
		case Hexa_ST_C_MEMD_Rx_S43_Rtt:
			temp <<= 3;
			break;
		}
		instr_struct->Operands[2].value = temp;
		if (id == Hexa_ST_C_MEMD_Rx_S43_Rtt) {
			instr_struct->Operands[3].type = o_R64;
		} else {
			instr_struct->Operands[3].type = o_reg;
		}
		instr_struct->Operands[3].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[3].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

		// IF (P) XYZ(U6)=R
	case Hexa_ST_C_MEMD_U6_Rtt:
	case Hexa_ST_C_MEMW_U6_Rt:
	case Hexa_ST_C_MEMH_U6_Rt:
	case Hexa_ST_C_MEMB_U6_Rt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 2) & 0x01) | (((instr >> 13) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 3) & 0x0F) | (((instr >> 16) & 0x03) << 4);
		instr_struct->Operands[1].value = temp;
		if (id == Hexa_ST_C_MEMD_U6_Rtt) {
			instr_struct->Operands[2].type = o_R64;
		} else {
			instr_struct->Operands[2].type = o_reg;
		}
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		if ((instr >> 21) & 0x01) {
			instr_struct->Operands[2].specval |= 1;	// .H
		}
		setDestinationRegister(instr_struct, -1);
		break;

	case Hexa_ST_ALLOCFRAME_U113:
		instr_struct->Operands[0].type = o_imm;
		instr_struct->Operands[0].value =
		    (((instr >> 0) & 0x07FF) << 3);
		setDestinationRegister(instr_struct, -1);
		break;

	case Hexa_CONST_EXT:
		instr_struct->Operands[0].type = o_imm;
		instr_struct->Operands[0].value =
		    ((instr & 0x3FFF) | (((instr >> 16) & 0x0FFF) << 14)) << 6;
		instr_struct->Operands[0].specval = 1;
		if (instr_struct == &cmd) {
			setDestinationRegister(instr_struct, -1);
		}
		break;

		// NV
	case Hexa_NV_MEMB_Rs_Ru_U2_Nt:
	case Hexa_NV_MEMH_Rs_Ru_U2_Nt:
	case Hexa_NV_MEMW_Rs_Ru_U2_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 7) & 0x1) | (((instr >> 13) & 0x1) << 1);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg =
		    getNewValueRegister(((instr >> 0) & 0x07));
		break;

	case Hexa_NV_MEMB_GP_U160_Nt:
	case Hexa_NV_MEMH_GP_U161_Nt:
	case Hexa_NV_MEMW_GP_U162_Nt:
		instr_struct->Operands[0].type = o_imm;
		temp = ((instr >> 0) & 0xFF)
		    | (((instr >> 13) & 0x01) << 8)
		    | (((instr >> 16) & 0x1F) << 9)
		    | (((instr >> 25) & 0x03) << 14);
		switch (id) {
		case Hexa_NV_MEMH_GP_U161_Nt:
			temp <<= 1;
			break;
		case Hexa_NV_MEMW_GP_U162_Nt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[0].value = temp;
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_MEMB_Rs_S110_Nt:
	case Hexa_NV_MEMH_Rs_S111_Nt:
	case Hexa_NV_MEMW_Rs_S112_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 0) & 0xFF)
		    | (((instr >> 13) & 0x01) << 8)
		    | (((instr >> 25) & 0x03) << 9);
		if (temp & (1 << 10)) {
			temp |= (0xFFFFFFFF << 10);
		}		// sign extension
		switch (id) {
		case Hexa_NV_MEMH_Rs_S111_Nt:
			temp <<= 1;
			break;
		case Hexa_NV_MEMW_Rs_S112_Nt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_MEMB_Rx_circ_Mu_Nt:
	case Hexa_NV_MEMH_Rx_circ_Mu_Nt:
	case Hexa_NV_MEMW_Rx_circ_Mu_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_CR;
		instr_struct->Operands[1].specval |= 0x02;
		instr_struct->Operands[1].reg = ((instr >> 13) & 0x01);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_MEMB_Rx_S40_circ_Mu_Nt:
	case Hexa_NV_MEMH_Rx_S41_circ_Mu_Nt:
	case Hexa_NV_MEMW_Rx_S42_circ_Mu_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 3) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_NV_MEMH_Rx_S41_circ_Mu_Nt:
			temp <<= 1;
			break;
		case Hexa_NV_MEMW_Rx_S42_circ_Mu_Nt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_CR;
		instr_struct->Operands[2].specval |= 0x02;
		instr_struct->Operands[2].reg = ((instr >> 13) & 0x01);
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg =
		    getNewValueRegister(((instr >> 0) & 0x07));
		break;

	case Hexa_NV_MEMB_Re_U6_Nt:
	case Hexa_NV_MEMH_Re_U6_Nt:
	case Hexa_NV_MEMW_Re_U6_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 0) & 0x3F);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_MEMB_Rx_S40_Nt:
	case Hexa_NV_MEMH_Rx_S41_Nt:
	case Hexa_NV_MEMW_Rx_S42_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 3) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_NV_MEMH_Rx_S41_Nt:
			temp <<= 1;
			break;
		case Hexa_NV_MEMW_Rx_S42_Nt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_MEMB_Ru_U2_U6_Nt:
	case Hexa_NV_MEMH_Ru_U2_U6_Nt:
	case Hexa_NV_MEMW_Ru_U2_U6_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 6) & 0x1) | (((instr >> 13) & 0x1) << 1);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 0) & 0x3F);
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_MEMB_Rx_Mu_Nt:
	case Hexa_NV_MEMH_Rx_Mu_Nt:
	case Hexa_NV_MEMW_Rx_Mu_Nt:
	case Hexa_NV_MEMB_Rx_Mu_brev_Nt:
	case Hexa_NV_MEMH_Rx_Mu_brev_Nt:
	case Hexa_NV_MEMW_Rx_Mu_brev_Nt:
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[1].type = o_CR;
		instr_struct->Operands[1].specval |= 0x02;
		instr_struct->Operands[1].reg = ((instr >> 13) & 0x01);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_C_MEMB_Rs_Ru_U2_Nt:
	case Hexa_NV_C_MEMH_Rs_Ru_U2_Nt:
	case Hexa_NV_C_MEMW_Rs_Ru_U2_Nt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 5) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 24) & 0x01) | (((instr >> 25) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[3].type = o_imm;
		instr_struct->Operands[3].value =
		    ((instr >> 7) & 0x01) | (((instr >> 13) & 0x01) << 1);
		instr_struct->Operands[4].type = o_reg;
		instr_struct->Operands[4].reg =
		    getNewValueRegister(((instr >> 0) & 0x07));
		break;

	case Hexa_NV_C_MEMB_Rs_U60_Nt:
	case Hexa_NV_C_MEMH_Rs_U61_Nt:
	case Hexa_NV_C_MEMW_Rs_U62_Nt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 25) & 0x01) | (((instr >> 26) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 3) & 0x1F) | (((instr >> 13) & 0x01) << 5);
		switch (id) {
		case Hexa_NV_C_MEMH_Rs_U61_Nt:
			temp <<= 1;
			break;
		case Hexa_NV_C_MEMW_Rs_U62_Nt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_C_MEMB_Rx_S40_Nt:
	case Hexa_NV_C_MEMH_Rx_S41_Nt:
	case Hexa_NV_C_MEMW_Rx_S42_Nt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 2) & 0x01) | (((instr >> 7) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 16) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 3) & 0x0F);
		if (temp & (1 << 3)) {
			temp |= (0xFFFFFFFF << 3);
		}		// sign extension
		switch (id) {
		case Hexa_NV_C_MEMH_Rx_S41_Nt:
			temp <<= 1;
			break;
		case Hexa_NV_C_MEMW_Rx_S42_Nt:
			temp <<= 2;
			break;
		}
		instr_struct->Operands[2].value = temp;
		instr_struct->Operands[3].type = o_reg;
		instr_struct->Operands[3].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_C_MEMB_U6_Nt:
	case Hexa_NV_C_MEMH_U6_Nt:
	case Hexa_NV_C_MEMW_U6_Nt:
		instr_struct->Operands[0].type = o_PR;
		instr_struct->Operands[0].reg = ((instr >> 0) & 0x03);
		instr_struct->Operands[0].specval |= ((instr >> 2) & 0x01) | (((instr >> 13) & 0x01) << 1);	//new+!
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 3) & 0x0F) | (((instr >> 16) & 0x03) << 4);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_reg;
		instr_struct->Operands[2].reg =
		    getNewValueRegister(((instr >> 8) & 0x07));
		break;

	case Hexa_NV_C_JUMP_CMP_EQ_Ns_R92:
	case Hexa_NV_C_JUMP_CMP_GT_Ns_R92:
	case Hexa_NV_C_JUMP_CMP_TSTBIT_Ns_R92:
		if ((instr >> 13) & 0x01) {
			instr_struct->auxpref |= 1;
		} else {
			instr_struct->auxpref |= 2;
		}
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg =
		    getNewValueRegister(((instr >> 16) & 0x07));
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 1) & 0x7F) | (((instr >> 20) & 0x03) << 7);
		if (temp & (1 << 8)) {
			temp |= (0xFFFFFFFF << 8);
		}		// sign extension
		temp <<= 2;
		instr_struct->Operands[1].value = temp;
		break;

	case Hexa_NV_C_JUMP_CMP_EQ_Ns_U5_R92:
	case Hexa_NV_C_JUMP_CMP_GT_Ns_U5_R92:
	case Hexa_NV_C_JUMP_CMP_GTU_Ns_U5_R92:
		if ((instr >> 13) & 0x01) {
			instr_struct->auxpref |= 1;
		} else {
			instr_struct->auxpref |= 2;
		}
		instr_struct->auxpref |= ((instr >> 22) & 0x01) << 2;
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg =
		    getNewValueRegister(((instr >> 16) & 0x07));
		instr_struct->Operands[1].type = o_imm;
		temp = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].value = temp;
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 1) & 0x7F) | (((instr >> 20) & 0x03) << 7);
		if (temp & (1 << 8)) {
			temp |= (0xFFFFFFFF << 8);
		}		// sign extension
		temp <<= 2;
		instr_struct->Operands[2].value = temp;
		break;

	case Hexa_NV_C_JUMP_CMP_EQ_Ns_Rt_R92:
	case Hexa_NV_C_JUMP_CMP_GT_Ns_Rt_R92:
	case Hexa_NV_C_JUMP_CMP_GTU_Ns_Rs_R92:
		if ((instr >> 13) & 0x01) {
			instr_struct->auxpref |= 1;
		} else {
			instr_struct->auxpref |= 2;
		}
		instr_struct->auxpref |= ((instr >> 22) & 0x01) << 2;
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg =
		    getNewValueRegister(((instr >> 16) & 0x07));
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 1) & 0x7F) | (((instr >> 20) & 0x03) << 7);
		if (temp & (1 << 8)) {
			temp |= (0xFFFFFFFF << 8);
		}		// sign extension
		temp <<= 2;
		instr_struct->Operands[2].value = temp;
		break;

	case Hexa_NV_C_JUMP_CMP_GT_Rt_Ns_R92:
	case Hexa_NV_C_JUMP_CMP_GTU_Rs_Ns_R92:
		if ((instr >> 13) & 0x01) {
			instr_struct->auxpref |= 1;
		} else {
			instr_struct->auxpref |= 2;
		}
		instr_struct->auxpref |= ((instr >> 22) & 0x01) << 2;
		instr_struct->Operands[0].type = o_reg;
		instr_struct->Operands[0].reg = ((instr >> 8) & 0x1F);
		instr_struct->Operands[1].type = o_reg;
		instr_struct->Operands[1].reg =
		    getNewValueRegister(((instr >> 16) & 0x07));
		instr_struct->Operands[2].type = o_imm;
		temp = ((instr >> 1) & 0x7F) | (((instr >> 20) & 0x03) << 7);
		if (temp & (1 << 8)) {
			temp |= (0xFFFFFFFF << 8);
		}		// sign extension
		temp <<= 2;
		instr_struct->Operands[2].value = temp;
		break;

	}

	if (instr_struct == &cmd) {
		// constant extensions
		switch (id) {
		case Hexa_CONST_EXT:
			constantExtender = instr_struct->Operands[0].value;
			break;

			// 1st operande extended
		case Hexa_ST_MEMB_GP_U160_Rt:
			extends(&instr_struct->Operands[0]);
			break;
		case Hexa_ST_MEMD_GP_U163_Rtt:
			extends(&instr_struct->Operands[0], 3);
			break;
		case Hexa_J_JR_CALL_R222:
		case Hexa_J_JR_JUMP_R222:
		case Hexa_ST_MEMW_GP_U162_Rt:
			extends(&instr_struct->Operands[0], 2);
			break;
		case Hexa_ST_MEMH_GP_U161_Rt:
			extends(&instr_struct->Operands[0], 1);
			break;

			// 2nd operande extended
		case Hexa_ALU32_TransferImm_Rd_s16:
		case Hexa_ALU32_COMBINE_Rdd_S8_Rs:
		case Hexa_ALU32_COMBINE_Rdd_S8_S8:
		case Hexa_ALU32_SUB_Rd_s10_Rs:
		case Hexa_ST_MEMD_Re_U6_Rtt:
		case Hexa_ST_MEMW_Re_U6_Rt:
		case Hexa_ST_MEMH_Re_U6_Rt:
		case Hexa_ST_MEMB_Re_U6_Rt:
		case Hexa_ST_MEMB_Rs_S110_Rt:
		case Hexa_ST_C_MEMD_U6_Rtt:
		case Hexa_ST_C_MEMW_U6_Rt:
		case Hexa_ST_C_MEMH_U6_Rt:
		case Hexa_ST_C_MEMB_U6_Rt:
		case Hexa_CR_ADD_Rd_Pc_U6:
		case Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_U6:
		case Hexa_XTYPE_MPY_ADD_Rd_U6_MPYI_Rs_Rt:
		case Hexa_XTYPE_PRED_ADD_Rx_U8_ASL_Rx_U5:
		case Hexa_XTYPE_PRED_ADD_Rx_U8_LSR_Rx_U5:
		case Hexa_XTYPE_PRED_SUB_Rx_U8_ASL_Rx_U5:
		case Hexa_XTYPE_PRED_SUB_Rx_U8_LSR_Rx_U5:
		case Hexa_XTYPE_PRED_AND_Rx_U8_ASL_Rx_U5:
		case Hexa_XTYPE_PRED_AND_Rx_U8_LSR_Rx_U5:
		case Hexa_XTYPE_PRED_OR_Rx_U8_ASL_Rx_U5:
		case Hexa_XTYPE_PRED_OR_Rx_U8_LSR_Rx_U5:
		case Hexa_LD_MEMB_Rd_GP_U160:
		case Hexa_LD_MEMUB_Rd_GP_U160:
		case Hexa_NV_MEMB_Rs_S110_Nt:
		case Hexa_NV_MEMB_Re_U6_Nt:
		case Hexa_NV_MEMH_Re_U6_Nt:
		case Hexa_NV_MEMW_Re_U6_Nt:
		case Hexa_NV_C_MEMB_U6_Nt:
		case Hexa_NV_C_MEMH_U6_Nt:
		case Hexa_NV_C_MEMW_U6_Nt:
			extends(&instr_struct->Operands[1]);
			break;
		case Hexa_LD_MEMD_Rdd_GP_U163:
		case Hexa_ST_MEMD_Rs_S113_Rtt:
			extends(&instr_struct->Operands[1], 3);
			break;
		case Hexa_J_JR_C_CALL_Pu_R152:
		case Hexa_LD_MEMW_Rd_GP_U162:
		case Hexa_ST_MEMW_Rs_S112_Rt:
		case Hexa_CR_LOOP0_R72_U10:
		case Hexa_CR_LOOP1_R72_U10:
		case Hexa_NV_MEMW_Rs_S112_Nt:
		case Hexa_NV_C_JUMP_CMP_EQ_Ns_R92:
		case Hexa_NV_C_JUMP_CMP_GT_Ns_R92:
		case Hexa_NV_C_JUMP_CMP_TSTBIT_Ns_R92:
			extends(&instr_struct->Operands[1], 2);
			break;
		case Hexa_LD_MEMH_Rd_GP_U161:
		case Hexa_LD_MEMUH_Rd_GP_U161:
		case Hexa_ST_MEMH_Rs_S111_Rt:
		case Hexa_NV_MEMH_Rs_S111_Nt:
			extends(&instr_struct->Operands[1], 1);
			break;

			// 3rd operande extended
		case Hexa_ALU32_COMBINE_Rdd_S8_U6:
		case Hexa_ALU32_COMBINE_Rdd_Rs_S8:
		case Hexa_ALU32_MUX_Rd_Pu_S8_S8:
		case Hexa_ALU32_MUX_Rd_Pu_S8_Rs:
		case Hexa_ALU32_CMP_eq_Pu_Rs_S10:
		case Hexa_ALU32_not_CMP_eq_Pu_Rs_S10:
		case Hexa_ALU32_CMP_gt_Pu_Rs_S10:
		case Hexa_ALU32_not_CMP_gt_Pu_Rs_S10:
		case Hexa_ALU32_CMP_gtu_Pu_Rs_U9:
		case Hexa_ALU32_not_CMP_gtu_Pu_Rs_U9:
		case Hexa_ALU32_CMP_eq_Rd_Rs_S8:
		case Hexa_ALU32_not_CMP_eq_Rd_Rs_S8:
		case Hexa_ALU32_AND_Rd_Rs_s10:
		case Hexa_ALU32_OR_Rd_Rs_s10:
		case Hexa_ALU32_ADD_Rd_Rs_s16:
		case Hexa_LD_C_MEMD_Rdd_U6:
		case Hexa_LD_C_MEMW_Rd_U6:
		case Hexa_LD_C_MEMH_Rd_U6:
		case Hexa_LD_C_MEMUH_Rd_U6:
		case Hexa_LD_C_MEMB_Rd_U6:
		case Hexa_LD_C_MEMUB_Rd_U6:
		case Hexa_LD_MEMD_Rdd_Re_U6:
		case Hexa_LD_MEMW_Rd_Re_U6:
		case Hexa_LD_MEMH_Rd_Re_U6:
		case Hexa_LD_MEMUH_Rd_Re_U6:
		case Hexa_LD_MEMB_Rd_Re_U6:
		case Hexa_LD_MEMUB_Rd_Re_U6:
		case Hexa_LD_MEMB_Rd_Rs_S110:
		case Hexa_LD_MEMUB_Rd_Rs_S110:
		case Hexa_ST_MEMD_Ru_U2_U6_Rtt:
		case Hexa_ST_MEMW_Ru_U2_U6_Rt:
		case Hexa_ST_MEMH_Ru_U2_U6_Rt:
		case Hexa_ST_MEMB_Ru_U2_U6_Rt:
		case Hexa_ST_C_MEMB_Rs_U60_Rt:
		case Hexa_CR_SP1LOOP0_P3_R72_U10:
		case Hexa_CR_SP2LOOP0_P3_R72_U10:
		case Hexa_CR_SP3LOOP0_P3_R72_U10:
		case Hexa_XTYPE_MPY_MPYI_Rd_Rs_Rt:
		case Hexa_XTYPE_MPY_pluseq_MPYI_Rd_Rs_U8:
		case Hexa_XTYPE_MPY_lesseq_MPYI_Rd_Rs_U8:
		case Hexa_XTYPE_ALU_pluseq_ADD_Rd_Rs_S8:
		case Hexa_XTYPE_ALU_lesseq_ADD_Rd_Rs_S8:
		case Hexa_XTYPE_ALU_ADD_Rd_Rs_SUB_S6_Ru:
		case Hexa_XTYPE_PRED_CMPB_EQ_Pd_Rs_U8:
		case Hexa_XTYPE_PRED_CMPB_GT_Pd_Rs_S8:
		case Hexa_XTYPE_PRED_CMPB_GTU_Pd_Rs_U7:
		case Hexa_XTYPE_PRED_CMPH_EQ_Pd_Rs_U8:
		case Hexa_XTYPE_PRED_CMPH_GT_Pd_Rs_S8:
		case Hexa_XTYPE_PRED_CMPH_GTU_Pd_Rs_U7:
		case Hexa_XTYPE_MPY_eqplus_MPYI_Rd_Rs_U8:
		case Hexa_XTYPE_MPY_eqless_MPYI_Rd_Rs_U8:
		case Hexa_ALU32_C_TransferImm_Pu_Rd_S12:
		case Hexa_ST_MEMW_Rs_U62_S8:
		case Hexa_NV_MEMB_Ru_U2_U6_Nt:
		case Hexa_NV_MEMH_Ru_U2_U6_Nt:
		case Hexa_NV_MEMW_Ru_U2_U6_Nt:
		case Hexa_NV_C_MEMB_Rs_U60_Nt:
			extends(&instr_struct->Operands[2]);
			break;
		case Hexa_LD_MEMD_Rdd_Rs_S113:
		case Hexa_ST_C_MEMD_Rs_U63_Rtt:
			extends(&instr_struct->Operands[2], 3);
			break;
		case Hexa_LD_MEMW_Rd_Rs_S112:
		case Hexa_ST_C_MEMW_Rs_U62_Rt:
		case Hexa_NV_C_MEMW_Rs_U62_Nt:
		case Hexa_NV_C_JUMP_CMP_EQ_Ns_U5_R92:
		case Hexa_NV_C_JUMP_CMP_GT_Ns_U5_R92:
		case Hexa_NV_C_JUMP_CMP_GTU_Ns_U5_R92:
		case Hexa_NV_C_JUMP_CMP_EQ_Ns_Rt_R92:
		case Hexa_NV_C_JUMP_CMP_GT_Ns_Rt_R92:
		case Hexa_NV_C_JUMP_CMP_GTU_Ns_Rs_R92:
		case Hexa_NV_C_JUMP_CMP_GT_Rt_Ns_R92:
		case Hexa_NV_C_JUMP_CMP_GTU_Rs_Ns_R92:
			extends(&instr_struct->Operands[2], 2);
			break;
		case Hexa_LD_MEMH_Rd_Rs_S111:
		case Hexa_LD_MEMUH_Rd_Rs_S111:
		case Hexa_ST_C_MEMH_Rs_U61_Rt:
		case Hexa_NV_C_MEMH_Rs_U61_Nt:
			extends(&instr_struct->Operands[2], 1);
			break;

			// 4th operande extended
		case Hexa_ALU32_MUX_Rd_Pu_Rs_S8:
		case Hexa_ALU32_C_ADD_Pu_Rd_Rs_S8:
		case Hexa_LD_MEMD_Rdd_Rt_U2_U6:
		case Hexa_LD_MEMW_Rd_Rt_U2_U6:
		case Hexa_LD_MEMH_Rd_Rt_U2_U6:
		case Hexa_LD_MEMUH_Rd_Rt_U2_U6:
		case Hexa_LD_MEMB_Rd_Rt_U2_U6:
		case Hexa_LD_MEMUB_Rd_Rt_U2_U6:
		case Hexa_XTYPE_ALU_ADD_Rd_Rs_ADD_Ru_S6:
		case Hexa_XTYPE_ALU_OR_Rx_Ru_AND_Rx_S10:
		case Hexa_LD_C_MEMB_Rd_Rs_U60:
		case Hexa_LD_C_MEMUB_Rd_Rs_U60:
			extends(&instr_struct->Operands[3]);
			break;
		case Hexa_LD_C_MEMD_Rdd_Rs_U63:
			extends(&instr_struct->Operands[3], 3);
			break;
		case Hexa_LD_C_MEMW_Rd_Rs_U62:
		case Hexa_ST_C_MEMW_Rs_U62_S6:
			extends(&instr_struct->Operands[3], 2);
			break;
		case Hexa_LD_C_MEMH_Rd_Rs_U61:
		case Hexa_LD_C_MEMUH_Rd_Rs_U61:
			extends(&instr_struct->Operands[3], 1);
			break;
		}
	}
	// Correction des sauts
	if (instr_struct == &cmd) {
		switch (id) {
			// op 1
		case Hexa_J_JR_CALL_R222:
		case Hexa_J_JR_JUMP_R222:
			instr_struct->Operands[0].addr -=
			    (((instr_struct->segpref) >> 8) & 0x03) * 4;
			break;
			// op 2
		case Hexa_J_JR_C_CALL_Pu_R152:
		case Hexa_J_JR_C_JUMP_Pu_R152:
		case Hexa_J_JR_C_differ_Rs_JUMP_R132:
		case Hexa_J_JR_C_lower_Rs_JUMP_R132:
		case Hexa_J_JR_C_equal_Rs_JUMP_R132:
		case Hexa_J_JR_C_greater_Rs_JUMP_R132:
			instr_struct->Operands[1].addr =
			    instr_struct->Operands[1].addr -
			    (((instr_struct->segpref) >> 5) & 0x03) * 4;
			break;

			// op 3
		case Hexa_J_JR_CMP_EQ_Pd_Rs_C_JUMP_R92:
		case Hexa_J_JR_CMP_GT_Pd_Rs_C_JUMP_R92:
		case Hexa_J_JR_TSTBIT_Pd_Rs_C_JUMP_R92:
		case Hexa_J_JR_Transfer_Rd_U6_JUMP_R92:
		case Hexa_J_JR_Transfer_Rd_Rs_JUMP_R92:
			instr_struct->Operands[2].addr -=
			    (((instr_struct->segpref) >> 8) & 0x03) * 4;
			break;

			// op 4
		case Hexa_J_JR_CMP_EQ_Pd_Rs_U5_C_JUMP_R92:
		case Hexa_J_JR_CMP_EQ_Pd_Rs_Rt_C_JUMP_R92:
		case Hexa_J_JR_CMP_GT_Pd_Rs_U5_C_JUMP_R92:
		case Hexa_J_JR_CMP_GT_Pd_Rs_Rt_C_JUMP_R92:
		case Hexa_J_JR_CMP_GTU_Pd_Rs_U5_C_JUMP_R92:
		case Hexa_J_JR_CMP_GTU_Pd_Rs_Rt_C_JUMP_R92:
			instr_struct->Operands[3].addr -=
			    (((instr_struct->segpref) >> 8) & 0x03) * 4;
			break;
		}
	}

}

/**Etends une constante utilisant la valeur stockee si besoin est.
 *
 */
void extends(op_t * operand)
{
	if (constantExtender != 1) {
		switch (operand->type) {
		case o_imm:
			operand->value =
			    ((operand->value) & 0x3F) | (constantExtender);
			break;
		case o_near:
			operand->addr =
			    ((operand->addr) & 0x3F) | (constantExtender);
			break;
		default:
			msg ("extending unextendable constant at %x\n", cmd.ea);
			break;
		}
		operand->specval |= 1;
		constantExtender = 1;
	}
}

/*! correct offset of variable assignment for immediate extended scalar */
void extends(op_t * operand, int offset)
{
	if (constantExtender != 1) {
		operand->value = (operand->value) >> offset;
		operand->addr = (operand->addr) >> offset;
		extends(operand);
	}
}

void setDestinationRegister(insn_t * instr_struct, int value)
{
	instr_struct->insnpref =
	    (((instr_struct->insnpref) & (~(0x07E))) | ((value & 0x3F) << 1));
}

int getDestinationRegister(insn_t * instr_struct)
{
	return (((instr_struct->insnpref) >> 1) & 0x3F);
}

int getNewValueRegister(int value)
{
	if (bNewValueAnalysis) {
		// msg("new value loop at %x\n", cmd.ea);
		return -2;
	}
	uint32 usedValueInstruction;
	int space;
	int i = 0;
	switch (value) {
	case 2:
	case 3:
		space = 1;
		break;
	case 4:
	case 5:
		space = 2;
		break;
	case 6:
	case 7:
		space = 3;
		break;
	default:
		return -2;
		break;
	}
	while (space > 0) {
		i++;
		get_many_bytes(cmd.ea - 4 * i, &usedValueInstruction, 4);
		if (((usedValueInstruction >> 28) & 0x0F) != 0x00) { // != constant extender
			space--;
		}
		if (i > 3) {
			// msg("new value not found at %x\n",cmd.ea);
			return -1;
		}
	}
	insn_t fakecmd;
	bNewValueAnalysis = true;
	analyse_instruction(usedValueInstruction, &fakecmd);
	bNewValueAnalysis = false;
	return getDestinationRegister(&fakecmd);
}

void addrnd()
{				//:rnd
	cmd.auxpref |= 0x0010;
}

void addcrnd()
{				//:crnd
	cmd.auxpref |= 0x0020;
}

void addraw()
{				//:raw
	cmd.auxpref |= 0x0040;
}

void addchop()
{				//:chop
	cmd.auxpref |= 0x0080;
}

void addsat()
{				//:sat
	cmd.auxpref |= 0x0008;
}

void addhi()
{				//:hi
	cmd.auxpref |= 0x0100;
}

void addlo()
{				//:lo
	cmd.auxpref |= 0x0200;
}

void adddec1()
{				//:<<1
	cmd.auxpref |= 0x0400;
}

void adddec16()
{				//:<<16
	cmd.auxpref |= 0x0800;
}

void addinc1()
{				//:>>1
	cmd.auxpref |= 0x1000;
}

void adddeprecated()
{				//:deprecated
	cmd.auxpref |= 0x2000;
}

void addnot()
{				//!
	cmd.insnpref |= 0x0001;
}

void addEndloop(int offset)
{
	cmd.segpref |= (0x04 << offset);
}
