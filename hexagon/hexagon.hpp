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

#ifndef _HEXA_HPP
#define _HEXA_HPP

#include <ida.hpp>
#include <idp.hpp>
#include <srarea.hpp>
#include <struct.hpp>
#include <diskio.hpp>
#include <frame.hpp>
#include <srarea.hpp>
#include <ieee.h>
#include <lines.hpp>

#include "ins.hpp"
#include "ana.hpp"
#include "out.hpp"
#include "emu.hpp"
#include "context.hpp"

#include "../idaidp.hpp"

enum hexagon_registers {
	// General Registers
	R0, R1, R2, R3, R4, R5, R6, R7,
	R8, R9, R10, R11, R12, R13, R14, R15,
	R16, R17, R18, R19, R20, R21, R22, R23,
	R24, R25, R26, R27, R28, R29, R30, R31,	// R29=SP, R30=FP, R31=LR,
	// Control Registers
	SA0, LC0, SA1, LC1,	// C0 , C1 , C2 , C3 
	C4, VC5,		//C4 = P3:0 !!!, C5 does not 
	M0, M1,			//C6 , C7
	USR, PC, UGP, GP,	// C8 , C9 , C10, C11
	CS0, CS1, UPCYCLELOW, UPCYCLEHI,	// C12, C13, C14, C15

	// Virtual Segment Registers
	VCS, VDS,
};

const optype_t
    o_CR = o_idpspec0, o_R64 = o_idpspec1, o_PR = o_idpspec2, o_MR = o_idpspec3;

#endif
