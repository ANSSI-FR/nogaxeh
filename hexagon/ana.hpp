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

#ifndef _ANA_HPP
#define _ANA_HPP

#include "hexagon.hpp"

extern uint32 constantExtender;

int idaapi ana(void);
int analyse_instruction(uint32 instr, insn_t * instr_struct);
void fill_struct(uint16 id, uint32 instr, insn_t * instr_struct);
void extends(op_t * operand);
void extends(op_t * operand, int offset);
void setDestinationRegister(insn_t * instr_struct, int value);
int getDestinationRegister(insn_t * instr_struct);
int getNewValueRegister(int value);

void addrnd();
void addcrnd();
void addraw();
void addchop();
void addsat();
void addhi();
void addlo();
void adddec1();
void adddec16();
void addinc1();
void adddeprecated();
void addnot();
void addEndloop(int offset);

#endif
