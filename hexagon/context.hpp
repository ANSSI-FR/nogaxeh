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

#ifndef _CONTEXT_HPP
#define _CONTEXT_HPP

#include "hexagon.hpp"

#define JUMP_TABLE_SIZE 10
#define CALL_TABLE_SIZE 10
#define OPERAND_TABLE_SIZE 4

class Context {
public:
	static Context & getInstance();
	void addJump(uint32 adress);
	void addCall(uint32 adress);
	void endPacket();
	int getAndResetFlowEnd();
	void stopFlow();

private:
	int *jumpTable;
	int jumpCounter;
	int *callTable;
	int callCounter;
	int flowEnd;

	static Context instance;
	 Context();
	~Context();
};

#endif
