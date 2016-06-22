
#   Copyright (C) 2015-2016  ANSSI
#   Copyright (C) 2015  Thomas Cordier
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

PROC=hexagon
ADDITIONAL_GOALS=config

include ../module.mak

config:    $(C)hexagon.cfg
$(C)hexagon.cfg:  hexagon.cfg
	$(CP) $? $@

# MAKEDEP dependency list ------------------
$(F)ana$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp   \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp ana.cpp hexagon.hpp      \
	          ins.hpp context.hpp
$(F)emu$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp   \
	          $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp $(I)ida.hpp        \
	          $(I)idp.hpp $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp   \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp      \
	          ../jptcmn.cpp emu.cpp hexagon.hpp ins.hpp context.hpp
$(F)ins$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp   \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)ua.hpp $(I)xref.hpp ../idaidp.hpp hexagon.hpp ins.cpp      \
	          ins.hpp context.hpp
$(F)out$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp   \
	          $(I)fpro.h $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp          \
	          $(I)kernwin.hpp $(I)lines.hpp $(I)llong.hpp               \
	          $(I)loader.hpp $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp  \
	          $(I)offset.hpp $(I)pro.h $(I)queue.hpp $(I)segment.hpp    \
	          $(I)srarea.hpp $(I)struct.hpp $(I)ua.hpp $(I)xref.hpp     \
	          ../idaidp.hpp hexagon.hpp ins.hpp out.cpp context.hpp
$(F)reg$(O)     : $(I)area.hpp $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp   \
	          $(I)diskio.hpp $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp     \
	          $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)queue.hpp $(I)segment.hpp $(I)srarea.hpp $(I)ua.hpp   \
	          $(I)xref.hpp ../idaidp.hpp hexagon.hpp ins.hpp reg.cpp
$(F)context$(O)  : $(I)area.hpp $(I)auto.hpp $(I)bitrange.hpp $(I)bytes.hpp   \
	          $(I)diskio.hpp $(I)fpro.h $(I)frame.hpp $(I)funcs.hpp     \
	          $(I)ida.hpp $(I)idp.hpp $(I)ieee.h $(I)kernwin.hpp        \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp   \
	          $(I)name.hpp $(I)netnode.hpp $(I)offset.hpp $(I)pro.h     \
	          $(I)queue.hpp $(I)segment.hpp $(I)srarea.hpp $(I)ua.hpp   \
	          $(I)xref.hpp ../idaidp.hpp hexagon.hpp ins.hpp context.cpp
