PROC=gerbay1
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)gerbay1$(O): $(I)area.hpp $(I)bytes.hpp $(I)fpro.h $(I)funcs.hpp         \
	        $(I)help.h $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp          \
	        $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)nalt.hpp     \
	        $(I)netnode.hpp $(I)pro.h $(I)segment.hpp $(I)ua.hpp        \
	        $(I)xref.hpp gerbay1.cpp
