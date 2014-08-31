// 
//  This is an IDA plugin, which loads a COFF obj/lib file signature...
//  Copyright (C) 2007 Gökhan ERBAY. All rights reserved.
//
//  This software is provided 'as-is', without any express or implied
//  warranty.  In no event will the author be held liable for any damages
//  arising from the use of this software.
//
//--------------------------------------------------------------------------
#include <ida.hpp>
#include <idp.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <name.hpp>
#include <segment.hpp>
#include <string>
#include <vector>
#include "coff.h"
//--------------------------------------------------------------------------
using namespace std;
//--------------------------------------------------------------------------
#define _S(x)     (string(x, sizeof(x)).c_str())
//--------------------------------------------------------------------------
#pragma pack(push, 4)
    
typedef struct  
{
	string name;
	unsigned value;
	short section;
	unsigned short type;
	unsigned char sClass, numAux;
} ge_symbol_t;

typedef struct  
{
	unsigned offset;
	unsigned symTabIndex;
	unsigned short type;
} ge_reloc_t;

typedef struct
{
    coff_section_header * sectionPtr;
    unsigned sectionNum;
} ge_section_t;

#pragma pack(pop)
//--------------------------------------------------------------------------
int init(void)
{
  if ( inf.filetype != f_PE ) return PLUGIN_SKIP; // only for PE files  
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void term(void)
{
}
//--------------------------------------------------------------------------
static ea_t eaStart = BADADDR;
static ea_t eaEnd   = BADADDR;
//--------------------------------------------------------------------------
ea_t applyCoffObject(FILE * fp)
{
    int bookmark = qftell(fp);
	char * stringTable = NULL;
	char * symbolTable = NULL;
	char * sectionHeaders = NULL;
	char * codeBlock = NULL;
	unsigned int codeBlockLen = 0;
	coff_section_header * textSectionHdr = NULL;
	int ourSection = -1;
	char * relocs = NULL;
    ea_t baseAddr = BADADDR;
	
	coff_file_header hdr;
	qfread(fp, &hdr, sizeof(coff_file_header));
    if (hdr.cpu_type != IMAGE_FILE_MACHINE_I386)
    {
        msg("gerbay - COFF Plugin -> This plugin only applicable for 32bit i386 COFF format!\n");
        return BADADDR;
    }
	unsigned strTablePos  = 0;
	unsigned strTableSize = 0;
	strTablePos = hdr.sym_table + (hdr.num_symbols * sizeof(coff_symbol));
	qfseek(fp, bookmark + strTablePos, SEEK_SET);
	qfread(fp, &strTableSize, sizeof(unsigned));

	if (strTableSize > 0)
	{
		strTableSize -= sizeof(strTablePos);
		stringTable = (char*)qalloc(strTableSize * sizeof(char)); 
		qfread(fp, stringTable, strTableSize);
	}

	qfseek(fp, bookmark + hdr.sym_table, SEEK_SET);
	symbolTable = (char*)qalloc(sizeof(coff_symbol) * hdr.num_symbols);
	qfread(fp, symbolTable, sizeof(coff_symbol) * hdr.num_symbols);
	char *name = 0;
	char buff[9];
	buff[8] = '\0';
	coff_symbol *symTab = (coff_symbol *)symbolTable;
	vector<ge_symbol_t> ge_symbols(hdr.num_symbols);
	for (unsigned symIdx = 0; symIdx < hdr.num_symbols; symIdx++)
	{
		if( symTab->name.non_name.zeros == 0 ) 
		{
			name = stringTable + symTab->name.non_name.offset - 4;
		} 
		else 
		if( symTab->name.name_string[8] == '\0' ) 
		{
			name = symTab->name.name_string;
		} 
		else 
		{
			memcpy( buff, symTab->name.name_string, 8 );
			name = buff;
		}
		ge_symbols[symIdx].name = name;
		ge_symbols[symIdx].section = symTab->sec_num;
		ge_symbols[symIdx].type = symTab->type;
		ge_symbols[symIdx].value = symTab->value;
		ge_symbols[symIdx].sClass = symTab->storage_class;
		ge_symbols[symIdx].numAux = symTab->num_aux;
		unsigned num_aux = symTab->num_aux;
		symTab++;
		if (num_aux > 0)
		{
			symIdx += num_aux;
			symTab += num_aux;
		}
	}
	sectionHeaders = (char*)qalloc(hdr.num_sections * sizeof(coff_section_header));
	qfseek(fp, bookmark + sizeof(coff_file_header), SEEK_SET);
	qfread(fp, sectionHeaders, sizeof(coff_section_header) * hdr.num_sections);
	coff_section_header * secHdr = (coff_section_header *)sectionHeaders;
    vector<ge_section_t> ge_textSections;
	for (unsigned i = 0; i < hdr.num_sections; i++, secHdr++)
	{
		if (strcmp(secHdr->name, ".text") == 0 || ((secHdr->flags & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE))
		{
            ge_section_t sect;
            sect.sectionPtr = secHdr;
            sect.sectionNum = i+1;
            ge_textSections.push_back(sect);
		}
	}
    if (ge_textSections.size() > 0)
    for (unsigned g = 0; g < ge_textSections.size(); g++)
	{
        textSectionHdr = ge_textSections[g].sectionPtr;
        ourSection     = ge_textSections[g].sectionNum;
		codeBlockLen = textSectionHdr->size;
		codeBlock = (char*)qalloc(codeBlockLen);
		memset(codeBlock, 0, codeBlockLen);
		qfseek(fp, bookmark + textSectionHdr->rawdata_ptr, SEEK_SET);
		qfread(fp, codeBlock, codeBlockLen);
		relocs = (char*)qalloc(textSectionHdr->num_relocs*sizeof(coff_reloc));
		qfseek(fp, bookmark + textSectionHdr->reloc_ptr, SEEK_SET);
		qfread(fp, relocs, sizeof(coff_reloc) * textSectionHdr->num_relocs);
		vector<ge_reloc_t> ge_relocs(textSectionHdr->num_relocs);
		coff_reloc * rel = (coff_reloc*)relocs;
		for (unsigned i = 0; i < textSectionHdr->num_relocs; i++, rel++)
		{
			ge_relocs[i].offset = rel->offset;
			ge_relocs[i].symTabIndex = rel->sym_tab_index;
			ge_relocs[i].type = rel->type;
		}
		vector<unsigned char> mask(codeBlockLen, 1);
		for (unsigned i = 0; i < ge_relocs.size(); i++)
		{
			if (ge_relocs[i].type == IMAGE_REL_I386_DIR32 
	         || ge_relocs[i].type == IMAGE_REL_I386_REL32)
	        {
	        	mask[ ge_relocs[i].offset + 0 ] = 0;
	        	mask[ ge_relocs[i].offset + 1 ] = 0;
	        	mask[ ge_relocs[i].offset + 2 ] = 0;
	        	mask[ ge_relocs[i].offset + 3 ] = 0;
	        }
		}
	    baseAddr = bin_search(eaStart, eaEnd, (unsigned char*)codeBlock, &mask[0], 
	      codeBlockLen, BIN_SEARCH_FORWARD, BIN_SEARCH_CASE);
	    if (baseAddr != BADADDR) 
	    {
	    	for (unsigned k = 0; k < ge_symbols.size(); k++)
	    	{
                if (wasBreak()) break;
	    		if (ge_symbols[k].section == ourSection && ge_symbols[k].type == 0x0020)
	    		{
	    			do_name_anyway(baseAddr + ge_symbols[k].value, ge_symbols[k].name.c_str());
	    		}
	    	}
	    	for (unsigned k = 0; k < ge_relocs.size(); k++)
	    	{
                if (wasBreak()) break;
	    		ulong u = get_long(baseAddr + ge_relocs[k].offset);
	    		ea_t ea = u;
	    		if (ge_relocs[k].type == IMAGE_REL_I386_REL32)
	    		{
	    			ea += (baseAddr + ge_relocs[k].offset + 4);
	    		}
	    		const char * relocName = ge_symbols[ ge_relocs[k].symTabIndex ].name.c_str();
	    		do_name_anyway(ea, relocName);
	  	  	}
	    	refresh_idaview_anyway();
        }
        msg("gerbay - COFF text signature found at address: %08a\n", baseAddr);
        msg("gerbay - COFF Plugin -> SymbolCount: %d, RelocCount: %d\n", ge_symbols.size(), ge_relocs.size());
	}
	else
	{
		msg("gerbay - COFF Plugin -> code section not found in this COFF file!\n");
	}
    qfree(stringTable);
    qfree(symbolTable);
    qfree(sectionHeaders);
    qfree(codeBlock);
    qfree(relocs);
    return baseAddr;
}
//--------------------------------------------------------------------------
inline void align(FILE * f)
{
    if (qftell(f) % 2 == 1) qfseek(f, +1, SEEK_CUR);
}
//--------------------------------------------------------------------------
void run(int /*arg*/)
{
	char * file = askfile_c(0,"*.obj;*.lib", "Please select COFF object file to find signature in...");
    if (file == NULL) return;
	FILE *fp = qfopen(file, "rb");
	if (fp == NULL) 
	{
	  error("gerbay - COFF Plugin -> Error: Can't open %s file for reading\n", file);
	  return;
	}
    segment_t * seg = getnseg(0);
    if (seg != NULL) eaStart = seg->startEA;
    seg = getnseg(get_segm_qty()-1);
    if (seg != NULL) eaEnd = seg->endEA;
    ea_t addr = get_screen_ea();
    msg("gerbay - COFF Plugin -> file: '%s'\n", file);
	msg("gerbay - COFF Plugin -> start addr: %08a, end addr: %08a\n", eaStart, eaEnd);
    try
    {
        show_wait_box("'%s'\n\ngökhan erbay's COFF Plugin: symbols loading...", file);
        clearBreak();
    	if (stristr(file, ".obj") > 0)	
            addr = applyCoffObject(fp);
    	else
    	if (stristr(file, ".lib") > 0)
    	{
            char buf[10];
        	qfread(fp, buf, 8);
        	if (strncmp(buf, arch_signature, 8) != 0)
        	{
        		error("this file is not a lib file (%s)!", file);
                qfclose(fp);
                hide_wait_box();
        		return;
        	}
        	arch_header hdr;
            qfread(fp, &hdr, sizeof(arch_header));
            int _1stLen = atol(_S(hdr.size));
            qfseek(fp, _1stLen, SEEK_CUR); // skip 1st. header
            align(fp);
            
            qfread(fp, &hdr, sizeof(arch_header));
            int _2ndLen = atol(_S(hdr.size));
            int bookMark1 = qftell(fp);
            int numberOfMembers = 0;
            qfread(fp, &numberOfMembers, sizeof(numberOfMembers));
            vector<int> objFiles(numberOfMembers);
            for (int i = 0; i < numberOfMembers; i++)
            {
                int v = 0;
                qfread(fp, &v, sizeof(v));
                objFiles[i] = v;
            }
            int numberOfSymbols = 0;
            qfread(fp, &numberOfSymbols, sizeof(numberOfSymbols));
            qfseek(fp, bookMark1, SEEK_SET); // go back to end of the 2nd. header
            qfseek(fp, _2ndLen, SEEK_CUR); // skip 2nd. header
            align(fp);
            
            qfread(fp, &hdr, sizeof(arch_header));
            for (unsigned i = 0; i < objFiles.size(); i++)
            {
                qfseek(fp, objFiles[i], SEEK_SET);
                qfread(fp, &hdr, sizeof(arch_header));
                addr = applyCoffObject(fp);
                if (wasBreak()) break;
            }
    	}
    }
    catch (...)
    {
    }
    hide_wait_box();    
    qfclose(fp);
    if (addr != BADADDR) jumpto(addr);
    refresh_idaview_anyway();
}

//--------------------------------------------------------------------------
char comment[] = "coff obj/lib signature loader...";

char help[] = "gokhan erbay, COFF signature loader plugin\n\nwritten by gokhan erbay\n";


//--------------------------------------------------------------------------
// This is the preferred name of the plugin module in the menu system
// The preferred name may be overriden in plugins.cfg file

char wanted_name[] = "COFF object signature loader by gerbay";


// This is the preferred hotkey for the plugin module
// The preferred hotkey may be overriden in plugins.cfg file
// Note: IDA won't tell you if the hotkey is not correct
//       It will just disable the hotkey.

char wanted_hotkey[] = "Ctrl+1";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
