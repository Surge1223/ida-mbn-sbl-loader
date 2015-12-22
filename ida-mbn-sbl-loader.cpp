/*
# Ida Mbn/Sbl loader for Ida Pro - by @Surge1223
#
# Relocation table isnt correct yet, send me an email if you
# know how to correct this (surge1223@gmail.com).
# Also support for osbl, dbl, and pbl
# can be added if theres a need, just add the header and where 
# to unpack from
*/

#include <..\ldr\idaldr.h>
#include <windows.h>
#include <vector>
#include "mbn.h"

#define YES_NO( condition ) ( condition ? "yes" : "no" )
typedef std::vector<unsigned char> CHARS;
#define mbn_MAGIC	` = 0x73D71034
#define FLASH_CODE_WORD						 = 0x844BDCD1      
#define BOOT_COOKIE_MAGIC_NUMBER			 = 0x33836685  
#define MAGIC_NUM							 = 0x73D71034 
#define HDR_FLASH_VER						 = 0x00000003
#define PAGE_SIZE_MAGIC_NUM                  = 0x7D0B435A
#define MI_FSBL_MAGIC1                       = 0x6FC123DF
#define MI_FSBL_MAGIC2                       = 0x60FDEFC7
#define MI_OSBL_MAGIC1                       = 0x6CBA1CFD
#define MI_OSBL_MAGIC2                       = 0x68D2CBE9
#define MI_SBL2_MAGIC1                       = 0x6012780C
#define MI_SBL2_MAGIC2                       = 0x6C93B127
#define NOR_SBL1_HEADER    = '<II72s'
#define NOR_SBL1_HEADER_SZ = struct.calcsize(NOR_SBL1_HEADER)
#define ALIGNMENT          = 256
#define NOR_CODE_WORD      = 0x844bdcd1
#define HEADER_SIZE sizeof(mbn)
const char BOOT_SEGMENT[] = "MBN_CODE";
char IDAP_comment[] = "loader to dissassemble mbn/sbl booatloaders";
char IDAP_help[] = "QCOM Bootloader Plugin";
char IDAP_hotkey[] = "Alt-X";

bool LoadFile(linput_t * file, CHARS & data)
{
	unsigned size = qlsize(file);
	data.resize(size);

	if (size > 0)
	{
		if (qlread(file, &data[0], size) == -1)
		{
			data.resize(0);
		}
	}
	return data.size() == size;
}

//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//


static unsigned int SWAP_BYTES_32(unsigned int a)
{
	return ((a >> 24) & 0x000000FF) | ((a >> 8) & 0x0000FF00) | ((a << 8) & 0x00FF0000) | ((a << 24) & 0xFF000000); // Swap dword LE to BE
}

//------------------------------------------------------------------------
static unsigned short READ_BE_WORD(unsigned char *addr)
{
	return (addr[0] << 8) | addr[1]; // Read BE word
}

//------------------------------------------------------------------------
static unsigned int READ_BE_UINT(unsigned char *addr)
{
	return (READ_BE_WORD(&addr[0]) << 16) | READ_BE_WORD(&addr[2]); // Read BE unsigned int by pointer
}

//------------------------------------------------------------------------
static void add_sub(unsigned int addr, const char *name, unsigned int max)
{
	if (!((addr >= 0x200) && (addr < max))) return;

	ea_t e_addr = toEA(ask_selector(0), addr);
	auto_make_proc(e_addr);
	set_name(e_addr, name);
}

//------------------------------------------------------------------------
static void add_segment(ea_t start, ea_t end, const char *name, const char *class_name, const char *cmnt)
{
	if (!add_segm(0, start, end, name, class_name)) loader_failure();
	segment_t *segm = getseg(start);
	set_segment_cmt(segm, cmnt, false);
	doByte(start, 1);
}
//------------------------------------------------------------------------

//------------------------------------------------------------------------
static mbn_hdr hdr;
static sbl_hdr shdr;
int accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{

	if (n != 0)
		return 0;

	// quit if file is smaller than size of iNes header
	if (qlsize(li) < sizeof(mbn_hdr))
		return 0;

	// set filepos to offset 0
//	imglen = qlsize(li);
	qlseek(li, 0, SEEK_SET);

	// read MBN header
	if (qlread(li, &hdr, MBN_HDR_SIZE) != MBN_HDR_SIZE)
		return 0;

	// read SBL header
	if (qlread(li, &shdr, SBL_HDR_SIZE) != SBL_HDR_SIZE)
		return 0;

	// this is the name of the file format which will be
	// displayed in IDA's dialog
	qstrncpy(fileformatname, "QCOM Bootloader", MAX_FILE_FORMAT_NAME);

	// set processor to ARM
	if (ph.id != PLFM_6502)
	{
		msg("QCOM Bootloader detected: setting processor type to ARM.\n");
		set_processor_type("ARM", SETPROC_ALL);
	}

	return (1 | ACCEPT_FIRST);
}
	//--------------------------------------------------------------------------
	void mbnhdr(linput_t *li, mbn &ex)
	{
		//lread(li, &ex, sizeof(ex));
		//mbn_hdr(li, ex);
		//lread(li, &mbn_hdr, sizeof(mbn));
		lread4bytes(li, &ex.image_id, true);
		lread4bytes(li, &ex.flash_parti_ver, true);
		lread4bytes(li, &ex.image_src, true);
		lread4bytes(li, &ex.image_dest_ptr, true);
		lread4bytes(li, &ex.image_size, true);
		lread4bytes(li, &ex.code_size, true);
		lread4bytes(li, &ex.signature_ptr, true);
		lread4bytes(li, &ex.signature_size, true);
		lread4bytes(li, &ex.cert_chain_ptr, true);
		lread4bytes(li, &ex.cert_chain_size, true);

		set_processor_type("arm", SETPROC_ALL | SETPROC_FATAL);
	}
	//--------------------------------------------------------------------------
	void sblhdr(linput_t *li, sbl &ex)
	{
		//lread(li, &ex, sizeof(ex));
		//mbn_hdr(li, ex);
		//lread(li, &mbn_hdr, sizeof(mbn));
		lread4bytes(li, &ex.codeword, true);
		lread4bytes(li, &ex.magic, true);
		lread4bytes(li, &ex.image_id, true);
		lread4bytes(li, &ex.image_src, true);
		lread4bytes(li, &ex.image_dest_ptr, true);
		lread4bytes(li, &ex.image_size, true);
		lread4bytes(li, &ex.code_size, true);
		lread4bytes(li, &ex.signature_ptr, true);
		lread4bytes(li, &ex.signature_size, true);
		lread4bytes(li, &ex.cert_chain_ptr, true);
		lread4bytes(li, &ex.cert_chain_size, true);
		set_processor_type("arm", SETPROC_ALL | SETPROC_FATAL);
	}

	//--------------------------------------------------------------------------
	//
	//      load file into the database.
	static void idaapi load_file(linput_t *li, ushort neflags, const char * fileformatname) {

			ea_t entry_point;
			mbn hdr;
			mbn ex;
			sbl hds;
			CHARS data;
			// display a messagebox asking the user for details
			//  1 - Yes
			//  0 - No
			// -1 - Cancel
			int answer = askyn_cv(1,
				"MBN/SBL loader by Surge1223.\n\n"
				"The partition may have a different start address if SBL1.\n"
				"Choose \"Yes\" to load the SBL1 type,\n"
				"\"No\" to load all other MBN types\n\n"
				"\nDo you want to load the SBL1 code?\n\n"
				, NULL
				);
			// user chose "cancel" ?
			if (answer == BADADDR)
			{
				qexit(1);
			}

			// user chose "yes" = arm9
			else if (answer)
			{
				// and read the whole header
				lread(li, &hds, SBL_HDR_SIZE);
				msg("Codeword:            : %08x\n", hds.codeword);
				msg("Magic No.:           : %08x\n", hds.magic);
				msg("Image ID:     : %08x\n", ex.image_id);
				msg("Source Location:     : %08x\n", ex.image_src);
				msg("Destination Address: : %08x\n", ex.image_dest_ptr);
				msg("Image Size:          : %08x\n", ex.image_size);
				msg("Code Size:           : %08x\n", ex.code_size);
				msg("Signature Ptr:       : %08x\n", ex.signature_ptr);
				msg("Signature Size:      : %08x\n", ex.signature_size);
				msg("Cert Chain Ptr:      : %08x\n", ex.cert_chain_ptr);
				msg("Cert Chain Size:     : %08x\n", ex.cert_chain_size);
				//read the program header from the input file
				//lread(li, &hdr, MBN_HDR_SIZE);
				//file2base does a seek and read from the input file into the database
				//file2base is prototyped in loader.hpp
				file2base(li, sizeof(sbl), hds.image_dest_ptr, hds.image_dest_ptr + hds.code_size, true);
				//try to add a new code segment to contain the program bytes
				if (!add_segm(0, hds.image_dest_ptr, hds.image_dest_ptr + hds.code_size, BOOT_SEGMENT, CLASS_CODE)) {

					loader_failure();
				}
				add_entry(hds.image_dest_ptr, hds.image_dest_ptr, "_start", true);
				//retrieve a handle to the new segment
				segment_t *s = get_segm_by_name(BOOT_SEGMENT);
				//so that we can set 32 bit addressing mode on
				set_segm_addressing(s, 1);  //set 32 bit addressing
				//tell IDA to create the file header comment for us.  Do this only once
				create_filename_cmt();
				//Add an entry point so that the processor module knows at least one
				//address that contains code.  This is the root of the recursive descent
				//disassembly process
				add_entry(hds.image_dest_ptr, hds.image_dest_ptr, "HEADER", true);
				//Add an entry point so that the processor module knows at least one
				//address that contains code.  This is the root of the recursive descent
				//disassembly process
				//----------------------------------------------------------------------
			}
			//read the program header from the input file
				lread(li, &hdr, MBN_HDR_SIZE);
				msg("Codeword:            : %08x\n", hdr.flash_parti_ver);
				msg("Magic No.:           : %08x\n", hdr.image_id);
				msg("Source Location:     : %08x\n", hdr.image_src);
				msg("Destination Address: : %08x\n", hdr.image_dest_ptr);
				msg("Image Size:          : %08x\n", hdr.image_size);
				msg("Code Size:           : %08x\n", hdr.code_size);
				msg("Signature Ptr:       : %08x\n", hdr.signature_ptr);
				msg("Signature Size:      : %08x\n", hdr.signature_size);
				msg("Cert Chain Ptr:      : %08x\n", hdr.cert_chain_ptr);
				msg("Cert Chain Size:     : %08x\n", hdr.cert_chain_size);

				//read the program header from the input file
				//lread(li, &hdr, MBN_HDR_SIZE);
				//file2base does a seek and read from the input file into the database
				//file2base is prototyped in loader.hpp
				file2base(li, MBN_HDR_SIZE, hdr.image_dest_ptr, hdr.image_dest_ptr + hdr.code_size, true);
				//try to add a new code segment to contain the program bytes
				if (!add_segm(0, hdr.image_dest_ptr, hdr.image_dest_ptr + hdr.code_size, BOOT_SEGMENT, CLASS_CODE)) {

					loader_failure();
				}
				//retrieve a handle to the new segment
				segment_t *s = get_segm_by_name(BOOT_SEGMENT);
				//so that we can set 32 bit addressing mode on
				set_segm_addressing(s, 1);  //set 32 bit addressing
				//tell IDA to create the file header comment for us.  Do this only once
				create_filename_cmt();
				//Add an entry point so that the processor module knows at least one
				//address that contains code.  This is the root of the recursive descent
				//disassembly process
				add_entry(hdr.image_dest_ptr, hdr.image_dest_ptr, "HEADER", true);
				//Add an entry point so that the processor module knows at least one
				//address that contains code.  This is the root of the recursive descent
				//disassembly process
				//----------------------------------------------------------------------
			}
		//----------------------------------------------------------------------
		//
		//      defines, names and comments an item
		//
		static void define_item(ushort address, asize_t size, char *shortdesc, char *comment)
		{
			do_unknown(address, true);
			set_name(address, shortdesc);
			set_cmt(address, comment, true);
		}


		bool idaapi init_loader_options(linput_t *li)
		{
			mbn ex;
			mbnhdr(li, ex);
			return true;
		}

		int  idaapi save_file(FILE * file, const char * formatname)
		{
			if (file == NULL) return 1;

			segment_t *s = get_segm_by_name(BOOT_SEGMENT);
			if (!s) return 0;

			base2file(file, 0, s->startEA, s->endEA);
			return 1;
		}

		static ea_t get_vector(ea_t vec)
		{
			return get_word(vec);
		}


		//----------------------------------------------------------------------
		//
		//      define location as word (2 byte), convert it to an offset, rename it
		//      and comment it with the file offset
		//
		static void name_vector(ushort address, const char *name)
		{
			do_unknown(address, true);
			do_data_ex(address, wordflag(), 2, BADNODE);
			set_offset(address, 0, 0);
			set_name(address, name);
		}

		//----------------------------------------------------------------------
		//
		//      LOADER DESCRIPTION BLOCK
		//
		//----------------------------------------------------------------------
		__declspec(dllexport)
			loader_t LDSC =
		{
			IDP_INTERFACE_VERSION,
			0,
			accept_file,
			load_file,
			save_file,
			NULL,
			NULL,
		};
