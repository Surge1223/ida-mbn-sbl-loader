/* mbn loader for Ida Pro 
*/

#include <../ldr/idaldr.h>
#include <vector>
#include "mbn.h"
typedef std::vector<unsigned char> CHARS;
#define mbn_MAGIC	`						 = 0x73D71034
#define FLASH_CODE_WORD						 = 0x844BDCD1      
#define BOOT_COOKIE_MAGIC_NUMBER			 = 0x33836685  
#define MAGIC_NUM							 = 0x73D71034 
#define PAGE_SIZE_MAGIC_NUM                  = 0x7D0B435A
#define MI_FSBL_MAGIC1                       = 0x6FC123DF
#define MI_FSBL_MAGIC2                       = 0x60FDEFC7
#define MI_OSBL_MAGIC1                       = 0x6CBA1CFD
#define MI_OSBL_MAGIC2                       = 0x68D2CBE9
#define MI_SBL2_MAGIC1                       = 0x6012780C
#define MI_SBL2_MAGIC2                       = 0x6C93B127
#define HEADER_SIZE sizeof(mbn)
const char BOOT_SEGMENT[] = "MBN_CODE";
//--------------------------------------------------------------------------
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//

static mbn_hdr hdr;
static sbl_hdr shdr;
int accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
	if( n!= 0 )
		return 0;

	// quit if file is smaller than size of iNes header
	if (qlsize(li) < sizeof(mbn_hdr))
		return 0;

	// set filepos to offset 0
	qlseek(li, 0, SEEK_SET);

	// read MBN header
	if(qlread(li, &hdr, MBN_HDR_SIZE) != MBN_HDR_SIZE)
		return 0;

	// read SBL header
	if(qlread(li, &shdr, SBL_HDR_SIZE) != SBL_HDR_SIZE)
		return 0;

	// this is the name of the file format which will be
	// displayed in IDA's dialog
	qstrncpy(fileformatname, "QCOM Bootloader", MAX_FILE_FORMAT_NAME);

	// set processor to ARM
	if ( ph.id != PLFM_6502 )
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
  lread4bytes(li, &ex.header_part_ver, true);
  lread4bytes(li, &ex.image_src, true);
  lread4bytes(li, &ex.image_dest_ptr, true);     
  lread4bytes(li, &ex.image_size, true);
  lread4bytes(li, &ex.code_size, true);
  lread4bytes(li, &ex.signature_ptr, true);
  lread4bytes(li, &ex.signature_size, true);     
  lread4bytes(li, &ex.cert_chain_ptr, true);     
  lread4bytes(li, &ex.cert_chain_size, true);     
  
  set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL);
}

//--------------------------------------------------------------------------
//
//      load file into the database.

//
void idaapi load_file(linput_t *li, ushort neflags, const char * formatname)
{
  mbn hdr;
  mbn ex;

   //read the program header from the input file
   //read the program header from the input file
  
  lread(li, &hdr, sizeof(mbn));
  msg("image_id: %08x\n", hdr.image_id);
  msg("header_part_ver: %08x\n", hdr.header_part_ver);
  msg("image_src: %08x\n", hdr.image_src);
  msg("image_dest_ptr: %08x\n", hdr.image_dest_ptr);
  msg("image_size: %08x\n", hdr.image_size);
  msg("code_size: %08x\n", hdr.code_size);
  msg("signature_ptr: %08x\n", hdr.signature_ptr);
  msg("signature_size: %08x\n", hdr.signature_size);
  msg("cert_chain_ptr: %08x\n", hdr.cert_chain_ptr);
  msg("cert_chain_size: %08x\n", hdr.cert_chain_size);
   //file2base does a seek and read from the input file into the database
   //file2base is prototyped in loader.hpp
   file2base(li, HEADER_SIZE, hdr.image_dest_ptr, hdr.image_dest_ptr + hdr.code_size, true);
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
}

//----------------------------------------------------------------------
bool idaapi init_loader_options(linput_t *li)
{
  mbn ex;
  mbnhdr(li, ex);
  return true;
}

int  idaapi save_file(FILE * file, const char * formatname)
{
	if (file == NULL) return 1;

	segment_t *s = get_segm_by_name(NAME_DATA);
	if (!s) return 0;

	base2file(file, 0, s->startEA, s->endEA);
	return 1;
}

//----------------------------------------------------------------------
//
//      LOADER DESCRIPTION BLOCK
//
//----------------------------------------------------------------------
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
