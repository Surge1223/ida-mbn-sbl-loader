# Ida Mbn/Sbl loader - by @Surge1223
# 
# Credit for some portions goes to cycad and Ralekdev
#
# Relocation table isnt correct yet, send me an email if you
# know how to correc this. Also support for osbl, dbl, and pbl
# can be added if theres a need, just add the header and where 
# to unpack from

import idaapi
from idc import *
import struct
import idc
import struct
import idautils

# Magic numbers filled in for boot headers
FLASH_PARTI_VERSION       = 3 
NOR_SBL1_HEADER    = '<II72s'
NOR_SBL1_HEADER_SZ = struct.calcsize(NOR_SBL1_HEADER)
NOR_CODE_WORD      = 0x844bdcd1
MAGIC_NUM          = 0x73d71034
PAGE_SIZE_MAGIC_NUM        = 0x7D0B435A
UNIFIED_BOOT_COOKIE_MAGIC_NUMBER      = 0x33836685
MBN_IMAGE_ID = 0x00000005
HDR_FLASH_VER = 0x00000003
MBN_HEADER_SIZE_B = 40
SBL_HEADER_SIZE_B = 80
SBL_HEADER_OFFSET_SIZE = 0x28
SBL_VIRTUAL_BLOCK_MAGIC_NUM           = 0xD48B54C6
SBL1 = "Qualcomm SBL image"
MBN = "Qualcomm MBN image"
DEBUG = True

# -----------------------------------------------------------------------
class Boot_Hdr:
    
    MBN_HEADER_SZ	= 40
    MBN_HEADER		= '<IIIIIIIIIIIIIIIIIIII'
    PAD_SZ			= 256
    NOR_CODE_WORD		= 0x844bdcd1
    MAGIC_NUM		= 0x73d71034
    
    def __init__(self, init_val):
        if len(init_val) < Sbl_Hdr.SBL1_HEADER_SZ: raise ValueError('Invalid ROM header size')
        
        # extract the values from the rom into the class
        (self.image_id,
         self.flash_parti_ver,
         self.image_src,
         self.image_dest_ptr,
         self.image_size,
         self.code_size,
         self.sig_ptr,
         self.sig_size,
         self.cert_chain_ptr,
         self.cert_chain_size,
         self.magic_number1,
         self.version,
         self.OS_type,
         self.boot_apps_parti_entry,
         self.boot_apps_size_entry,
         self.boot_apps_ram_loc,
         self.reserved_ptr,
         self.reserved_1,
         self.reserved_2,
         self.reserved_3) = struct.unpack_from(self.MBN_HEADER, init_val)

# -----------------------------------------------------------------------

class Sbl_Hdr:
    
    SBL1_HEADER_SZ	= 80
    SBL1_HEADER		= '<IIIIIIIIIIIIIIIIIIII'
    PAD_SZ			= 256
    NOR_CODE_WORD		= 0x844bdcd1
    MAGIC_NUM		= 0x73d71034

    def __init__(self, init_val):
        if len(init_val) < Sbl_Hdr.SBL1_HEADER_SZ: raise ValueError('Invalid ROM header size')
        
        # extract the values from the rom into the class
        (self.codeword,
         self.magic,
         self.image_id,
         self.reserved_1,
         self.reserved_2,
         self.image_src,
         self.image_dest_ptr,
         self.image_size,
         self.code_size,
         self.sig_ptr,
         self.sig_size,
         self.cert_chain_ptr,
         self.cert_chain_size,
         self.oem_root_cert_sel,
         self.oem_num_root_certs,
         self.reserved_5,
         self.reserved_6,
         self.reserved_7,
         self.reserved_8,
         self.reserved_9) = struct.unpack_from(self.SBL1_HEADER, init_val)

# -----------------------------------------------------------------------

class SblImage:
    """Represents the ROM when broken up into its sections."""
    def __init__(self, init_val):
        # parse the header
        self.header = Sbl_Hdr(init_val)

        # pull out the image data as it would be loaded from the rom
        image_start = self.header.image_src + Sbl_Hdr.SBL1_HEADER_SZ
        self.image = init_val[image_start:image_start + self.header.image_size]

        # pull out the overlay, too
        self.overlay_data = init_val[image_start + self.header.image_size:]
        if len(self.overlay_data) == 0: self.overlay_data = None
        else: self.overlay_base = self.header.image_dest_ptr + self.header.image_size
        
        # load the code section
        self.code_base = self.header.image_dest_ptr
        code_size = self.header.code_size
        self.code_data = self.image[:code_size]

        # create the signature segment
        sig_size = self.header.sig_size
        self.sig_data = None
        if sig_size > 0:
            sig_base = self.header.sig_ptr
            self.sig_data = self.image[code_size:code_size + sig_size]
            self.sig_base = sig_base
        
        # create the cert chain segment
        cert_size = self.header.cert_chain_size
        self.cert_data = None
        if cert_size > 0:
            cert_base = self.header.cert_chain_ptr
            self.cert_data = self.image[code_size + sig_size:code_size + sig_size + cert_size]
            self.cert_base = cert_base

        # create the tail (data after code + sig + certs, but not part of the overlay)
        tail_size = len(self.image) - (code_size + sig_size + cert_size)
        self.tail_data = None
        if tail_size > 0:
            self.tail_base = self.code_base + code_size + sig_size + cert_size
            self.tail_data = self.image[code_size + sig_size + cert_size:]
# -----------------------------------------------------------------------

class MbnImage:
    """Represents the ROM when broken up into its sections."""
    def __init__(self, init_val):
        # parse the header
        self.header = Boot_Hdr(init_val)

        # pull out the image data as it would be loaded from the rom
        image_start = self.header.image_src + Boot_Hdr.MBN_HEADER_SZ
        self.image = init_val[image_start:image_start + self.header.image_size]

        # pull out the overlay, too
        self.overlay_data = init_val[image_start + self.header.image_size:]
        if len(self.overlay_data) == 0: self.overlay_data = None
        else: self.overlay_base = self.header.image_dest_ptr + self.header.image_size
        
        # load the code section
        self.code_base = self.header.image_dest_ptr
        code_size = self.header.code_size
        self.code_data = self.image[:code_size]

        # create the signature segment
        sig_size = self.header.sig_size
        self.sig_data = None
        if sig_size > 0:
            sig_base = self.header.sig_ptr
            self.sig_data = self.image[code_size:code_size + sig_size]
            self.sig_base = sig_base
        
        # create the cert chain segment
        cert_size = self.header.cert_chain_size
        self.cert_data = None
        if cert_size > 0:
            cert_base = self.header.cert_chain_ptr
            self.cert_data = self.image[code_size + sig_size:code_size + sig_size + cert_size]
            self.cert_base = cert_base

        # create the tail (data after code + sig + certs, but not part of the overlay)
        tail_size = len(self.image) - (code_size + sig_size + cert_size)
        self.tail_data = None
        if tail_size > 0:
            self.tail_base = self.code_base + code_size + sig_size + cert_size
            self.tail_data = self.image[code_size + sig_size + cert_size:]

# -----------------------------------------------------------------------

# -----------------------------------------------------------------------
def read_whole_file(li):
    li.seek(0)
    return li.read(li.size())

# -----------------------------------------------------------------------

def dwordAt(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4: 
        return 0
    return struct.unpack('<I', s)[0]

# -----------------------------------------------------------------------

def AddIdbComment(image_base, key, value=None):
    """Print out comments in key/value columns, or just a string if no value is given.

    Non-string values for 'value' are converted to 8-digit hex."""
    if value is None:
        idaapi.describe(image_base, True, key)
    else:
        if type(value) != str: value = '0x%08X' % value
        idaapi.describe(image_base, True, '%-24s %s' % (key + ':', value))

# -----------------------------------------------------------------------


def AddSegment(name, base_address, data):
    """Add a segment to the IDB with some basic options set for convenience."""
    s = idaapi.segment_t()
    
    s.startEA = base_address
    s.endEA = base_address + len(data)
    
    s.bitness = 1 # 32-bit
    
    s.align = idaapi.saRelByte
    s.comb = idaapi.scPub
    
    s.sel = idaapi.setup_selector(0)
    
    idaapi.add_segm_ex(s, name, None, idaapi.ADDSEG_NOSREG | idaapi.ADDSEG_OR_DIE)
    idaapi.mem2base(data, base_address)
# -----------------------------------------------------------------------

def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing 
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # check the MAGIC
    li.seek(0)
    if n > 0: return 0
    if dwordAt(li, 4) == MAGIC_NUM:        # accept the file
		idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
		idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
		return SBL1
    if dwordAt(li, 4) == HDR_FLASH_VER:
        # accept the file
		idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
		idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
		return MBN
# -----------------------------------------------------------------------

def load_file(li, neflags, format):
    
    idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
    idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
    
    if format == SBL1:
        init_val = li.read(li.size())
        rom = SblImage(init_val)
        image_base = rom.header.image_dest_ptr
        entry = image_base
	return load_file_sbl(li, neflags, format)
    elif format == MBN:
        init_val = li.read(li.size())
        rom = MbnImage(init_val)
        image_base = rom.header.image_dest_ptr
        entry = image_base - rom.header.image_src
	return load_file_mbn(li, neflags, format)

        
        # rewind the input file and read its contents
        li.seek(0)
        (image_id, header_flash_ver, image_src, image_dest_ptr, image_size, code_size, signature_ptr, signature_size, cert_chain_ptr, cert_chain_size) = struct.unpack(">IIIIIIIIII", li.read(4*10))
        
        # Load the file data (sans header) into IDA
        li.file2base(entry, entry, data_end, True)
        
        # Define the .text .data and .bss segments
        add_segm(0, entry, data_end, ".text", "CODE")
        add_segm(0, data_start, data_end, ".data", "DATA")
        add_segm(0, data_end, bss_end, ".bss", "BSS")
        
        if DEBUG:
            print "Created File Segments: "
            print "\t.text   0x%.8X - 0x%.8X" % (entry, data_start)
            print "\t.data   0x%.8X - 0x%.8X" % (data_start, data_end)
            print "\t.bss    0x%.8X - 0x%.8X" % (data_end, bss_end)

        # for convenience

# mark the entry point as being the first byte of the loaded image


# -----------------------------------------------------------------------


def load_file_sbl(li, neflags, format):
    
    # set the processor type and enable 'metaarm' so ida disassembles all instructions
	idaapi.set_processor_type("arm:ARMv7-A&R", idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
	idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
    
    # rewind the input file and read its contents
	li.seek(0)
	init_val = li.read(li.size())

        # Load the file data (sans header) into IDA
        rom = SblImage(init_val)
        
        AddSeg(rom.header.image_dest_ptr, rom.header.image_dest_ptr + rom.header.image_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegmentType(rom.header.image_dest_ptr, idaapi.SEG_CODE)
        RenameSeg(rom.header.image_dest_ptr, "CODE")        
       # li.file2base(file_offset, seg1, seg1 + code_seg_size, 0)
        # Load the file data (sans header) into IDA
        li.file2base(80, rom.header.image_dest_ptr, rom.header.image_dest_ptr + rom.header.code_size, 0)
        

        # Define the .text .data and .bss segments
        #AddSegEx(0, rom.header.image_dest_ptr, rom.header.image_dest_ptr + rom.header.code_size, s, ".code", "CODE", ADDSEG_OR_DIE)
       # AddSegment(0, data_start, data_end, ".data", "DATA")
       # AddSegment(0, data_end, bss_end, ".bss", "BSS")
        image_base = rom.header.image_dest_ptr
        entry = rom.header.image_src
        #if DEBUG:
        #        print "Created File Segments: "
        #        print "\t.text   0x%.8X - 0x%.8X" % (entry, data_start)
        #        print "\t.data   0x%.8X - 0x%.8X" % (data_start, data_end)
        #        print "\t.bss    0x%.8X - 0x%.8X" % (data_end, bss_end)

        # mark the entry point as being the first byte of the loaded image
        idaapi.add_entry(rom.header.image_dest_ptr, rom.header.image_dest_ptr, "HEADER", 1)
        
        AddIdbComment(image_base, 'Codeword:            ', rom.header.codeword)
        AddIdbComment(image_base, 'Magic No.:           ', rom.header.magic)
        AddIdbComment(image_base, 'Source Location:     ', rom.header.image_src)
        AddIdbComment(image_base, 'Destination Address: ', rom.header.image_dest_ptr)
        AddIdbComment(image_base, 'Image Size:          ', rom.header.image_size)
        AddIdbComment(image_base, 'Code Size:           ', rom.header.code_size)
        AddIdbComment(image_base, 'Signature Ptr:       ', rom.header.sig_ptr)
        AddIdbComment(image_base, 'Signature Size:      ', rom.header.sig_size)
        AddIdbComment(image_base, 'Cert Chain Ptr:      ', rom.header.cert_chain_ptr)
        AddIdbComment(image_base, 'Cert Chain Size:     ', rom.header.cert_chain_size)
        AddIdbComment(image_base, 'OEM Cert Sel:        ', rom.header.oem_root_cert_sel)
        AddIdbComment(image_base, 'OEM Cert Num:        ', rom.header.oem_num_root_certs)

	return 1




# -----------------------------------------------------------------------


def load_file_mbn(li, neflags, format):
    
    # set the processor type and enable 'metaarm' so ida disassembles all instructions
	idaapi.set_processor_type("arm:ARMv7-A&R", idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
	idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')

    # rewind the input file and read its contents
	li.seek(0)
	init_val = li.read(li.size())

        # Load the file data (sans header) into IDA
        rom = MbnImage(init_val)
        
        #CODE SEGMENT
        #seg1_size = (rom.header.image_dest_ptr + 0xFFF) &(~0xFFF)
        #file_offset = header_size + reloc_header_size*3
        
        AddSeg(rom.header.image_dest_ptr, rom.header.image_dest_ptr + rom.header.image_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegmentType(rom.header.image_dest_ptr, idaapi.SEG_CODE)
        RenameSeg(rom.header.image_dest_ptr, "CODE")

       # li.file2base(file_offset, seg1, seg1 + code_seg_size, 0)
        # Load the file data (sans header) into IDA
        li.file2base(40, rom.header.image_dest_ptr, rom.header.image_dest_ptr + rom.header.code_size, 0)
        #AddSegment('%s_code' % rom, rom.code_base, rom.code_data)
        #if rom.sig_data is not None: AddSegment('%s_sig' % rom, rom.sig_base, rom.sig_data) RenameSeg(rom.header.image_dest_ptr, "CODE")
        #if rom.cert_data is not None: AddSegment('%s_cert' % rom, rom.cert_base, rom.cert_data)
        #if rom.tail_data is not None: AddSegment('%s_tail' % rom, rom.tail_base, rom.tail_data)
        
        
        #dataseg = rom.header.image_dest_ptr
        #dataseg_size = init_val
        #filofs = rom.header.code_size
        #AddSeg(dataseg, rom.header.image_dest_ptr + rom.header.image_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
        #SetSegmentType(dataseg, idaapi.SEG_DATA)
        #RenameSeg(dataseg, "DATA")
        #li.file2base(rom.header.image_dest_ptr, dataseg, dataseg + rom.header.image_dest_ptr + rom.header.image_size, 0)
        # Define the .text .data and .bss segments
        #AddSegEx(rom.header.image_dest_ptr, rom.header.image_dest_ptr + rom.header.code_size, 0, 1, ".code", "CODE", ADDSEG_OR_DIE)
        #AddSegment(0, data_start, data_end, ".data", "DATA")
        #AddSegment(0, data_end, bss_end, ".bss", "BSS")
        image_base = rom.header.image_dest_ptr
        entry = image_base - rom.header.image_src
            #if DEBUG:
            #        print "Created File Segments: "
            #   print "\t.text   0x%.8X - 0x%.8X" % (entry, data_start)
            #   print "\t.data   0x%.8X - 0x%.8X" % (data_start, data_end)
            #   print "\t.bss    0x%.8X - 0x%.8X" % (data_end, bss_end)

        # mark the entry point as being the first byte of the loaded image
        idaapi.add_entry(rom.header.image_dest_ptr, rom.header.image_dest_ptr, "HEADER", 1)
        
        AddIdbComment(image_base, 'Flash Part Version:  ', rom.header.flash_parti_ver)
        AddIdbComment(image_base, 'Source Location:     ', rom.header.image_src)
        AddIdbComment(image_base, 'Destination Address: ', rom.header.image_dest_ptr)
        AddIdbComment(image_base, 'Image Size:          ', rom.header.image_size)
        AddIdbComment(image_base, 'Code Size:           ', rom.header.code_size)
        AddIdbComment(image_base, 'Signature Ptr:       ', rom.header.sig_ptr)
        AddIdbComment(image_base, 'Signature Size:      ', rom.header.sig_size)
        AddIdbComment(image_base, 'Cert Chain Ptr:      ', rom.header.cert_chain_ptr)
        AddIdbComment(image_base, 'Cert Chain Size:     ', rom.header.cert_chain_size)

	return 1



# -----------------------------------------------------------------------

