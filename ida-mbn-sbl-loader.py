# Ida Mbn Sbl and ELF test loader - by @Surge1223
# 
# Mostly from scratch to figure out fucking segments
#
# Relocation table isnt correct yet, send me an email if you
# know how to correct this. Also support for osbl, dbl, and pbl
# can be added if theres a need, just add the header (or adjust the SBL hdr)
# and where  to unpack from

from idaapi import *
from idautils import *
from idc import *
import os
import sys
import struct

# Magic numbers filled in for boot headers
FLASH_PARTI_VERSION             = 3 
NOR_SBL1_HEADER                 = '<II72s'
NOR_SBL1_HEADER_SZ              = struct.calcsize(NOR_SBL1_HEADER)
NOR_CODE_WORD                   = 0x844bdcd1
MAGIC_NUM                       = 0x73d71034
PAGE_SIZE_MAGIC_NUM             = 0x7D0B435A
MAGIC_COOKIE                    = 0x33836685
MBN_IMAGE_ID                    = 0x00000005
HDR_FLASH_VER                   = 0x00000003
MBN_HEADER_SIZE_B               = 40
SBL_HEADER_SIZE_B               = 80
SBL_HEADER_OFFSET_SIZE          = 0x28
SBL_VIRTUAL_BLOCK_MAGIC_NUM     = 0xD48B54C6
MBN_HDR_LENGTH                  = 20
SBL                             = "SBL FORMAT IMG"
MBN                             = "MBN FORMAT IMG"
ELF                             = "ELF FORMAT IMG"

# ELF Definitions
ELF_HDR_SIZE              = 52          
ELF_PHDR_SIZE             = 32          
ELFINFO_MAG0_INDEX        = 0
ELFINFO_MAG1_INDEX        = 1
ELFINFO_MAG2_INDEX        = 2
ELFINFO_MAG3_INDEX        = 3
ELFINFO_MAG0              = '\x7F\x45\x4c\x46\x01\x01\x01'
ELFINFO_CLASS_INDEX       = 4
ELFINFO_CLASS_32          = '\x01'
ELFINFO_VERSION_INDEX     = 6
ELFINFO_VERSION_CURRENT   = '\x01'
MAX_PHDRS_COUNT           = 100
ELF_BLOCK_ALIGN           = 0x1000
PROGRAM_HEADER_LEN        = 8
ALLOWED_IMG_ALIGN_VALUES = 0x100000
ALIGNVALUE_1MB             = 0x100000
ALIGNVALUE_4MB             = 0x400000
ELFMAG                     = 0x464C457F 
# ELF Program Header Types
NULL_TYPE                 = 0x0
LOAD_TYPE                 = 0x1
DYNAMIC_TYPE              = 0x2
INTERP_TYPE               = 0x3
NOTE_TYPE                 = 0x4
SHLIB_TYPE                = 0x5
PHDR_TYPE                 = 0x6
TLS_TYPE                  = 0x7

    
# -----------------------------------------------------------------------

class Buf(object):
    def __init__(self, dat) :
        self.pos = 0
        self.dat = dat
    def read(self, n):
        x = self.dat[self.pos : self.pos + n]
        self.pos += n
        return x
    def seek(self, pos):
        self.pos = pos
    def readUnpack(self, fmt):
        sz = struct.calcsize(fmt)
        return struct.unpack_from("<" + fmt, self.read(sz))
    
# -----------------------------------------------------------------------

class Mbn_Hdr(object):
    # mbn header has a 40 byte header with 10 entries
    MBN_HEADER_SZ	= 40
    MBN_HEADER		= '<IIIIIIIIII'
    PAD_SZ			= 0
    MAGIC_NUM		        = 0x73d71034
    
    def __init__(self, init_val):
        
        self.image_id = init_val
        self.flash_parti_ver = init_val
        self.image_src = init_val
        self.image_dest_ptr = init_val
        self.image_size = init_val
        self.code_size = init_val
        self.sig_ptr = init_val
        self.sig_size = init_val
        self.cert_chain_ptr = init_val
        self.cert_chain_size = init_val
        self.magic_number1 = init_val
        self.version = init_val
        self.OS_type = init_val
        self.boot_apps_parti_entry = init_val
        self.boot_apps_size_entry = init_val
        self.boot_apps_ram_loc = init_val
        self.reserved_ptr = init_val
        self.reserved_1 = init_val
        self.reserved_2 = init_val
        self.reserved_3 = init_val

    def Mbn_Hdrsz(self):
        init_hdrobjs = [self.image_id,
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
         self.reserved_3
        ]
        print ("hdr len size {} ".format(str(len(init_hdrobjs))))
        return len(init_hdrobjs)

    def getLength(self):
      return MBN_HDR_LENGTH

    def genMbn_segs(self):
            image_id              = self.image_id
            flash_parti_ver       = self.flash_parti_ver
            image_src             = self.image_src
            image_dest_ptr        = self.image_dest_ptr
            image_size            = self.image_size
            code_size             = self.code_size
            sig_ptr               = self.sig_ptr
            sig_size              = self.sig_size
            cert_chain_ptr        = self.cert_chain_ptr
            cert_chain_size       = self.cert_chain_size
            hdr_offset            = str(self.Mbn_Hdrsz())
            header_start          = self.image_dest_ptr
            header_end            = self.image_dest_ptr + hdr_offset
            code_start            = header_end + self.image_dest_ptr
            code_end              = code_start + code_size
            data_start            = 0
            data_end              = 0
            bss_start             = 0
            bss_end               = 0
            rodata_start          = 0
            rodata_end            = 0
            
    def getSize(self):
        self.size = str(self.Mbn_Hdrsz())
        return self.size

# -----------------------------------------------------------------------

class Sbl_Hdr:
    # sbl header has a 80 byte header with 20 entries
    MBN_HEADER_SZ	= 80
    SBL_HEADER		= '<IIIIIIIIIIIIIIIIIIII'
    s = struct.Struct('<II72s')
    PAD_SZ			= 0
    MAGIC_NUM		        = 0x844bdcd1
    
    def __init__(self, init_val):
 #     unpacked_data       = (Sbl_Hdr.s).unpack(init_val)  
      self.codeword        = init_val
      self.magic           = init_val
      self.image_id        = init_val
      self.reserved_1      = init_val
      self.reserved_2      = init_val
      self.image_src       = init_val
      self.image_dest_ptr  = init_val
      self.image_size      = init_val
      self.code_size       = init_val
      self.sig_ptr         = init_val
      self.sig_size        = init_val
      self.cert_chain_ptr  = init_val
      self.cert_chain_size = init_val
      self.reserved_3      = init_val
      self.reserved_4      = init_val
      self.reserved_5      = init_val
      self.reserved_6      = init_val
      self.reserved_7      = init_val
      self.reserved_8      = init_val
      self.reserved_9      = init_val


    def Sbl_Hdrsz(self):
        init_hdrobjs = [self.codeword,
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
                self.reserved_3,
                self.reserved_4,
                self.reserved_5,
                self.reserved_6,
                self.reserved_7,
                self.reserved_8,
                self.reserved_9
               ]
        return len(init_hdrobjs)

    def getLength(self):
      return SBL_HDR_LENGTH

    def genSbl_segs(self):
            image_id              = self.image_id
            magic                 = self.magic
            codeword              = self.codeword
            image_src             = self.image_src
            image_dest_ptr        = self.image_dest_ptr
            image_size            = self.image_size
            code_size             = self.code_size
            sig_ptr               = self.sig_ptr
            sig_size              = self.sig_size
            cert_chain_ptr        = self.cert_chain_ptr
            cert_chain_size       = self.cert_chain_size
            hdr_offset            = str(self.Sbl_Hdrsz())
            header_start          = self.image_dest_ptr
            header_end            = self.image_dest_ptr + hdr_offset
            code_start            = header_end + self.image_dest_ptr
            code_end              = code_start + code_size
            data_start            = 0
            data_end              = 0
            bss_start             = 0
            bss_end               = 0
            rodata_start          = 0
            rodata_end            = 0
            
    def getSize(self):
        self.size = str(self.Sbl_Hdrsz())
        return self.size
        
# -----------------------------------------------------------------------
# ph = program header
# sh = section header

class Elf32_Ehdr(object):
    # elf32 header has a 52 byte header
    ELF_HDR_SIZE = 52
    ELF_HEADER		= 'HHIIIIIHHHHHH'
    s = struct.Struct('16sHHIIIIIHHHHHH')
    PAD_SZ			= 0
    MAGIC_NUM		        = 0x464C457F
    
    
    def __init__(self, init_val):
       self.e_ident = ELFINFO_MAG0
       self.e_type = 0x2
       self.e_machine = 0xA4
       self.e_version = 0x1
       self.e_entry = init_val
       self.e_phoff = 52
       self.e_shoff = init_val
       self.e_flags = 3
       self.e_ehsize = 52
       self.e_phentsize = 32
       self.e_phnum = 1
       self.e_shentsize = init_val
       self.e_shnum = init_val
       self.e_shstrndx = init_val
      
    def Elf32_Hdrsz(self):
        init_hdrobjs = [self.e_ident,
                self.e_type,
                self.e_machine,
                self.e_version,
                self.e_entry,
                self.e_phoff,
                self.e_shoff,
                self.e_flags,
                self.e_ehsize,
                self.e_phentsize,
                self.e_phnum,
                self.e_shentsize,
                self.e_shnum,
                self.e_shstrndx
               ]
        return len(init_hdrobjs)

    def getLength(self):
      return len(self.Elf32_Hdrsz())

    def genElf_segs(self):
            e_ident                = self.e_ident
            e_type                 = self.e_type
            e_machine              = self.e_machine
            e_version              = self.e_version
            e_entry                = self.e_entry
            e_phoff                = self.e_phoff
            e_shoff                = self.e_shoff
            e_flags                = self.e_flags
            e_ehsize               = self.e_ehsize
            e_phentsize            = self.e_phentsize
            e_phnum                = self.e_phnum
            e_shentsize            = self.e_shentsize
            e_shnum                = self.e_shnum
            e_shstrndx             = self.e_shstrndx
            phdr_size              = self.e_phentsize
            data_start             = 0
            data_end               = 0
            bss_start              = 0
            bss_end                = 0
            rodata_start           = 0
            rodata_end             = 0
            
    def getSize(self):
        self.size = str(self.Elf32_Hdrsz())
        return self.size

#----------------------------------------------------------------------------
# ELF program header table (Phdr)

class Elf32_Phdr:

    # elf32 phdr has a 32 byte header
    ELF_PHDR_SIZE = 32
    ELF_HEADER		= '<HHIIIIIHHHHHH'
    s = struct.Struct('16sHHIIIIIHHHHHH')
    PAD_SZ			= 0
    MAGIC_NUM		        = 0x464C457F
   
    def __init__(self, init_val):
      self.p_type         = 1
      self.p_offset       = 0x001000
      self.p_vaddr        = init_val
      self.p_paddr        = init_val
      self.p_filesz       = init_val
      self.p_memsz        = init_val
      self.p_flags        = 7
      self.p_align        = 0
      
      if make_reloc:
          self.p_align = ALLOWED_IMG_ALIGN_VALUES
          self.p_flags = 0x8000007
      else:
          self.p_flags        = 7
          self.p_align        = 0	 


    def Elf32_PHdrsz(self):
        init_hdrobjs = [self.p_type,
                self.p_offset,
                self.p_vaddr,
                self.p_paddr,
                self.p_filesz,
                self.p_memsz,
                self.p_flags,
                self.p_align
               ]
        return len(init_hdrobjs)

    def getLength(self):
        return len(self.Elf32_PHdrsz())

# -----------------------------------------------------------------------

class SegmentInfo:
   def __init__(self):
      self.flag  = 0
      self.start_addr = 0
   def printValues(self):
      print ('Flag: ' + str(self.flag))
      print ('Start Address: ' + str(hex(self.start_addr)))

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

def hexRead(li, off):
    li.seek(off)
    h = li.read(12)
    if len(h) < 12:
        return 0
    return struct.unpack('<III', h)[0]


# -----------------------------------------------------------------------

def procElf(li, init_val) :
    fe = li.read(struct.calcsize(init_val))
    return struct.unpack("<" + init_val, self.read(fe))

# -----------------------------------------------------------------------

def FormatHex(HexVal):
    HexValue = ('0x' + str(HexVal))
    if type(HexVal) != str:
        HexValue =  str(HexVal)
        return FormatHex(str(HexValue))
        
    if (HexValue [0:2] == '0x'):       
        HexValue = HexValue [2:]
        while (len (HexValue) < 8):
            HexValue =  str(HexValue) + '0'
    HexValue = '0x' + HexValue
    print("load addr: {}".format(str((HexVal))))
    #print ("Start Address: {}".format(str(HexValue)))
    print (HexValue)
    return HexValue

# -----------------------------------------------------------------------

def armcinstr(ea):
    search_start = ea
    search_end = search_start + 0x10000
    addr = idc.FindBinary(search_start, SEARCH_DOWN, "?? ?? 00 EA")
    inst = DecodeInstruction(addr)
    kmain_addr = FindBinary(ea, SEARCH_DOWN, "?? ?? 00 FA")
    if inst.get_canon_mnem() == 'B':
        reset = DecodeInstruction(addr).Op1.addr
        arm_undefined = DecodeInstruction(addr + 0x4).Op1.addr
        arm_syscall = DecodeInstruction(addr + 0x8).Op1.addr
        arm_prefetch_abort = DecodeInstruction(addr + 0xC).Op1.addr
        arm_reserved = DecodeInstruction(addr + 0x10).Op1.addr
        arm_irq = DecodeInstruction(addr + 0x14).Op1.addr
        arm_fiq = DecodeInstruction(addr + 0x18).Op1.addr
        MakeName(reset, "reset")
        MakeName(arm_undefined, "arm_undefined")
        idaapi.add_entry(arm_undefined, arm_undefined, "arm_undefined", 1)        
        MakeName(arm_syscall, "arm_syscall")
        idaapi.add_entry(arm_syscall, arm_syscall, "arm_syscall", 1)
        MakeName(arm_prefetch_abort, "arm_prefetch_abort")
        idaapi.add_entry(arm_prefetch_abort, arm_prefetch_abort, "arm_prefetch_abort", 1)
        MakeName(arm_reserved, "arm_reserved")
        idaapi.add_entry(arm_reserved, arm_reserved, "arm_reserved", 1)
        MakeName(arm_irq, "arm_irq")
        idaapi.add_entry(arm_irq, arm_irq, "arm_irq", 1)
        MakeName(arm_fiq, "arm_fiq")
        idaapi.add_entry(arm_fiq, arm_fiq, "arm_fiq", 1)
        MakeName(kmain_addr, "kmain")
        idaapi.add_entry(kmain_addr, kmain_addr, "kmain", 1)
    if ea == idc.BADADDR:
        idc.Message("Can't find func\n")
        return 0

    else:
        idc.Message("new func is at 0x%08x\n" % addr)
        MakeName(kmain_addr, "kmain")
        idaapi.add_entry(kmain_addr, kmain_addr, "kmain", 1)
        return 0

def arminstruc():
    addr = ((str(hex(dwordAt(li, 12)))) [:-1])
    inst = DecodeInstruction(addr)
    reset = inst(addr).Op1.addr
    arm_undefined = inst(addr + 0x4).Op1.addr
    arm_syscall = inst(addr + 0x8).Op1.addr
    arm_prefetch_abort = inst(addr + 0x12).Op1.addr
    arm_reserved = inst(addr + 0x16).Op1.addr
    arm_irq = inst(addr + 0x20).Op1.addr
    arm_fiq = inst(addr + 0x24).Op1.addr
    
    if not inst.get_canon_mnem() == 'B':
        return 0
    else:
        MakeName(reset, "reset")
        idaapi.add_entry(reset, reset, "reset", 1)
        MakeName(arm_undefined, "arm_undefined")
        idaapi.add_entry(arm_undefined, arm_undefined, "arm_undefined", 1)        
        MakeName(arm_syscall, "arm_syscall")
        idaapi.add_entry(arm_syscall, arm_syscall, "arm_syscall", 1)
        MakeName(arm_prefetch_abort, "arm_prefetch_abort")
        idaapi.add_entry(arm_prefetch_abort, arm_prefetch_abort, "arm_prefetch_abort", 1)
        MakeName(arm_reserved, "arm_reserved")
        idaapi.add_entry(arm_reserved, arm_reserved, "arm_reserved", 1)
        MakeName(arm_irq, "arm_irq")
        idaapi.add_entry(arm_irq, arm_irq, "arm_irq", 1)
        MakeName(arm_fiq, "arm_fiq")
        idaapi.add_entry(arm_fiq, arm_fiq, "arm_fiq", 1)
        return 0

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

def AddIdbComment(image_base, key, value=None):
    """Print out comments in key/value columns, or just a string if no value is given.
    Non-string values for 'value' are converted to 8-digit hex."""
    
    if value is None:
        idaapi.describe(image_base, True, key)
    else:
        if type(value) != str: value = '0x%08X' % value
        idaapi.describe(image_base, True, '%-24s %s' % (key + ':', value))

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
    if hexRead(li, 0) != None:
        print ("hex at first 4 bytes 0 {} ".format(str(hexRead(li, 0x80 + 0x20))))
        entry = (str(hex(dwordAt(li, 12))))
        if (str(hex(dwordAt(li, 12)))) [-1] == 'L':
            entry = (str(hex(dwordAt(li, 12)))) [:-1]
        print ("entry address: " + (entry))
    if dwordAt(li, 4) == MAGIC_NUM:
        idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
        idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
        idc.ChangeConfig('ARM_SIMPLIFY = NO')
        return SBL

    if hexRead(li, 4) == HDR_FLASH_VER:
        print ("hex at first 4 bytes 1 {} ".format(str(hexRead(li, 4))))
        idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
        idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
        idc.ChangeConfig('ARM_SIMPLIFY = NO')
        return MBN

    if hexRead(li, 0) == 1179403647:
        print ("hex at first 4 bytes 2 {} ".format(str(hexRead(li, 0x52 + 0x24))))
        idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
        idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
        idc.ChangeConfig('ARM_SIMPLIFY = NO')
        return ELF
    
    return

# -----------------------------------------------------------------------

def load_file(li, neflags, format):
    
    idaapi.set_processor_type("arm:ARMv7-A&R", SETPROC_ALL|SETPROC_FATAL)
    idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')
    
    if format == SBL:
        return load_file_sbl(li, neflags, format)
    if format == MBN:
        return load_file_mbn(li, neflags, format)
    if format == ELF:
        return load_file_elf(li, neflags, format)
    return

# -----------------------------------------------------------------------

def load_file_mbn(li, neflags, format):

    # set the processor type and enable 'metaarm' so ida disassembles all instructions
    idaapi.set_processor_type("arm:ARMv7-A&R", idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
    idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')

    # rewind the input file and read its contents
    # extract the values from the rom into the class
    li.seek(0)
   
    # initialize class Mbn_Hdr with size of input file
    init_val = li.read(li.size())
    print ("size: " + str(len(init_val)))
    rom = Mbn_Hdr(init_val)
    
    offs = rom.Mbn_Hdrsz()
    offset = li.tell()
    FormatHex(rom.image_dest_ptr)
    
    # gen the segment class object references
    rom.genMbn_segs()
    rom.getSize()
    
    (rom.image_id,
     rom.flash_parti_ver,
     rom.image_src,
     rom.image_dest_ptr,
     rom.image_size,
     rom.code_size,
     rom.sig_ptr,
     rom.sig_size,
     rom.cert_chain_ptr,
     rom.cert_chain_size) = struct.unpack_from(rom.MBN_HEADER, init_val)

    image_base = rom.image_dest_ptr - rom.image_src 
    image_size = rom.sig_size + rom.cert_chain_size
    start = 0x28
    ''' This is necessary to 4byte align the image_size'''
    if (image_size % 4) != 0:
        image_size += (4 - (image_size % 4))
    rom.image_size = image_size

    ''' This is necessary to 4byte align the code_size'''
    if (rom.code_size % 4) != 0:
        rom.code_size += (4 - (rom.code_size % 4))
    code_size = rom.code_size

    hdr_offset = rom.Mbn_Hdrsz()
    header_start = rom.image_dest_ptr 
    header_end =  0x140
    code_start = rom.image_dest_ptr + header_end
    code_end = code_start + rom.code_size
    li.seek(40)


    li.file2base(0, header_start, header_start + image_size, True)
    
    #CODE SEGMENT
    codeseg = header_start
    AddSeg(codeseg, codeseg + code_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegClass(codeseg, "CODE")
    RenameSeg(codeseg, "CODE")
    li.file2base(start, codeseg, codeseg + code_size,  0)
    

    #BOOT SEGMENT
    bootseg = header_start
    AddSeg(bootseg, bootseg + header_end, 0, 1, idaapi.saRelByte, idaapi.scPub)
    SetSegClass(bootseg, "CODE")
    RenameSeg(bootseg, ".text.boot")
    li.file2base(start, bootseg, bootseg + header_end, 0)

    #DATA SEGMENT    
    def finddataseg(image_base):
        search_start = image_base
        search_end = search_start + 0x100

        data_insts = FindBinary(search_start, SEARCH_DOWN, "?? 00 ?? ?? ?? 10 ?? ?? ?? 20 ?? ??")
        if data_insts == BADADDR or data_insts > search_end:
            return False

        data_start = Dword(DecodeInstruction(data_insts + 4).Op2.addr)
        data_end = Dword(DecodeInstruction(data_insts + 8).Op2.addr)
        data_end = (data_end + 3) & ~3

        AddSeg(data_start, data_end, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegClass(data_start, "DATA")
        RenameSeg(data_start, "DATA")
        return True

    finddataseg(header_start)
    idaapi.add_entry(header_start, header_start, "_start", 1)
    idaapi.set_segm_addressing(idaapi.get_segm_by_name(".text.boot"), 1)
    idaapi.set_segm_addressing(idaapi.get_segm_by_name("CODE"), 0)
    idaapi.analyze_area(bootseg, header_end)
    armcinstr(bootseg)
    idaapi.analyze_area(bootseg, header_end)
    idaapi.analyze_area(codeseg, code_end)




    AddIdbComment(image_base, 'Flash Part Version:  ', rom.flash_parti_ver)
    AddIdbComment(image_base, 'Source Location:     ', rom.image_src)
    AddIdbComment(image_base, 'Destination Address: ', rom.image_dest_ptr)
    AddIdbComment(image_base, 'Image Size:          ', rom.image_size)
    AddIdbComment(image_base, 'Code Size:           ', rom.code_size)
    AddIdbComment(image_base, 'Signature Ptr:       ', rom.sig_ptr)
    AddIdbComment(image_base, 'Signature Size:      ', rom.sig_size)
    AddIdbComment(image_base, 'Cert Chain Ptr:      ', rom.cert_chain_ptr)
    AddIdbComment(image_base, 'Cert Chain Size:     ', rom.cert_chain_size)

    return 1


# -----------------------------------------------------------------------

def load_file_sbl(li, neflags, format):

    # set the processor type and enable 'metaarm' so ida disassembles all instructions
    idaapi.set_processor_type("arm:ARMv7-A&R", idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
    idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')

    # rewind the input file and read its contents
    # extract the values from the rom into the class
    li.seek(0)
   
    # initialize class Sbl_Hdr with size of input file
    init_val = li.read(li.size())
    rom = Sbl_Hdr(init_val)
    offs = rom.Sbl_Hdrsz()
    size = li.tell()
        
    # gen the segment class object references
    rom.genSbl_segs()
    rom.getSize()
    
    (rom.codeword,
     rom.magic,
     rom.image_id,
     rom.reserved_1,
     rom.reserved_2,
     rom.image_src,
     rom.image_dest_ptr,
     rom.image_size,
     rom.code_size,
     rom.sig_ptr,
     rom.sig_size,
     rom.cert_chain_ptr,
     rom.cert_chain_size,
     rom.oem_root_cert_sel,
     rom.oem_num_root_certs,
     rom.reserved_5,
     rom.reserved_6,
     rom.reserved_7, 
     rom.reserved_8,
     rom.reserved_9) = struct.unpack_from(Sbl_Hdr.SBL_HEADER, init_val)

    

    image_base = rom.image_dest_ptr - rom.image_src
    image_size = rom.code_size + rom.sig_size +rom.cert_chain_size
    start = 0x285
    ''' This is necessary to 4byte align the image_size'''
    if (image_size % 4) != 0:
        image_size += (4 - (image_size % 4))
    rom.image_size = image_size

    ''' This is necessary to 4byte align the code_size'''
    if (rom.code_size % 4) != 0:
        rom.code_size += (4 - (rom.code_size % 4))
    code_size = rom.code_size - start

    hdr_offset = rom.Sbl_Hdrsz()
    header_start = rom.image_dest_ptr 
    header_end = rom.image_dest_ptr + 80
    code_start = rom.image_dest_ptr
    code_end = code_start + rom.code_size
    start = 0x285

    li.file2base(start, code_start, code_start + code_size, 0)

    #BOOT SEGMENT
    idc.AddSeg(header_start, header_end, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegmentType(header_start, idaapi.SEG_CODE)
    RenameSeg(header_start, ".text.boot")
    
    #CODE SEGMENT
    AddSeg(code_start, code_start + rom.code_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegmentType(code_start, idaapi.SEG_CODE)
    RenameSeg(code_start, "CODE")
       
    image_base = rom.image_dest_ptr
    image_code = (rom.image_dest_ptr + rom.image_size)
    idaapi.add_entry(header_start, header_start, "_start", 1)
    idaapi.set_segm_addressing(idaapi.getseg(header_start), 1)

    AddIdbComment(image_base, 'Codeword:            ', rom.codeword)
    AddIdbComment(image_base, 'Magic No.:           ', rom.magic)
    AddIdbComment(image_base, 'Source Location:     ', rom.image_src)
    AddIdbComment(image_base, 'Destination Address: ', rom.image_dest_ptr)
    AddIdbComment(image_base, 'Image Size:          ', rom.image_size)
    AddIdbComment(image_base, 'Code Size:           ', rom.code_size)
    AddIdbComment(image_base, 'Signature Ptr:       ', rom.sig_ptr)
    AddIdbComment(image_base, 'Signature Size:      ', rom.sig_size)
    AddIdbComment(image_base, 'Cert Chain Ptr:      ', rom.cert_chain_ptr)
    AddIdbComment(image_base, 'Cert Chain Size:     ', rom.cert_chain_size)
    AddIdbComment(image_base, 'OEM Cert Sel:        ', rom.oem_root_cert_sel)
    AddIdbComment(image_base, 'OEM Cert Num:        ', rom.oem_num_root_certs)


    return 1

# -----------------------------------------------------------------------


def load_file_elf(li, neflags, format):

# set the processor type and enable 'metaarm' so ida disassembles all instructions
    idaapi.set_processor_type("arm:ARMv7-A&R", idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
    idc.ChangeConfig('ARM_DEFAULT_ARCHITECTURE = metaarm')

    # rewind the input file and read its contents
    # extract the values from the rom into the class
    li.seek(0)

    # initialize class ELF Hdr with size of input file
    init_val = li.read(li.size())
    b = Buf(init_val)
    rom = Elf32_Ehdr(b)
    offs = rom.Elf32_Hdrsz()
    size = li.tell()
    
    # gen the segment class object references
    rom.genElf_segs()
    rom.getSize()
    

    rom.e_ident = li.read(16)
    (rom.e_type,
         rom.e_machine,
         rom.e_version,
         rom.e_entry,
         rom.e_phoff,
         rom.e_shoff,
         rom.e_flags,
         rom.e_ehsize,
         rom.e_phentsize,
         rom.e_phnum,
         rom.e_shentsize,
         rom.e_shnum,
         rom.e_shstrndx) = b.readUnpack(Elf32_Ehdr.ELF_HEADER)

    hdr_offset = rom.Elf32_Hdrsz()
    header_start = rom.e_entry 
    header_end = rom.e_entry + rom.e_phoff
    code_start = rom.e_entry
    code_end = rom.e_entry + rom.e_ehsize
    start = 0x28

    #CODE SEGMENT
    AddSeg(code_start, code_start + rom.e_ehsize, 0, 1, idaapi.saRelPara, idaapi.scPub)
    SetSegmentType(code_start, idaapi.SEG_CODE)
    RenameSeg(code_start, "CODE")
       
    image_base = rom.e_entry
    image_code = (rom.e_entry + rom.e_ehsize)
    idaapi.add_entry(header_start, header_start, "HEADER", 1)
    idaapi.set_segm_addressing(idaapi.getseg(header_start), 1)


    AddIdbComment(image_base, 'e_type:              ', rom.e_type)
    AddIdbComment(image_base, 'e_machine:           ', rom.e_machine)
    AddIdbComment(image_base, 'e_version:           ', rom.e_version)
    AddIdbComment(image_base, 'Image Entry VA:      ', rom.e_entry)
    AddIdbComment(image_base, 'ELFH_PHOFF_OFFSET:   ', rom.e_phoff)
    AddIdbComment(image_base, 'ELFH_SHOFF_OFFSET:   ', rom.e_shoff)
    AddIdbComment(image_base, 'e_flags:             ', rom.e_flags)
    AddIdbComment(image_base, 'ELF HDR SZ (bytes):  ', rom.e_ehsize)
    AddIdbComment(image_base, 'PHDR Entry SZ:       ', rom.e_phentsize)
    AddIdbComment(image_base, 'ELFH_PHNUM_OFFSET:   ', rom.e_phnum)
    AddIdbComment(image_base, 'SHDR Entry SZ:       ', rom.e_shentsize)
    AddIdbComment(image_base, 'ELFH_SHNUM_OFFSET:   ', rom.e_shnum)
    AddIdbComment(image_base, 'Section HDR (sh) index: ', rom.e_shstrndx)
   
    return 1

