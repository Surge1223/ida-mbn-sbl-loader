Instructions:

Copy ida-mbn-sbl-loader.py and/or ida-mbn-sbl-loader.pmc to $IDADIR/loaders/

load the attached aboot.mbn and it should load it right in

I dont have my windows pc with me atm, but the plw and visual studio source will be uploaded soon.  It uses the same files as the mac and linux versions though so it shouldn�t be too hard to figure out. The windows version it quite a bit more extensive though.  i kept it cpp source simple for now though


These exist but I commented out the segment adding code because there's gotta be a easier way to find the segments without having the source itself,  I'm not sure if maybe FindInstructions as defined in the idaapi could be used to make finding these segs less of a "hardcoded"  and more of  "dynamically found" type of thing. Below are the actual addresses of the data_start (of the DATA segment) and .bss etc
 

  Segment Sections
   00     .ARM.exidx
   01     .text.boot .text .rodata .ARM.exidx .data .bss
   02

Segment type:	Absolute symbols
__dtor_list = 0x88F3AE6C
__ctor_list = 0x88F3AE6C
__data_end = 0x88F3AE6C
__data_start = 0x88E54740
__data_start_rom = 0x88E54740
__ctor_end = 0x88F3AE6C
_end_of_ram = 0x89000000
__bss_start = 0x88F3AE6C
_end = 0x88F4DC54
__dtor_end = 0x88F3AE6C
