Instructions:

Copy any one of, or all three of the loaders (ida-mbn-sbl-loader.py, ida-mbn-sbl-loader.plw, ida-mbn-sbl-loader.pmc( to $IDADIR/loaders/

load the attached aboot.mbn and it should load it right in

The ida-mbn-sbl-loader.cpp is the source for the plw (Windows version) of the plugin and can be built with visual studio (only tested and confirmed to build for me on 2013 version though).  I havent uploaded the sln or studio build config files yet but it uses the same files as the mac and linux versions though so it shouldn't be too hard to figure out.


These exist but I commented out the segment adding code because there's gotta be a easier way to find the segments without having the source itself,  I'm not sure if maybe FindInstructions as defined in the idaapi could be used to make finding these segs less of a "hardcoded"  and more of  "dynamically found" type of thing. 
 

  Segment Sections
   00     .ARM.exidx
   01     .text.boot .text .rodata .ARM.exidx .data .bss
   02
   
   
Below are the actual addresses of the data_start (of the DATA segment) and .bss etc that were provided by a source in the know. The goal for now is to get this loader to recognize those data and bss addresses and add them correctly. The loader by Ralekdev does almost achieve this, but not quite you got download his loader from here and test yourself to see. https://github.com/ralekdev/mbn_ida_loader/blob/master/mbn_ida_loader.py

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
