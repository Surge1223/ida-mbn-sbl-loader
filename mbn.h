#ifndef __MBN_H__
#define __MBN_H__

typedef struct mbn {
  int  image_id;
  int  header_part_ver;
  int  image_src;
  int  image_dest_ptr;     
  int  image_size;
  int  code_size;
  int  signature_ptr;
  int  signature_size;
  int  cert_chain_ptr;
    int  cert_chain_size;
} mbn_hdr;


// size of MBN header
#define MBN_HDR_SIZE                       sizeof( mbn_hdr )


//============================

#endif

#ifndef __SBL_H__
#define __SBN_H__

typedef struct sbl {
  int  codeword;
  int  magic;              /* Magic number */
  int  image_id;		   /* image content */
  int  image_src;
  int  image_dest_ptr;
  int  image_size;
  int  code_size;
  int  signature_ptr;
  int  signature_size;
  int  cert_chain_ptr;
  int  cert_chain_size;
  int  oem_root_cert_sel;
  int  oem_num_root_certs;
} sbl_hdr;

// size of SBL header
#define SBL_HDR_SIZE                       sizeof( sbl_hdr )


//============================
#endif
