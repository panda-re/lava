#ifndef __PANDA_HYPERCALL_STRUCT_H__
#define __PANDA_HYPERCALL_STRUCT_H__

// For LAVA use only

/*
 * Keep me in sync between PANDA and LAVA repos
 */

typedef struct panda_hypercall_struct {
  unsigned long long action;      // label / query / etc
  unsigned long long buf;         // ptr to memory we want labeled or queried or ...
  unsigned long len;         // number of bytes to label or query or ...
  unsigned long label_num;   // if labeling, this is the label number.  if querying this should be zero
  //  uint32_t offset;      // offset is used for what?
  unsigned long long src_filename;  // if querying from src this is a char * to filename.  
  unsigned long long src_linenum;   // if querying from src this is the line number
  unsigned long long src_ast_node_name;     // if querying from src this is the name of the l-value queries 
} PandaHypercallStruct;

#endif

