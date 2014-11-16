/* BFD back-end for M32R COFF files.
   Copyright 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1999, 2000, 2001,
   2002, 2003, 2005, 2007, 2008, 2012  Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "coff/m32r.h"
#include "coff/internal.h"
#include "libcoff.h"

#define COFF_DEFAULT_SECTION_ALIGNMENT_POWER (2)

#define BADMAG(x) \
  ((x).f_magic != M32R_MAGIC_BIG && (x).f_magic != M32R_MAGIC_LITTLE)

/* The page size is a guess based on ELF.  */
#define COFF_PAGE_SIZE 0x1000

enum reloc_type
  {
    R_M32R_NONE = 0,
    R_M32R_16,
    R_M32R_32,
    R_M32R_24,
    R_M32R_10_PCREL,
    R_M32R_18_PCREL,
    R_M32R_26_PCREL,
    R_M32R_HI16_ULO,
    R_M32R_HI16_SLO,
    R_M32R_LO16,
    R_M32R_SDA16,
    R_M32R_max
  };



/* Handle the R_M32R_10_PCREL reloc.  */

static bfd_reloc_status_type
m32r_coff_10_pcrel_reloc (bfd * abfd,
			  arelent * reloc_entry,
			  asymbol * symbol,
			  void * data,
			  asection * input_section,
			  bfd * output_bfd,
			  char ** error_message ATTRIBUTE_UNUSED)
{
  bfd_signed_vma relocation;
  unsigned long x;
  bfd_reloc_status_type ret;
  reloc_howto_type *howto = reloc_entry->howto;
  bfd_vma offset = reloc_entry->address;

  /* If this is a partial link, do nothing.  */
  if (output_bfd != NULL)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  /* Sanity check the address (offset in section).  */
  if (offset > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;

  relocation = symbol->value;
  relocation += symbol->section->output_section->vma;
  relocation += symbol->section->output_offset;
  relocation += reloc_entry->addend;
  /* Make it pc relative.  */
  relocation -=	(input_section->output_section->vma
		 + input_section->output_offset);
  /* These jumps mask off the lower two bits of the current address
     before doing pcrel calculations.  */
  relocation -= (offset & -(bfd_vma) 4);

  if (relocation < -0x200 || relocation > 0x1ff)
    ret = bfd_reloc_overflow;
  else
    ret = bfd_reloc_ok;

  x = bfd_get_16 (abfd, data + offset);
  relocation >>= howto->rightshift;
  relocation <<= howto->bitpos;
  x = (x & ~howto->dst_mask) | (((x & howto->src_mask) + relocation) & howto->dst_mask);
  bfd_put_16 (abfd, (bfd_vma) x, data + offset);

  return ret;
}

/* Do generic partial_inplace relocation.
   This is a local replacement for bfd_elf_generic_reloc.  */

static bfd_reloc_status_type
m32r_coff_generic_reloc (bfd *input_bfd,
			 arelent *reloc_entry,
			 asymbol *symbol,
			 void * data,
			 asection *input_section,
			 bfd *output_bfd,
			 char **error_message ATTRIBUTE_UNUSED)
{
  bfd_reloc_status_type ret;
  bfd_vma relocation;
  bfd_byte *inplace_address;

  /* If this is a partial link, do nothing.  */
  if (output_bfd != NULL)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  return bfd_reloc_continue;

  /* Sanity check the address (offset in section).  */
  if (reloc_entry->address > bfd_get_section_limit (input_bfd, input_section))
    return bfd_reloc_outofrange;

  ret = bfd_reloc_ok;
  if (bfd_is_und_section (symbol->section))
    ret = bfd_reloc_undefined;

  /* Get symbol value.  (Common symbols are special.)  */
  if (bfd_is_com_section (symbol->section))
    relocation = 0;
  else
    relocation = symbol->value;

  relocation += symbol->section->output_section->vma;
  relocation += symbol->section->output_offset;
  relocation += reloc_entry->addend;

  inplace_address = (bfd_byte *) data + reloc_entry->address;

#define DOIT(x) \
  x = ( (x & ~reloc_entry->howto->dst_mask) \
        | (((x & reloc_entry->howto->src_mask) + relocation) \
	   & reloc_entry->howto->dst_mask) )

  switch (reloc_entry->howto->size)
    {
    case 1:
      {
	short x = bfd_get_16 (input_bfd, inplace_address);
	DOIT (x);
      	bfd_put_16 (input_bfd, (bfd_vma) x, inplace_address);
      }
      break;
    case 2:
      {
	unsigned long x = bfd_get_32 (input_bfd, inplace_address);
	DOIT (x);
      	bfd_put_32 (input_bfd, (bfd_vma) x, inplace_address);
      }
      break;
    default:
      BFD_ASSERT (0);
    }

  return ret;
}

/* Handle the R_M32R_SDA16 reloc.
   This reloc is used to compute the address of objects in the small data area
   and to perform loads and stores from that area.
   The lower 16 bits are sign extended and added to the register specified
   in the instruction, which is assumed to point to _SDA_BASE_.  */

static bfd_reloc_status_type
m32r_coff_sda16_reloc (bfd *abfd ATTRIBUTE_UNUSED,
		       arelent *reloc_entry,
		       asymbol *symbol ATTRIBUTE_UNUSED,
		       void * data ATTRIBUTE_UNUSED,
		       asection *input_section,
		       bfd *output_bfd,
		       char **error_message ATTRIBUTE_UNUSED)
{
  /* If this is a partial link, do nothing.  */
  if (output_bfd != NULL)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  /* FIXME: not sure what to do here yet.  But then again, the linker
     may never call us.  */
  abort ();
}

/* Handle the R_M32R_HI16_[SU]LO relocs.
   HI16_SLO is for the add3 and load/store with displacement instructions.
   HI16_ULO is for the or3 instruction.
   For R_M32R_HI16_SLO, the lower 16 bits are sign extended when added to
   the high 16 bytes so if the lower 16 bits are negative (bit 15 == 1) then
   we must add one to the high 16 bytes (which will get subtracted off when
   the low 16 bits are added).
   These relocs have to be done in combination with an R_M32R_LO16 reloc
   because there is a carry from the LO16 to the HI16.  Here we just save
   the information we need; we do the actual relocation when we see the LO16.
   This code is copied from the elf32-mips.c.  We also support an arbitrary
   number of HI16 relocs to be associated with a single LO16 reloc.  The
   assembler sorts the relocs to ensure each HI16 immediately precedes its
   LO16.  However if there are multiple copies, the assembler may not find
   the real LO16 so it picks the first one it finds.  */

struct m32r_hi16
{
  struct m32r_hi16 *next;
  int type; /* One of R_M32R_HI16_[SU]LO.  */
  bfd_byte *addr;
  bfd_vma addend;
};

/* FIXME: This should not be a static variable.  */

static struct m32r_hi16 *m32r_coff_hi16_list;

static bfd_reloc_status_type
m32r_coff_hi16_reloc (bfd *abfd ATTRIBUTE_UNUSED,
		      arelent *reloc_entry,
		      asymbol *symbol,
		      void * data,
		      asection *input_section,
		      bfd *output_bfd,
		      char **error_message ATTRIBUTE_UNUSED)
{
  bfd_reloc_status_type ret;
  bfd_vma relocation;
  struct m32r_hi16 *n;

  /* If this is a partial link, do nothing.  */
  if (output_bfd != NULL)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  /* Sanity check the address (offset in section).  */
  if (reloc_entry->address > bfd_get_section_limit (abfd, input_section))
    return bfd_reloc_outofrange;

  ret = bfd_reloc_ok;
  if (bfd_is_und_section (symbol->section))
    ret = bfd_reloc_undefined;

  /* Get symbol value.  (Common symbols are special.)  */
  if (bfd_is_com_section (symbol->section))
    relocation = 0;
  else
    relocation = symbol->value;

  relocation += symbol->section->output_section->vma;
  relocation += symbol->section->output_offset;
  relocation += reloc_entry->addend;

  /* Save the information, and let LO16 do the actual relocation.  */
  n = bfd_malloc ((bfd_size_type) sizeof *n);
  if (n == NULL)
    return bfd_reloc_outofrange;
  n->type = reloc_entry->howto->type;
  n->addr = (bfd_byte *) data + reloc_entry->address;
  n->addend = relocation;
  n->next = m32r_coff_hi16_list;
  m32r_coff_hi16_list = n;

  return ret;
}

/* Do an R_M32R_LO16 relocation.  This is a straightforward 16 bit
   inplace relocation; this function exists in order to do the
   R_M32R_HI16_[SU]LO relocation described above.  */

static bfd_reloc_status_type
m32r_coff_lo16_reloc (bfd *input_bfd,
		      arelent *reloc_entry,
		      asymbol *symbol,
		      void * data,
		      asection *input_section,
		      bfd *output_bfd,
		      char **error_message)
{
  /* If this is a partial link, do nothing.  */
  if (output_bfd != NULL)
    {
      reloc_entry->address += input_section->output_offset;
      return bfd_reloc_ok;
    }

  if (m32r_coff_hi16_list != NULL)
    {
      struct m32r_hi16 *l;

      l = m32r_coff_hi16_list;
      while (l != NULL)
	{
	  unsigned long insn;
	  unsigned long val;
	  unsigned long vallo;
	  struct m32r_hi16 *next;

	  /* Do the HI16 relocation.  Note that we actually don't need
	     to know anything about the LO16 itself, except where to
	     find the low 16 bits of the addend needed by the LO16.  */
	  insn = bfd_get_32 (input_bfd, l->addr);
	  vallo = (bfd_get_32 (input_bfd, (bfd_byte *) data + reloc_entry->address)
		   & 0xffff);
	  if (l->type == R_M32R_HI16_SLO)
	    vallo = (vallo ^ 0x8000) - 0x8000;
	  val = ((insn & 0xffff) << 16) + vallo;
	  val += l->addend;

	  /* Reaccount for sign extension of low part.  */
	  if (l->type == R_M32R_HI16_SLO
	      && (val & 0x8000) != 0)
	    val += 0x10000;

	  insn = (insn &~ (bfd_vma) 0xffff) | ((val >> 16) & 0xffff);
	  bfd_put_32 (input_bfd, (bfd_vma) insn, l->addr);

	  next = l->next;
	  free (l);
	  l = next;
	}

      m32r_coff_hi16_list = NULL;
    }

  /* Now do the LO16 reloc in the usual way.  */
  return m32r_coff_generic_reloc (input_bfd, reloc_entry, symbol, data,
				  input_section, output_bfd, error_message);
}

static reloc_howto_type coff_m32r_howto_table[] =
{
  /* This reloc does nothing.  */
  HOWTO (R_M32R_NONE,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 m32r_coff_generic_reloc, /* special_function */
	 "R_M32R_NONE",		/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 16 bit absolute relocation.  */
  HOWTO (R_M32R_16,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 m32r_coff_generic_reloc, /* special_function */
	 "R_M32R_16",		/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 32 bit absolute relocation.  */
  HOWTO (R_M32R_32,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield, /* complain_on_overflow */
	 m32r_coff_generic_reloc, /* special_function */
	 "R_M32R_32",		/* name */
	 FALSE,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 24 bit address.  */
  HOWTO (R_M32R_24,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 24,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_unsigned, /* complain_on_overflow */
	 m32r_coff_generic_reloc, /* special_function */
	 "R_M32R_24",		/* name */
	 FALSE,			/* partial_inplace */
	 0xffffff,		/* src_mask */
	 0xffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A PC Relative 10-bit relocation, shifted by 2.
     This reloc is complicated because relocations are relative to pc & -4.
     i.e. branches in the right insn slot use the address of the left insn
     slot for pc.  */
  /* ??? It's not clear whether this should have partial_inplace set or not.
     Branch relaxing in the assembler can store the addend in the insn,
     and if bfd_install_relocation gets called the addend may get added
     again.  */
  HOWTO (R_M32R_10_PCREL,	/* type */
	 2,	                /* rightshift */
	 1,	                /* size (0 = byte, 1 = short, 2 = long) */
	 10,	                /* bitsize */
	 TRUE,	                /* pc_relative */
	 0,	                /* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 m32r_coff_10_pcrel_reloc, /* special_function */
	 "R_M32R_10_PCREL",	/* name */
	 FALSE,	                /* partial_inplace */
	 0xff,		        /* src_mask */
	 0xff,   		/* dst_mask */
	 TRUE),			/* pcrel_offset */

  /* A relative 18 bit relocation, right shifted by 2.  */
  HOWTO (R_M32R_18_PCREL,	/* type */
	 2,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 m32r_coff_generic_reloc, /* special_function */
	 "R_M32R_18_PCREL",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 TRUE),			/* pcrel_offset */

  /* A relative 26 bit relocation, right shifted by 2.  */
  /* ??? It's not clear whether this should have partial_inplace set or not.
     Branch relaxing in the assembler can store the addend in the insn,
     and if bfd_install_relocation gets called the addend may get added
     again.  */
  HOWTO (R_M32R_26_PCREL,	/* type */
	 2,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 26,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 m32r_coff_generic_reloc, /* special_function */
	 "R_M32R_26_PCREL",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffffff,		/* src_mask */
	 0xffffff,		/* dst_mask */
	 TRUE),			/* pcrel_offset */

  /* High 16 bits of address when lower 16 is or'd in.  */
  HOWTO (R_M32R_HI16_ULO,	/* type */
	 16,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 m32r_coff_hi16_reloc,	/* special_function */
	 "R_M32R_HI16_ULO",	/* name */
	 FALSE,			/* partial_inplace */
	 0x0000ffff,		/* src_mask */
	 0x0000ffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* High 16 bits of address when lower 16 is added in.  */
  HOWTO (R_M32R_HI16_SLO,	/* type */
	 16,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 m32r_coff_hi16_reloc,	/* special_function */
	 "R_M32R_HI16_SLO",	/* name */
	 FALSE,			/* partial_inplace */
	 0x0000ffff,		/* src_mask */
	 0x0000ffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* Lower 16 bits of address.  */
  HOWTO (R_M32R_LO16,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont, /* complain_on_overflow */
	 m32r_coff_lo16_reloc,	/* special_function */
	 "R_M32R_LO16",		/* name */
	 FALSE,			/* partial_inplace */
	 0x0000ffff,		/* src_mask */
	 0x0000ffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* Small data area 16 bits offset.  */
  HOWTO (R_M32R_SDA16,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_signed, /* complain_on_overflow */
	 m32r_coff_sda16_reloc,	/* special_function */
	 "R_M32R_SDA16",	/* name */
	 FALSE,			/* partial_inplace */  /* FIXME: correct? */
	 0x0000ffff,		/* src_mask */
	 0x0000ffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */
};

struct coff_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char coff_reloc_val;
};

static const struct coff_reloc_map m32r_reloc_map[] =
{
  { BFD_RELOC_NONE, R_M32R_NONE, },
  { BFD_RELOC_16, R_M32R_16, },
  { BFD_RELOC_32, R_M32R_32 },
  { BFD_RELOC_M32R_24, R_M32R_24 },
  { BFD_RELOC_M32R_10_PCREL, R_M32R_10_PCREL },
  { BFD_RELOC_M32R_18_PCREL, R_M32R_18_PCREL },
  { BFD_RELOC_M32R_26_PCREL, R_M32R_26_PCREL },
  { BFD_RELOC_M32R_HI16_ULO, R_M32R_HI16_ULO },
  { BFD_RELOC_M32R_HI16_SLO, R_M32R_HI16_SLO },
  { BFD_RELOC_M32R_LO16, R_M32R_LO16 },
  { BFD_RELOC_M32R_SDA16, R_M32R_SDA16 },
};

static reloc_howto_type *
coff_m32r_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			     bfd_reloc_code_real_type code)
{
  unsigned int i;
  for (i = 0; i < sizeof (m32r_reloc_map) / sizeof (struct coff_reloc_map); i++)
    {
      if (m32r_reloc_map[i].bfd_reloc_val == code)
	return &coff_m32r_howto_table[(int) m32r_reloc_map[i].coff_reloc_val];
    }
  return 0;
}
#define coff_bfd_reloc_type_lookup coff_m32r_reloc_type_lookup

static reloc_howto_type *
coff_m32r_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			     const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < (sizeof (coff_m32r_howto_table)
	    / sizeof (coff_m32r_howto_table[0]));
       i++)
    if (coff_m32r_howto_table[i].name != NULL
	&& strcasecmp (coff_m32r_howto_table[i].name, r_name) == 0)
      return &coff_m32r_howto_table[i];

  return NULL;
}
#define coff_bfd_reloc_name_lookup coff_m32r_reloc_name_lookup

static void
rtype2howto (arelent *cache_ptr, struct internal_reloc *dst)
{
  BFD_ASSERT (dst->r_type < (unsigned int) R_M32R_max);
  cache_ptr->howto = &coff_m32r_howto_table[dst->r_type];
}

#define RTYPE2HOWTO(internal, relocentry) rtype2howto(internal,relocentry)

#define SWAP_IN_RELOC_OFFSET	H_GET_32
#define SWAP_OUT_RELOC_OFFSET	H_PUT_32
#define CALC_ADDEND(abfd, ptr, reloc, cache_ptr) \
  cache_ptr->addend = reloc.r_offset;

/* Clear the r_spare field in relocs.  */
#define SWAP_OUT_RELOC_EXTRA(abfd,src,dst) \
  do { \
       dst->r_spare[0] = 0; \
       dst->r_spare[1] = 0; \
     } while (0)

#define __A_MAGIC_SET__

/* Enable M32R-specific hacks in coffcode.h.  */

#define COFF_M32R

#define bfd_pe_print_pdata NULL

#include "coffcode.h"

#ifndef TARGET_BIG_SYM
#define TARGET_BIG_SYM m32rcoff_big_vec
#endif

#ifndef TARGET_BIG_NAME
#define TARGET_BIG_NAME "coff-m32r"
#endif

#ifndef TARGET_LITTLE_SYM
#define TARGET_LITTLE_SYM m32rcoff_little_vec
#endif

#ifndef TARGET_LITTLE_NAME
#define TARGET_LITTLE_NAME "coff-m32rle"
#endif

/* Forward declaration for use initialising alternative_target field.  */
extern const bfd_target TARGET_LITTLE_SYM;

CREATE_BIG_COFF_TARGET_VEC (TARGET_BIG_SYM, TARGET_BIG_NAME, D_PAGED, 0, 0, &TARGET_LITTLE_SYM, COFF_SWAP_TABLE)
CREATE_LITTLE_COFF_TARGET_VEC (TARGET_LITTLE_SYM, TARGET_LITTLE_NAME, D_PAGED, 0, 0, &TARGET_BIG_SYM, COFF_SWAP_TABLE)
