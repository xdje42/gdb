# Linker script for ARM COFF.
# Based on i386coff.sc by Ian Taylor <ian@cygnus.com>.
test -z "$ENTRY" && ENTRY=_start
if test -z "${DATA_ADDR}"; then
  if test "$LD_FLAG" = "N" || test "$LD_FLAG" = "n"; then
    DATA_ADDR=.
  fi
fi

# These are substituted in as variables in order to get '}' in a shell
# conditional expansion.
CTOR='.ctor : {
    *(SORT(.ctors.*))
    *(.ctor)
  }'
DTOR='.dtor : {
    *(SORT(.dtors.*))
    *(.dtor)
  }'

cat <<EOF
OUTPUT_FORMAT("${OUTPUT_FORMAT}", "${BIG_OUTPUT_FORMAT}", "${LITTLE_OUTPUT_FORMAT}")
${LIB_SEARCH_DIRS}

${RELOCATING+ENTRY (${ENTRY})}

SECTIONS
{
  /* Leave the bottom page empty so NULL is not used by anything
     accidentally.  */
  . = . + 0x1000;

  .text ${RELOCATING+ ALIGN(0x1000)} : {
    *(.init)
    *(.text*)
    *(.rodata)
    *(.rdata)
    ${CONSTRUCTING+ __CTOR_LIST__ = . ; 
			LONG (-1); *(.ctors); *(.ctor); LONG (0); }
    ${CONSTRUCTING+ __DTOR_LIST__ = . ; 
			LONG (-1); *(.dtors); *(.dtor);  LONG (0); }
    *(.fini)
    ${RELOCATING+ etext  = .;}
    ${RELOCATING+ _etext = .;}
  }
  .data ${RELOCATING+${DATA_ADDR-0x40000 + (ALIGN(0x8) & 0xfffc0fff)}} : {
    *(.data*)

    ${RELOCATING+*(.gcc_exc*)}
    ${RELOCATING+__EH_FRAME_BEGIN__ = . ;}
    ${RELOCATING+*(.eh_fram*)}
    ${RELOCATING+__EH_FRAME_END__ = . ;}
    ${RELOCATING+LONG(0);}

    ${RELOCATING+ edata  =  .;}
    ${RELOCATING+ _edata  =  .;}
  }

  ${CONSTRUCTING+${RELOCATING-$CTOR}}
  ${CONSTRUCTING+${RELOCATING-$DTOR}}

  /* NOTE: crt0.o zeroes memory from __bss_start to _end.  */
  .bss ${RELOCATING+ ALIGN(0x8)} :
  { 					
    ${RELOCATING+ __bss_start = . ;}
    *(.bss)
    *(COMMON)
    ${RELOCATING+ __bss_end = . ;}
  }
  ${RELOCATING+ end = .;}
  ${RELOCATING+ _end = .;}
  ${RELOCATING+ __end__ = .;}

  /* Ideally this would live at the top of memory, but we don't know
     what that is, and crt0 is coded to use _stack.  Pick a number.  */
  ${RELOCATING+ PROVIDE (_stack = 0x7ffffc);}

  .stab  0 ${RELOCATING+(NOLOAD)} : 
  {
    [ .stab ]
  }
  .stabstr  0 ${RELOCATING+(NOLOAD)} :
  {
    [ .stabstr ]
  }
}
EOF
