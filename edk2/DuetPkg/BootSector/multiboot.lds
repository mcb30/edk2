ENTRY ( _start )

SECTIONS {

    . = 0x200000;

    _start = .;

    .text : {
	*(.text)
	*(.text.*)
    } = 0x9090

    .rodata : {
	*(.rodata)
	*(.rodata.*)
    }
    .data : {
	*(.data)
	*(.data.*)
    }
    .bss : {
	*(.bss)
	*(.bss.*)
	*(COMMON)
    }
    .stack : {
	*(.stack)
	*(.stack.*)
    }

    . = ALIGN ( 16 );

    _end = .;    

    /DISCARD/ : {
	*(.comment)
	*(.note)
    }
}
