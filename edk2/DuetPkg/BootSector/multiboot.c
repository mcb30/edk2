#include <stdint.h>

typedef uint32_t UINT32;
typedef uint32_t ULONG;
typedef int32_t LONG;
typedef uint16_t USHORT;
typedef uint8_t UINT8;
typedef uint8_t UCHAR;


static inline void _bochsbp ( uint32_t eax ) {
	uint32_t discard;

	__asm__ __volatile__ ( "xchgw %%bx, %%bx"
			       : "=a" ( discard )
			       : "0" ( eax ) );
}
#define bochsbp( eax ) _bochsbp ( ( uint32_t ) (eax ) )


typedef struct {          
  UINT32       Signature;     
  UINT32       HeaderCheckSum;
  UINT32       FileLength;
  UINT32       NumberOfImages;
} EFILDR_HEADER;

typedef struct {
  UINT32 CheckSum;
  UINT32 Offset;
  UINT32 Length;
  UINT8  FileName[52];
} EFILDR_IMAGE;

typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
    USHORT e_magic;         // Magic number
    USHORT e_cblp;          // Bytes on last page of file
    USHORT e_cp;            // Pages in file
    USHORT e_crlc;          // Relocations
    USHORT e_cparhdr;       // Size of header in paragraphs
    USHORT e_minalloc;      // Minimum extra paragraphs needed
    USHORT e_maxalloc;      // Maximum extra paragraphs needed
    USHORT e_ss;            // Initial (relative) SS value
    USHORT e_sp;            // Initial SP value
    USHORT e_csum;          // Checksum
    USHORT e_ip;            // Initial IP value
    USHORT e_cs;            // Initial (relative) CS value
    USHORT e_lfarlc;        // File address of relocation table
    USHORT e_ovno;          // Overlay number
    USHORT e_res[4];        // Reserved words
    USHORT e_oemid;         // OEM identifier (for e_oeminfo)
    USHORT e_oeminfo;       // OEM information; e_oemid specific
    USHORT e_res2[10];      // Reserved words
    LONG   e_lfanew;        // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    USHORT  Machine;
    USHORT  NumberOfSections;
    ULONG   TimeDateStamp;
    ULONG   PointerToSymbolTable;
    ULONG   NumberOfSymbols;
    USHORT  SizeOfOptionalHeader;
    USHORT  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    ULONG   VirtualAddress;
    ULONG   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER {
    //
    // Standard fields.
    //
    USHORT  Magic;
    UCHAR   MajorLinkerVersion;
    UCHAR   MinorLinkerVersion;
    ULONG   SizeOfCode;
    ULONG   SizeOfInitializedData;
    ULONG   SizeOfUninitializedData;
    ULONG   AddressOfEntryPoint;
    ULONG   BaseOfCode;
    ULONG   BaseOfData;
    //
    // NT additional fields.
    //
    ULONG   ImageBase;
    ULONG   SectionAlignment;
    ULONG   FileAlignment;
    USHORT  MajorOperatingSystemVersion;
    USHORT  MinorOperatingSystemVersion;
    USHORT  MajorImageVersion;
    USHORT  MinorImageVersion;
    USHORT  MajorSubsystemVersion;
    USHORT  MinorSubsystemVersion;
    ULONG   Reserved1;
    ULONG   SizeOfImage;
    ULONG   SizeOfHeaders;
    ULONG   CheckSum;
    USHORT  Subsystem;
    USHORT  DllCharacteristics;
    ULONG   SizeOfStackReserve;
    ULONG   SizeOfStackCommit;
    ULONG   SizeOfHeapReserve;
    ULONG   SizeOfHeapCommit;
    ULONG   LoaderFlags;
    ULONG   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    UCHAR   Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            ULONG   PhysicalAddress;
            ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

static void start_efiloader ( EFILDR_HEADER *efihdr ) {
	EFILDR_IMAGE *image;
	IMAGE_DOS_HEADER *mz;
	IMAGE_FILE_HEADER *pe;
	IMAGE_OPTIONAL_HEADER *opt;
	IMAGE_SECTION_HEADER *section;
	uint8_t *src;
	uint8_t *dest;
	uint32_t len;
	uint32_t entry;
	uint32_t discard;
	int i;

	/* EfiLoader.efi has to be the first image */
	image = ( EFILDR_IMAGE * ) ( efihdr + 1 );

	/* EfiLoader.efi starts with a DOS MZ header */
	mz = ( ( ( void * ) efihdr ) + image->Offset );
	bochsbp ( mz );

	/* ..which points to a PE header */
	pe = ( ( ( void * ) mz ) + mz->e_lfanew + 4 );
	bochsbp ( pe );
	/* ..followed by an optional header component */
	opt = ( IMAGE_OPTIONAL_HEADER * ) ( pe + 1 );
	bochsbp ( opt );
	/* ..followed by the first section header */
	section = ( IMAGE_SECTION_HEADER * ) ( opt + 1 );
	bochsbp ( section );

	/* Iterate through sections */
	for ( i = 0 ; i < pe->NumberOfSections ; i++, section++ ) {

		/* Identify source address */
		src = ( ( ( void * ) mz ) + section->PointerToRawData );
		bochsbp ( src );

		/* Identify destination address */
		dest = ( ( void * ) ( opt->ImageBase +
				      section->VirtualAddress ) );
		bochsbp ( dest );

		/* Identify size */
		len = section->SizeOfRawData;
		bochsbp ( len );

		/* Copy data */
		while ( len-- )
			*(dest++) = *(src++);
	}

	/* Identify entry point */
	entry = ( opt->ImageBase + opt->AddressOfEntryPoint );
	bochsbp ( entry );

	/* Jump to entry point */
	__asm__ __volatile__ ( "pushl %%eax\n\t"
			       "ret\n\t"
			       : "=a" ( discard )
			       : "0" ( entry ) );
}


#define MULTIBOOT_HEADER_MAGIC 0x1BADB002
#define MB_FLAG_PGALIGN 0x00000001
#define MB_FLAG_MEMMAP 0x00000002
#define MB_FLAG_VIDMODE 0x00000004
#define MB_FLAG_RAW 0x00010000

struct multiboot_header {
	uint32_t magic;
	uint32_t flags;
	uint32_t checksum;
	uint32_t header_addr;
	uint32_t load_addr;
	uint32_t load_end_addr;
	uint32_t bss_end_addr;
	uint32_t entry_addr;
};

struct multiboot_aout_symbol_table {
	uint32_t tabsize;
	uint32_t strsize;
	uint32_t addr;
	uint32_t reserved;
};

struct multiboot_elf_section_header_table {
	uint32_t num;
	uint32_t size;
	uint32_t addr;
	uint32_t shndx;
};

struct multiboot_info {
	uint32_t flags;
	uint32_t mem_lower;
	uint32_t mem_upper;
	uint32_t boot_device;
	uint32_t cmdline;
	uint32_t mods_count;
	uint32_t mods_addr;
	union {
		struct multiboot_aout_symbol_table aout_syms;
		struct multiboot_elf_section_header_table elf_sections;
	} syms;
	uint32_t mmap_length;
	uint32_t mmap_addr;
	uint32_t drives_length;
	uint32_t drives_addr;
	uint32_t config_table;
	uint32_t boot_loader_name;
	uint32_t apm_table;
	uint32_t vbe_control_info;
	uint32_t vbe_mode_info;
	uint16_t vbe_mode;
	uint16_t vbe_interface_seg;
	uint16_t vbe_interface_off;
	uint16_t vbe_interface_len;
};

struct multiboot_module {
	uint32_t mod_start;
	uint32_t mod_end;
	uint32_t string;
	uint32_t reserved;
};

struct multiboot_memory_map {
	uint32_t size;
	uint64_t base_addr;
	uint64_t length;
	uint32_t type;
};

#define MB_FLAGS ( MB_FLAG_MEMMAP | MB_FLAG_RAW )
#define MB_LOAD_ADDR 0x200000

extern char _start[];
extern char _end[];

void mbmain ( struct multiboot_info *info ) {
	EFILDR_HEADER *efihdr;

	bochsbp ( info );
	efihdr = ( ( ( void * ) MB_LOAD_ADDR ) + ( _end - _start ) );
	bochsbp ( efihdr );
	start_efiloader ( efihdr );
}

extern void mbentry ( void );

void mbentry_wrapper ( void ) {
	__asm__ __volatile__ ( "\nmbentry:\n\t"
			       "pushl %ebx\n\t"
			       "jmp mbmain\n\t" );
}

struct multiboot_header mbhdr = {
	.magic = MULTIBOOT_HEADER_MAGIC,
	.flags = MB_FLAGS,
	.checksum = ( 0 - MULTIBOOT_HEADER_MAGIC - MB_FLAGS ),
	.header_addr = ( ( uint32_t ) &mbhdr ),
	.load_addr = MB_LOAD_ADDR,
	.entry_addr = ( ( uint32_t ) mbentry ),
};
