// hex_viewer.c
// Compile with: clang -O2 -o hex_viewer hex_viewer.c -lncurses

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdint.h>
#include <ncurses.h>

#ifdef __linux__
#include <elf.h>
#endif

// Structure for ELF header (32/64 bit compatible)
typedef struct {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} ELF_Header;

// PE/COFF structures
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_Header;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} PE_DataDirectory;

typedef struct {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    PE_DataDirectory DataDirectory[16];
} PE_OptionalHeader;

// Global file data
static uint8_t *file_data = NULL;
static size_t file_size = 0;
static char filename[256] = {0};
static int is_elf = 0;
static int is_pe = 0;
static int hex_offset = 0;
static int selected_tab = 0;
static int hex_cursor_x = 0, hex_cursor_y = 0;
static int current_view = 0; // 0=hex, 1=ascii, 2=struct, 3=raw
static int rows = 0, cols = 0;

// Color pairs
#define COLOR_HEADER 1
#define COLOR_ADDR   2
#define COLOR_HEX    3
#define COLOR_ASCII  4
#define COLOR_CURSOR 5

void init_colors() {
    start_color();
    init_pair(COLOR_HEADER, COLOR_CYAN, COLOR_BLACK);
    init_pair(COLOR_ADDR, COLOR_GREEN, COLOR_BLACK);
    init_pair(COLOR_HEX, COLOR_YELLOW, COLOR_BLACK);
    init_pair(COLOR_ASCII, COLOR_WHITE, COLOR_BLACK);
    init_pair(COLOR_CURSOR, COLOR_BLACK, COLOR_WHITE);
}

int load_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    file_data = (uint8_t*)malloc(file_size);
    if (!file_data) {
        fclose(fp);
        return 0;
    }
    
    fread(file_data, 1, file_size, fp);
    fclose(fp);
    
    strncpy(filename, path, sizeof(filename) - 1);
    
    // Detect file type
    if (file_size >= 4 && file_data[0] == 0x7F && 
        file_data[1] == 'E' && file_data[2] == 'L' && file_data[3] == 'F') {
        is_elf = 1;
        is_pe = 0;
    } else if (file_size >= 2 && file_data[0] == 'M' && file_data[1] == 'Z') {
        is_pe = 1;
        is_elf = 0;
    }
    
    return 1;
}

void draw_header() {
    attron(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    mvprintw(0, 0, "=== HACKER HEX VIEWER ===");
    attroff(COLOR_PAIR(COLOR_HEADER) | A_BOLD);
    
    mvprintw(0, 28, "File: %s", filename);
    mvprintw(0, 50, "Size: %zu bytes", file_size);
    
    if (is_elf) mvprintw(0, 70, "[ELF]");
    else if (is_pe) mvprintw(0, 70, "[PE/COFF]");
    else mvprintw(0, 70, "[RAW]");
    
    // Tabs
    const char *tabs[] = {"[HEX VIEW]", "[ASCII]", "[STRUCTURES]", "[RAW DATA]"};
    int x = 2;
    for (int i = 0; i < 4; i++) {
        if (i == current_view) attron(A_REVERSE);
        mvprintw(1, x, "%s", tabs[i]);
        if (i == current_view) attroff(A_REVERSE);
        x += strlen(tabs[i]) + 2;
    }
    
    mvhline(2, 0, '-', cols - 1);
}

void draw_hex_view() {
    int bytes_per_row = (cols - 10) / 4; // 3 hex + 1 space
    if (bytes_per_row > 16) bytes_per_row = 16;
    
    int max_rows = rows - 5;
    int start_offset = hex_offset;
    
    for (int row = 0; row < max_rows; row++) {
        int offset = start_offset + (row * bytes_per_row);
        if (offset >= (int)file_size) break;
        
        // Address
        attron(COLOR_PAIR(COLOR_ADDR));
        mvprintw(row + 3, 0, "0x%08X:", offset);
        attroff(COLOR_PAIR(COLOR_ADDR));
        
        // Hex dump
        attron(COLOR_PAIR(COLOR_HEX));
        for (int col = 0; col < bytes_per_row; col++) {
            int idx = offset + col;
            if (idx < (int)file_size) {
                int x_pos = 10 + (col * 3);
                if (row == hex_cursor_y && col == hex_cursor_x && current_view == 0) {
                    attron(COLOR_PAIR(COLOR_CURSOR));
                    mvprintw(row + 3, x_pos, "%02X", file_data[idx]);
                    attroff(COLOR_PAIR(COLOR_CURSOR));
                } else {
                    mvprintw(row + 3, x_pos, "%02X", file_data[idx]);
                }
            } else {
                mvprintw(row + 3, 10 + (col * 3), "  ");
            }
        }
        attroff(COLOR_PAIR(COLOR_HEX));
        
        // ASCII dump
        attron(COLOR_PAIR(COLOR_ASCII));
        mvprintw(row + 3, 10 + (bytes_per_row * 3) + 2, "|");
        for (int col = 0; col < bytes_per_row; col++) {
            int idx = offset + col;
            if (idx < (int)file_size) {
                char c = isprint(file_data[idx]) ? file_data[idx] : '.';
                mvaddch(row + 3, 11 + (bytes_per_row * 3) + col, c);
            } else {
                mvaddch(row + 3, 11 + (bytes_per_row * 3) + col, ' ');
            }
        }
        mvprintw(row + 3, 11 + (bytes_per_row * 3) + bytes_per_row, "|");
        attroff(COLOR_PAIR(COLOR_ASCII));
    }
}

void draw_ascii_view() {
    int bytes_per_row = cols - 10;
    int max_rows = rows - 5;
    
    for (int row = 0; row < max_rows; row++) {
        int offset = hex_offset + row * bytes_per_row;
        if (offset >= (int)file_size) break;
        
        attron(COLOR_PAIR(COLOR_ADDR));
        mvprintw(row + 3, 0, "0x%08X: ", offset);
        attroff(COLOR_PAIR(COLOR_ADDR));
        
        attron(COLOR_PAIR(COLOR_ASCII));
        for (int col = 0; col < bytes_per_row && offset + col < (int)file_size; col++) {
            char c = file_data[offset + col];
            if (isprint(c)) mvaddch(row + 3, 10 + col, c);
            else mvaddch(row + 3, 10 + col, '.');
        }
        attroff(COLOR_PAIR(COLOR_ASCII));
    }
}

void draw_elf_info() {
    if (!is_elf || file_size < 52) {
        mvprintw(4, 2, "Not an ELF file or file too small");
        return;
    }
    
    ELF_Header *elf = (ELF_Header*)file_data;
    
    mvprintw(4, 2, "=== ELF HEADER ===");
    mvprintw(5, 4, "Magic: %02X %02X %02X %02X", 
             elf->e_ident[0], elf->e_ident[1], elf->e_ident[2], elf->e_ident[3]);
    mvprintw(6, 4, "Class: %s", elf->e_ident[4] == 1 ? "ELF32" : "ELF64");
    mvprintw(7, 4, "Endianness: %s", elf->e_ident[5] == 1 ? "Little" : "Big");
    mvprintw(8, 4, "Type: 0x%04X", elf->e_type);
    mvprintw(9, 4, "Machine: 0x%04X", elf->e_machine);
    mvprintw(10, 4, "Entry Point: 0x%016lX", (unsigned long)elf->e_entry);
    mvprintw(11, 4, "Program Headers: %d (offset: 0x%lx)", 
             elf->e_phnum, (unsigned long)elf->e_phoff);
    mvprintw(12, 4, "Section Headers: %d (offset: 0x%lx)", 
             elf->e_shnum, (unsigned long)elf->e_shoff);
    
    // Parse program headers if available
    if (elf->e_phoff > 0 && elf->e_phnum > 0) {
        mvprintw(14, 2, "=== PROGRAM HEADERS ===");
        int y = 15;
        for (int i = 0; i < elf->e_phnum && i < 5 && y < rows-2; i++) {
            uint64_t offset = elf->e_phoff + (i * elf->e_phentsize);
            if (offset + 8 <= file_size) {
                uint32_t p_type = *(uint32_t*)(file_data + offset);
                mvprintw(y++, 4, "  [%d] Type: 0x%08X Offset: 0x%lx", 
                         i, p_type, (unsigned long)offset);
            }
        }
    }
}

void draw_pe_info() {
    if (!is_pe || file_size < 64) {
        mvprintw(4, 2, "Not a PE file or file too small");
        return;
    }
    
    // Find PE header (after DOS stub)
    uint32_t pe_offset = *(uint32_t*)(file_data + 0x3C);
    if (pe_offset + 4 > file_size || 
        memcmp(file_data + pe_offset, "PE\0\0", 4) != 0) {
        mvprintw(4, 2, "Invalid PE signature");
        return;
    }
    
    COFF_Header *coff = (COFF_Header*)(file_data + pe_offset + 4);
    
    mvprintw(4, 2, "=== COFF HEADER ===");
    mvprintw(5, 4, "Machine: 0x%04X %s", coff->Machine,
             coff->Machine == 0x14C ? "x86" : 
             coff->Machine == 0x8664 ? "x64" : "Unknown");
    mvprintw(6, 4, "Sections: %d", coff->NumberOfSections);
    mvprintw(7, 4, "TimeDateStamp: 0x%08X", coff->TimeDateStamp);
    mvprintw(8, 4, "Characteristics: 0x%04X", coff->Characteristics);
    
    // Optional header
    if (coff->SizeOfOptionalHeader > 0) {
        uint8_t *opt_start = file_data + pe_offset + 4 + sizeof(COFF_Header);
        uint16_t magic = *(uint16_t*)opt_start;
        
        mvprintw(10, 2, "=== OPTIONAL HEADER ===");
        mvprintw(11, 4, "Magic: 0x%04X %s", magic,
                 magic == 0x10B ? "PE32" : 
                 magic == 0x20B ? "PE32+" : "Unknown");
        
        if (magic == 0x10B && coff->SizeOfOptionalHeader >= 68) {
            uint32_t entry = *(uint32_t*)(opt_start + 16);
            uint32_t image_base = *(uint32_t*)(opt_start + 28);
            mvprintw(12, 4, "Entry Point: 0x%08X", entry);
            mvprintw(13, 4, "Image Base: 0x%08X", image_base);
        } else if (magic == 0x20B && coff->SizeOfOptionalHeader >= 72) {
            uint32_t entry = *(uint32_t*)(opt_start + 16);
            uint64_t image_base = *(uint64_t*)(opt_start + 24);
            mvprintw(12, 4, "Entry Point: 0x%08X", entry);
            mvprintw(13, 4, "Image Base: 0x%016lX", (unsigned long)image_base);
        }
    }
    
    // Section headers
    int section_offset = pe_offset + 4 + sizeof(COFF_Header) + coff->SizeOfOptionalHeader;
    mvprintw(15, 2, "=== SECTION HEADERS ===");
    int y = 16;
    for (int i = 0; i < coff->NumberOfSections && i < 10 && y < rows-2; i++) {
        char name[9] = {0};
        memcpy(name, file_data + section_offset + (i * 40), 8);
        uint32_t vsize = *(uint32_t*)(file_data + section_offset + (i * 40) + 8);
        uint32_t vaddr = *(uint32_t*)(file_data + section_offset + (i * 40) + 12);
        uint32_t raw_size = *(uint32_t*)(file_data + section_offset + (i * 40) + 16);
        uint32_t raw_ptr = *(uint32_t*)(file_data + section_offset + (i * 40) + 20);
        
        mvprintw(y++, 4, "[%2d] %-8s VA:0x%08X VS:0x%08X RS:0x%08X RP:0x%08X",
                 i, name, vaddr, vsize, raw_size, raw_ptr);
    }
}

void draw_raw_view() {
    int max_bytes = (rows - 5) * (cols - 10);
    int offset = hex_offset;
    
    attron(COLOR_PAIR(COLOR_HEX));
    for (int i = 0; i < max_bytes && offset + i < (int)file_size; i++) {
        int row = 3 + (i / (cols - 10));
        int col = 10 + (i % (cols - 10));
        if (row < rows - 2) {
            mvprintw(row, col, "%02X", file_data[offset + i]);
        }
    }
    attroff(COLOR_PAIR(COLOR_HEX));
}

void draw_status() {
    mvhline(rows - 2, 0, '-', cols - 1);
    attron(COLOR_PAIR(COLOR_HEADER));
    mvprintw(rows - 1, 0, 
             "[Arrow Keys] Navigate  [Tab] Switch View  [PgUp/PgDn] Page  [q] Quit");
    mvprintw(rows - 1, cols - 30, "Offset: 0x%08X", hex_offset);
    attroff(COLOR_PAIR(COLOR_HEADER));
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }
    
    if (!load_file(argv[1])) {
        fprintf(stderr, "Failed to load file: %s\n", argv[1]);
        return 1;
    }
    
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    init_colors();
    
    getmaxyx(stdscr, rows, cols);
    
    int running = 1;
    while (running) {
        getmaxyx(stdscr, rows, cols);
        clear();
        draw_header();
        
        switch (current_view) {
            case 0: draw_hex_view(); break;
            case 1: draw_ascii_view(); break;
            case 2: 
                if (is_elf) draw_elf_info();
                else if (is_pe) draw_pe_info();
                else mvprintw(4, 2, "No structure info available for this file type");
                break;
            case 3: draw_raw_view(); break;
        }
        
        draw_status();
        refresh();
        
        int ch = getch();
        switch (ch) {
            case 'q':
                running = 0;
                break;
            case KEY_UP:
                if (hex_offset >= 16) hex_offset -= 16;
                break;
            case KEY_DOWN:
                if (hex_offset + 16 < (int)file_size) hex_offset += 16;
                break;
            case KEY_LEFT:
                if (hex_cursor_x > 0) hex_cursor_x--;
                else if (hex_offset >= 16) {
                    hex_offset -= 16;
                    hex_cursor_x = 15;
                }
                break;
            case KEY_RIGHT:
                if (hex_cursor_x < 15) hex_cursor_x++;
                else if (hex_offset + 16 < (int)file_size) {
                    hex_offset += 16;
                    hex_cursor_x = 0;
                }
                break;
            case KEY_NPAGE:
                hex_offset += (rows - 5) * 16;
                if (hex_offset >= (int)file_size) hex_offset = file_size - (rows - 5) * 16;
                if (hex_offset < 0) hex_offset = 0;
                break;
            case KEY_PPAGE:
                hex_offset -= (rows - 5) * 16;
                if (hex_offset < 0) hex_offset = 0;
                break;
            case 9: // Tab
                current_view = (current_view + 1) % 4;
                hex_offset = 0;
                hex_cursor_x = hex_cursor_y = 0;
                break;
            case 'h':
                current_view = 0;
                break;
            case 'a':
                current_view = 1;
                break;
            case 's':
                current_view = 2;
                break;
            case 'r':
                current_view = 3;
                break;
        }
        
        if (hex_offset < 0) hex_offset = 0;
        if (hex_offset > (int)file_size - 16) hex_offset = file_size > 16 ? file_size - 16 : 0;
    }
    
    endwin();
    free(file_data);
    return 0;
}
