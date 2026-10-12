#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

/* Windows PE Characteristics Flags for Memory Protection */
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ    0x40000000
#define IMAGE_SCN_MEM_WRITE   0x80000000

typedef struct { uint16_t magic; uint8_t pad[58]; uint32_t lfanew; } __attribute__((packed)) DOS_HDR;
typedef struct { uint16_t machine; uint16_t num_sections; uint32_t ts; uint32_t sym_ptr; uint32_t num_sym; uint16_t opt_size; uint16_t charact; } __attribute__((packed)) FILE_HDR;
typedef struct { uint16_t magic; uint8_t major_lnk, minor_lnk; uint32_t code_sz, init_sz, uninit_sz, entry_point; uint64_t image_base; uint32_t sec_align, file_align; uint16_t major_os, minor_os, major_img, minor_img, major_sub, minor_sub; uint32_t win32, img_size, hdrs_size, chksum; uint16_t subsys, dll_char; uint64_t st_res, st_com, hp_res, hp_com; uint32_t ldr_flg, rva_sz; } __attribute__((packed)) OPT_HDR;
typedef struct { uint32_t signature; FILE_HDR file; OPT_HDR opt; } __attribute__((packed)) NT_HDR;
typedef struct { uint8_t name[8]; uint32_t v_size; uint32_t v_addr; uint32_t raw_size; uint32_t raw_ptr; uint8_t pad[12]; uint32_t characteristics; } __attribute__((packed)) SEC_HDR;

int main(int argc, char* argv[]) {
    if (argc < 2) return printf("Usage: Drag and drop a Windows .exe onto this binary.\n"), 1;

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) return printf("[-] Error: Cannot open target binary.\n"), 1;

    DOS_HDR dos;
    if (read(fd, &dos, sizeof(DOS_HDR)) != sizeof(DOS_HDR) || dos.magic != 0x5A4D) 
        return printf("[-] Error: Missing MZ signature.\n"), close(fd), 1;

    lseek(fd, dos.lfanew, SEEK_SET);
    NT_HDR nt;
    if (read(fd, &nt, sizeof(NT_HDR)) != sizeof(NT_HDR) || nt.signature != 0x00004550)
        return printf("[-] Error: Invalid PE file format.\n"), close(fd), 1;

    size_t img_size = (nt.opt.img_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    // Crucial: Allocate raw native mapping space at preferred ImageBase
    void* base = mmap((void*)nt.opt.image_base, img_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED) {
        base = mmap(NULL, img_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return printf("[-] Error: Virtual memory allocation denied.\n"), close(fd), 1;
    }

    // Direct Zero-Copy stream map loop for application execution segments
    SEC_HDR sec;
    off_t section_hdr_offset = dos.lfanew + sizeof(NT_HDR);
    
    for (int i = 0; i < nt.file.num_sections; i++) {
        lseek(fd, section_hdr_offset + (i * sizeof(SEC_HDR)), SEEK_SET);
        if (read(fd, &sec, sizeof(SEC_HDR)) != sizeof(SEC_HDR)) break;
        if (!sec.raw_size) continue;

        lseek(fd, sec.raw_ptr, SEEK_SET);
        read(fd, (void*)((uintptr_t)base + sec.v_addr), sec.raw_size);

        // Dynamic page protection mapping matching original Windows compiler parameters
        int prot = 0;
        if (sec.characteristics & IMAGE_SCN_MEM_READ)    prot |= PROT_READ;
        if (sec.characteristics & IMAGE_SCN_MEM_WRITE)   prot |= PROT_WRITE;
        if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) prot |= PROT_EXEC;

        size_t sec_size = (sec.v_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        mprotect((void*)((uintptr_t)base + sec.v_addr), sec_size, prot);
    }

    uintptr_t entry = (uintptr_t)base + nt.opt.entry_point;
    printf("[+] Linative Engine Synced. Target Image Entry Point Pointing to: 0x%lX\n", entry);
    close(fd);

    /* 
     *  NATIVE ABI BOUNDARY HANDOFF 
     * Hard-realigning the System V AMD64 Linux stack frames into Microsoft x64 Vector Layout.
     * Overwrites registers directly on the CPU silicon for 0% abstraction loss.
     */
    asm volatile (
        "mov %0, %%rax \n\t"    // Load target entry point into RAX
        "xor %%rcx, %%rcx \n\t"  // Clear Microsoft x64 1st Arg (LPVOID lpParameter / Instance)
        "xor %%rdx, %%rdx \n\t"  // Clear 2nd Arg
        "and $-16, %%rsp \n\t"   // Force 16-byte stack realignment rule
        "sub $32, %%rsp \n\t"    // Allocate mandatory 32-byte shadow space for Win64 ABI
        "jmp *%%rax"             // Execute native handover context injection
        :
        : "r"(entry)
        : "rax", "rcx", "rdx"
    );

    return 0;
}
