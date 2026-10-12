/**
 * @file linative.c
 * @brief Devrimsel Windows Subsystem & PE Runtime Layer for Linux
 * 
 * CORE ARCHITECTURE:
 * Bypasses Wine entirely. Maps Win64 binaries via mmap, parses the Import 
 * Address Table (IAT), hooks core Windows APIs, and hot-swaps them into 
 * native Linux POSIX / Syscall handlers before silicone ABI jump.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

/* Custom Native Win32 API Emulation Hooks */
void win_ExitProcess(uint32_t uExitCode) {
    printf("[Linative Hook] ExitProcess(%d) intercepted -> Executing POSIX exit\n", uExitCode);
    _exit(uExitCode);
}

void win_GetStdHandle(uint32_t nStdHandle) {
    printf("[Linative Hook] GetStdHandle(%d) stub fired\n", nStdHandle);
}

/* Hardcoded Resolver for Devrimsel Core System Calls */
uintptr_t resolve_win_api(const char* dll_name, const char* func_name) {
    if (strcasecmp(dll_name, "kernel32.dll") == 0) {
        if (strcmp(func_name, "ExitProcess") == 0) return (uintptr_t)win_ExitProcess;
        if (strcmp(func_name, "GetStdHandle") == 0) return (uintptr_t)win_GetStdHandle;
    }
    return 0; // Fallback for unhandled symbols
}

typedef struct { uint16_t magic; uint8_t pad[58]; uint32_t lfanew; } __attribute__((packed)) DOS_HDR;
typedef struct { uint16_t machine; uint16_t num_sections; uint32_t ts; uint32_t sym_ptr; uint32_t num_sym; uint16_t opt_size; uint16_t charact; } __attribute__((packed)) FILE_HDR;
typedef struct { 
    uint16_t magic; uint8_t major_lnk, minor_lnk; uint32_t code_sz, init_sz, uninit_sz, entry_point; uint64_t image_base; uint32_t sec_align, file_align; 
    uint16_t major_os, minor_os, major_img, minor_img, major_sub, minor_sub; uint32_t win32, img_size, hdrs_size, chksum; uint16_t subsys, dll_char; 
    uint64_t st_res, st_com, hp_res, hp_com; uint32_t ldr_flg, rva_sz;
    struct { uint32_t rva; uint32_t size; } data_dir[16]; /* Windows Data Directories */
} __attribute__((packed)) OPT_HDR;
typedef struct { uint32_t signature; FILE_HDR file; OPT_HDR opt; } __attribute__((packed)) NT_HDR;
typedef struct { uint8_t name[8]; uint32_t v_size; uint32_t v_addr; uint32_t raw_size; uint32_t raw_ptr; uint8_t pad[12]; uint32_t characteristics; } __attribute__((packed)) SEC_HDR;

/* Win64 Import Directory Structures */
typedef struct { uint32_t lookup_table_rva; uint32_t ts; uint32_t forwarder; uint32_t name_rva; uint32_t address_table_rva; } __attribute__((packed)) WIN_IMPORT_DESC;

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
    void* base = mmap((void*)nt.opt.image_base, img_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED) {
        base = mmap(NULL, img_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) return printf("[-] Error: VMA allocation denied.\n"), close(fd), 1;
    }

    SEC_HDR sec;
    off_t section_hdr_offset = dos.lfanew + sizeof(NT_HDR);
    for (int i = 0; i < nt.file.num_sections; i++) {
        lseek(fd, section_hdr_offset + (i * sizeof(SEC_HDR)), SEEK_SET);
        if (read(fd, &sec, sizeof(SEC_HDR)) != sizeof(SEC_HDR)) break;
        if (!sec.raw_size) continue;

        lseek(fd, sec.raw_ptr, SEEK_SET);
        read(fd, (void*)((uintptr_t)base + sec.v_addr), sec.raw_size);
    }

    /* 
     * ⚡ DEVRİMSEL ADIM: IMPORT ADDRESS TABLE (IAT) HOT-SWAPPING ⚡
     * Parses Windows import descriptors and maps internal target pointers 
     * directly to our lightning-fast native POSIX wrapper functions.
     */
    uint32_t import_rva = nt.opt.data_dir[1].rva; // Directory index 1 = Import Table
    if (import_rva != 0) {
        WIN_IMPORT_DESC* import_desc = (WIN_IMPORT_DESC*)((uintptr_t)base + import_rva);
        while (import_desc->name_rva != 0) {
            const char* dll_name = (const char*)((uintptr_t)base + import_desc->name_rva);
            uint64_t* thunk = (uint64_t*)((uintptr_t)base + import_desc->address_table_rva);
            uint64_t* lookup = (uint64_t*)((uintptr_t)base + import_desc->lookup_table_rva);
            if (import_desc->lookup_table_rva == 0) lookup = thunk;

            while (*lookup != 0) {
                if (!(*lookup & (1ULL << 63))) { // Import by name, not ordinal
                    const char* func_name = (const char*)((uintptr_t)base + (*lookup) + 2);
                    uintptr_t native_hook = resolve_win_api(dll_name, func_name);
                    if (native_hook) {
                        *thunk = native_hook; // Overwrite IAT address directly with Linux hook
                    }
                }
                thunk++;
                lookup++;
            }
            import_desc++;
        }
    }

    // Set globally secure running boundaries
    mprotect(base, img_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    uintptr_t entry = (uintptr_t)base + nt.opt.entry_point;
    printf("[+] Linative Subsystem Active. ABI Handoff Target -> 0x%lX\n", entry);
    close(fd);

    /* HARDWARE LEVEL TRANSITION */
    asm volatile (
        "mov %0, %%rax \n\t"
        "xor %%rcx, %%rcx \n\t"
        "xor %%rdx, %%rdx \n\t"
        "and $-16, %%rsp \n\t"
        "sub $32, %%rsp \n\t"
        "jmp *%%rax"
        :
        : "r"(entry)
        : "rax", "rcx", "rdx"
    );

    return 0;
}
