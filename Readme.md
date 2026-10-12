# Linative

An ultra-minimalist, zero-dependency, high-speed Windows PE loader designed to execute x64 `.exe` binaries directly on Linux user-space with native CPU efficiency.

---

## ⚡ Core Philosophy
* **Zero-Copy Memory Mapping:** Maps PE sections directly into Linux virtual memory pages (`mmap`) with zero abstraction overhead.
* **Hardware-Level Permissions:** Synchronizes page protections (`mprotect`) match original compiler specifications.
* **Silicon-Level ABI Handoff:** Realigns System V AMD64 Linux stack frames into Microsoft x64 calling convention directly on physical CPU registers via inline assembly.

---

## 🎨 Drag-and-Drop Workflow
No setup or configuration required. Drag and drop any 64-bit Windows `.exe` directly onto the compiled ELF binary icon in your Linux desktop environment.


## 🛠️ Quick Start

### Compile
```bash
gcc -O3 linative.c -o linative
```

### Run
* **GUI:** Drag and drop a Windows `.exe` onto the `linative` binary icon.
* **CLI:** `./linative target.exe`

---



*Wine is not the only way. Let's run Windows binaries natively.*
