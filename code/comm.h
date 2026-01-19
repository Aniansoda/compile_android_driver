#ifndef _COMM_H_
#define _COMM_H_

#include <linux/types.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

typedef struct _PHYSICAL_MEMORY {
    uintptr_t phys_addr;
    void *buffer;
    size_t size;
} PHYSICAL_MEMORY, *PPHYSICAL_MEMORY;

enum OPERATIONS {
    FJ_INIT_KEY = 0x730800,
    FJ_READ_MEM = 0x830901,
    FJ_WRITE_MEM = 0x930102,
    FJ_MODULE_BASE = 0x130203,
    FJ_MODULE_BSS = 0x130204,
    FJ_MODULE_SIZE = 0x130205,
    FJ_READ_PHYSICAL = 0x930106,
    FJ_WRITE_PHYSICAL = 0x930107,
};

#endif /* _COMM_H_ */