#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <linux/kernel.h>
#include <linux/types.h>

uintptr_t get_module_base(pid_t pid, char *name, uintptr_t *bss_addr);
uintptr_t get_module_bss(pid_t pid, char *name);
size_t get_module_size(pid_t pid, char *name);

#endif /* _PROCESS_H_ */