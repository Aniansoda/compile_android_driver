#ifndef _MEMORY_H_
#define _MEMORY_H_

#include <linux/kernel.h>
#include <linux/types.h>

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool read_physical_memory(uintptr_t phys_addr, void *buffer, size_t size);
bool write_physical_memory(uintptr_t phys_addr, void *buffer, size_t size);
ssize_t batch_memory_rw(struct task_struct *task, uintptr_t addr, 
                        void *buffer, size_t size, bool is_write);

#endif /* _MEMORY_H_ */