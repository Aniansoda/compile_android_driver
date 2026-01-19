#include "memory.h"
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/io.h>
#include <asm/io.h>

#define MAX_CHUNK_SIZE (4 * 1024 * 1024)
#define OPTIMAL_CHUNK_SIZE (512 * 1024)
#define MIN_CHUNK_SIZE (4 * 1024)
#define HW_BUFFER_SIZE (256 * 1024)

static size_t calculate_optimal_chunk(size_t remaining, size_t total)
{
    if (remaining <= MIN_CHUNK_SIZE) {
        return remaining;
    } else if (remaining <= OPTIMAL_CHUNK_SIZE) {
        return remaining;
    } else if (remaining <= MAX_CHUNK_SIZE) {
        return OPTIMAL_CHUNK_SIZE;
    } else {
        return OPTIMAL_CHUNK_SIZE;
    }
}

static ssize_t batch_memory_rw(struct task_struct *task, uintptr_t addr, 
                               void *buffer, size_t size, bool is_write)
{
    void *kbuf = NULL;
    size_t remaining = size;
    uintptr_t current_addr = addr;
    size_t total_processed = 0;
    size_t chunk_size;
    int ret;
    
    if (size <= MAX_CHUNK_SIZE) {
        kbuf = kmalloc(size, GFP_KERNEL | __GFP_NOWARN);
    }
    
    if (kbuf) {
        if (is_write) {
            if (copy_from_user(kbuf, buffer, size)) {
                kfree(kbuf);
                return -EFAULT;
            }
            ret = access_process_vm(task, addr, kbuf, size, FOLL_FORCE | FOLL_WRITE);
        } else {
            ret = access_process_vm(task, addr, kbuf, size, FOLL_FORCE);
            if (ret > 0 && copy_to_user(buffer, kbuf, ret)) {
                kfree(kbuf);
                return -EFAULT;
            }
        }
        kfree(kbuf);
        return ret;
    }
    
    while (remaining > 0) {
        chunk_size = calculate_optimal_chunk(remaining, size);
        
        kbuf = kmalloc(chunk_size, GFP_KERNEL);
        if (!kbuf) {
            chunk_size = MIN_CHUNK_SIZE;
            kbuf = kmalloc(chunk_size, GFP_KERNEL);
            if (!kbuf) {
                return total_processed > 0 ? total_processed : -ENOMEM;
            }
        }
        
        if (is_write) {
            if (copy_from_user(kbuf, buffer + total_processed, chunk_size)) {
                kfree(kbuf);
                return total_processed > 0 ? total_processed : -EFAULT;
            }
            ret = access_process_vm(task, current_addr, kbuf, chunk_size, 
                                    FOLL_FORCE | FOLL_WRITE);
        } else {
            ret = access_process_vm(task, current_addr, kbuf, chunk_size, FOLL_FORCE);
            if (ret > 0 && copy_to_user(buffer + total_processed, kbuf, ret)) {
                kfree(kbuf);
                return total_processed > 0 ? total_processed : -EFAULT;
            }
        }
        
        kfree(kbuf);
        
        if (ret <= 0) {
            break;
        }
        
        total_processed += ret;
        current_addr += ret;
        remaining -= ret;
    }
    
    return total_processed;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    ssize_t bytes_read;
    
    if (size == 0) {
        return false;
    }
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        printk(KERN_ERR "[富江] PID %d not found\n", pid);
        return false;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return false;
    }
    
    bytes_read = batch_memory_rw(task, addr, buffer, size, false);
    put_task_struct(task);
    
    if (bytes_read == size || bytes_read > 0) {
        return true;
    }
    
    printk(KERN_ERR "[富江] Read failed: %zd\n", bytes_read);
    return false;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    ssize_t bytes_written;
    
    if (size == 0) {
        return false;
    }
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        printk(KERN_ERR "[富江] PID %d not found\n", pid);
        return false;
    }
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) {
        return false;
    }
    
    bytes_written = batch_memory_rw(task, addr, buffer, size, true);
    put_task_struct(task);
    
    if (bytes_written == size || bytes_written > 0) {
        return true;
    }
    
    printk(KERN_ERR "[富江] Write failed: %zd\n", bytes_written);
    return false;
}

bool read_physical_memory(uintptr_t phys_addr, void *buffer, size_t size)
{
    void __iomem *io_addr;
    size_t remaining = size;
    uintptr_t current_addr = phys_addr;
    size_t chunk_size;
    size_t total_read = 0;
    
    if (size == 0 || !buffer) {
        return false;
    }
    
    while (remaining > 0) {
        chunk_size = remaining > HW_BUFFER_SIZE ? HW_BUFFER_SIZE : remaining;
        
        io_addr = ioremap(current_addr, chunk_size);
        if (!io_addr) {
            break;
        }
        
        memcpy_fromio(buffer + total_read, io_addr, chunk_size);
        iounmap(io_addr);
        
        total_read += chunk_size;
        current_addr += chunk_size;
        remaining -= chunk_size;
    }
    
    return total_read == size;
}

bool write_physical_memory(uintptr_t phys_addr, void *buffer, size_t size)
{
    void __iomem *io_addr;
    size_t remaining = size;
    uintptr_t current_addr = phys_addr;
    size_t chunk_size;
    size_t total_written = 0;
    
    if (size == 0 || !buffer) {
        return false;
    }
    
    while (remaining > 0) {
        chunk_size = remaining > HW_BUFFER_SIZE ? HW_BUFFER_SIZE : remaining;
        
        io_addr = ioremap(current_addr, chunk_size);
        if (!io_addr) {
            break;
        }
        
        memcpy_toio(io_addr, buffer + total_written, chunk_size);
        iounmap(io_addr);
        
        total_written += chunk_size;
        current_addr += chunk_size;
        remaining -= chunk_size;
    }
    
    return total_written == size;
}