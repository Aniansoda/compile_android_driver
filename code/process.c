#include "process.h"
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/string.h>

/* 兼容旧内核版本的mmap锁API */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_lock(mm)    down_read(&(mm)->mmap_sem)
#define mmap_read_unlock(mm)  up_read(&(mm)->mmap_sem)
#endif

#define ARC_PATH_MAX 256
#define MAX_MODULE_NAME 64

struct module_cache {
    pid_t pid;
    char name[MAX_MODULE_NAME];
    uintptr_t base_addr;
    uintptr_t bss_addr;
    unsigned long timestamp;
    struct module_cache *next;
};

static struct module_cache *cache_head = NULL;
static DEFINE_SPINLOCK(cache_lock);

static void update_cache(pid_t pid, const char *name, uintptr_t base_addr, uintptr_t bss_addr)
{
    struct module_cache *entry;
    unsigned long flags;
    
    spin_lock_irqsave(&cache_lock, flags);
    
    /* 查找现有缓存 */
    for (entry = cache_head; entry; entry = entry->next) {
        if (entry->pid == pid && strcmp(entry->name, name) == 0) {
            entry->base_addr = base_addr;
            entry->bss_addr = bss_addr;
            entry->timestamp = jiffies;
            spin_unlock_irqrestore(&cache_lock, flags);
            return;
        }
    }
    
    /* 创建新缓存 */
    entry = kmalloc(sizeof(struct module_cache), GFP_KERNEL);
    if (entry) {
        entry->pid = pid;
        strncpy(entry->name, name, MAX_MODULE_NAME - 1);
        entry->name[MAX_MODULE_NAME - 1] = '\0';
        entry->base_addr = base_addr;
        entry->bss_addr = bss_addr;
        entry->timestamp = jiffies;
        entry->next = cache_head;
        cache_head = entry;
    }
    
    spin_unlock_irqrestore(&cache_lock, flags);
}

static bool get_cached_module(pid_t pid, const char *name, uintptr_t *base_addr, uintptr_t *bss_addr)
{
    struct module_cache *entry;
    unsigned long flags;
    bool found = false;
    
    spin_lock_irqsave(&cache_lock, flags);
    
    for (entry = cache_head; entry; entry = entry->next) {
        if (entry->pid == pid && strcmp(entry->name, name) == 0) {
            if (time_after(jiffies, entry->timestamp + msecs_to_jiffies(5000))) {
                /* 缓存过期，删除 */
                struct module_cache *prev = cache_head;
                if (entry == cache_head) {
                    cache_head = entry->next;
                } else {
                    while (prev && prev->next != entry) prev = prev->next;
                    if (prev) prev->next = entry->next;
                }
                kfree(entry);
            } else {
                if (base_addr) *base_addr = entry->base_addr;
                if (bss_addr) *bss_addr = entry->bss_addr;
                found = true;
            }
            break;
        }
    }
    
    spin_unlock_irqrestore(&cache_lock, flags);
    return found;
}

static uintptr_t find_module_base_from_vma(struct mm_struct *mm, const char *name, uintptr_t *bss_addr)
{
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;
    uintptr_t last_exec_start = 0;
    bool found_exec = false;
    
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
            char buf[ARC_PATH_MAX];
            char *path_nm;
            
            path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX - 1);
            if (!IS_ERR(path_nm)) {
                const char *basename = kbasename(path_nm);
                if (strcmp(basename, name) == 0) {
                    if (vma->vm_flags & VM_EXEC) {
                        /* 可执行段，通常是代码段 */
                        base_addr = vma->vm_start;
                        last_exec_start = vma->vm_start;
                        found_exec = true;
                    } else if (found_exec && !(vma->vm_flags & VM_EXEC)) {
                        /* BSS段通常在代码段之后，且不可执行 */
                        if (bss_addr && *bss_addr == 0 && 
                            vma->vm_start > last_exec_start) {
                            *bss_addr = vma->vm_start;
                        }
                    }
                }
            }
        }
    }
    
    return base_addr;
}

uintptr_t get_module_base(pid_t pid, char *name, uintptr_t *bss_addr)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    uintptr_t base_addr = 0;
    
    if (!name)
        return 0;
    
    /* 先从缓存获取 */
    if (get_cached_module(pid, name, &base_addr, bss_addr))
        return base_addr;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return 0;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return 0;
    
    mmap_read_lock(mm);
    
    if (bss_addr)
        *bss_addr = 0;
    base_addr = find_module_base_from_vma(mm, name, bss_addr);
    
    mmap_read_unlock(mm);
    mmput(mm);
    
    /* 更新缓存 */
    update_cache(pid, name, base_addr, bss_addr ? *bss_addr : 0);
    
    return base_addr;
}

/* 获取模块BSS段地址（专用函数） */
uintptr_t get_module_bss(pid_t pid, char *name)
{
    uintptr_t bss_addr = 0;
    get_module_base(pid, name, &bss_addr);
    return bss_addr;
}

/* 获取模块大小 */
size_t get_module_size(pid_t pid, char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t start_addr = 0;
    uintptr_t end_addr = 0;
    size_t total_size = 0;
    
    if (!name)
        return 0;
    
    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;
    
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return 0;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return 0;
    
    mmap_read_lock(mm);
    
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
            char buf[ARC_PATH_MAX];
            char *path_nm;
            
            path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX - 1);
            if (!IS_ERR(path_nm)) {
                const char *basename = kbasename(path_nm);
                if (strcmp(basename, name) == 0) {
                    if (start_addr == 0)
                        start_addr = vma->vm_start;
                    end_addr = vma->vm_end;
                }
            }
        }
    }
    
    mmap_read_unlock(mm);
    mmput(mm);
    
    if (start_addr && end_addr)
        total_size = end_addr - start_addr;
    
    return total_size;
}