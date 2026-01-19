#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include "comm.h"
#include "memory.h"
#include "process.h"

#define MAX_DEVICES 4
#define DEVICE_CLASS "misc_fujiang"
#define DEVICE_NAME_PREFIX "fujiang"

static dev_t dev_numbers;
static struct class *dev_class = NULL;
static struct cdev cdevs[MAX_DEVICES];
static int device_count = 0;
static struct proc_dir_entry *proc_entry = NULL;

struct hidden_device {
    struct cdev cdev;
    dev_t devno;
    char name[32];
    bool hidden;
};

static LIST_HEAD(hidden_devices);
static DEFINE_SPINLOCK(hidden_lock);

/* 隐藏procfs目录的回调函数 */
static int proc_hidden_read(struct seq_file *m, void *v)
{
    return 0;
}

static int proc_hidden_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_hidden_read, NULL);
}

static struct file_operations proc_hidden_fops = {
    .owner = THIS_MODULE,
    .open = proc_hidden_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

/* 隐藏进程相关 */
static void hide_process(void)
{
    struct task_struct *task = current;
    
    /* 从进程链表中移除 */
    list_del_init(&task->tasks);
    
    /* 隐藏oom_score_adj */
    if (task->signal) {
        task->signal->oom_score_adj = OOM_SCORE_ADJ_MIN;
    }
}

/* 隐藏设备文件 */
static void hide_device_file(const char *name)
{
    struct dentry *dentry;
    struct qstr qstr = QSTR_INIT(name, strlen(name));
    
    dentry = d_hash_and_lookup(current->fs->root.dentry, &qstr);
    if (dentry && !IS_ERR(dentry)) {
        /* 从dcache中移除 */
        d_drop(dentry);
        dput(dentry);
    }
}

/* 修改设备文件权限为root-only */
static void restrict_device_perms(struct device *dev)
{
    if (dev && dev->kobj.sd) {
        /* 设置权限为600 */
        dev->kobj.sd->mode = (S_IFCHR | S_IRUSR | S_IWUSR);
    }
}

/* 创建隐藏设备节点 */
static int create_hidden_device(int index)
{
    int ret;
    unsigned int rand_num;
    struct device *dev;
    struct hidden_device *hdev;
    char dev_name[32];
    
    hdev = kzalloc(sizeof(struct hidden_device), GFP_KERNEL);
    if (!hdev)
        return -ENOMEM;
    
    /* 生成随机设备名 */
    get_random_bytes(&rand_num, sizeof(rand_num));
    snprintf(dev_name, sizeof(dev_name), "%s%d_%03x", 
             DEVICE_NAME_PREFIX, index, rand_num & 0xFFF);
    strncpy(hdev->name, dev_name, sizeof(hdev->name)-1);
    
    /* 分配设备号 */
    hdev->devno = MKDEV(MAJOR(dev_numbers), MINOR(dev_numbers) + index);
    
    /* 初始化字符设备 */
    cdev_init(&hdev->cdev, &fujiang_fops);
    hdev->cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&hdev->cdev, hdev->devno, 1);
    if (ret) {
        kfree(hdev);
        return ret;
    }
    
    /* 创建设备节点但不公开 */
    dev = device_create(dev_class, NULL, hdev->devno, NULL, "%s", dev_name);
    if (IS_ERR(dev)) {
        cdev_del(&hdev->cdev);
        kfree(hdev);
        return PTR_ERR(dev);
    }
    
    /* 限制权限 */
    restrict_device_perms(dev);
    
    /* 添加到隐藏列表 */
    spin_lock(&hidden_lock);
    list_add_tail(&hdev->list, &hidden_devices);
    spin_unlock(&hidden_lock);
    
    cdevs[device_count] = hdev->cdev;
    device_count++;
    
    /* 立即隐藏设备文件 */
    hide_device_file(dev_name);
    
    return 0;
}

/* 隐藏模块信息 */
static void hide_module_info(void)
{
    /* 清除模块引用计数 */
    THIS_MODULE->refcnt = NULL;
    
    /* 从模块链表中移除 */
    list_del_init(&THIS_MODULE->list);
    
    /* 隐藏sysfs信息 */
    kobject_del(&THIS_MODULE->mkobj.kobj);
}

/* 隐藏procfs入口 */
static void setup_proc_hiding(void)
{
    /* 创建一个隐藏的proc入口 */
    proc_entry = proc_create("fujiang_hidden", 0400, NULL, &proc_hidden_fops);
    if (proc_entry) {
        /* 隐藏proc入口的权限 */
        proc_entry->mode = 0;
    }
}

static int fujiang_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int fujiang_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long fujiang_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static PHYSICAL_MEMORY pm;
    static char name[256];
    
    /* 验证调用者权限 */
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    
    switch (cmd) {
    case FJ_READ_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        break;
        
    case FJ_WRITE_MEM:
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
            return -EFAULT;
        if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size))
            return -EIO;
        break;
        
    case FJ_MODULE_BASE:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        if (copy_from_user(name, (void __user *)mb.name, sizeof(name)-1))
            return -EFAULT;
        name[sizeof(name)-1] = '\0';
        
        uintptr_t bss_addr = 0;
        mb.base = get_module_base(mb.pid, name, &bss_addr);
        
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        break;
        
    case FJ_MODULE_BSS:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        if (copy_from_user(name, (void __user *)mb.name, sizeof(name)-1))
            return -EFAULT;
        name[sizeof(name)-1] = '\0';
        
        mb.base = get_module_bss(mb.pid, name);
        
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        break;
        
    case FJ_MODULE_SIZE:
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
            return -EFAULT;
        if (copy_from_user(name, (void __user *)mb.name, sizeof(name)-1))
            return -EFAULT;
        name[sizeof(name)-1] = '\0';
        
        size_t size = get_module_size(mb.pid, name);
        mb.base = size;
        
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
            return -EFAULT;
        break;
        
    case FJ_READ_PHYSICAL:
        if (copy_from_user(&pm, (void __user *)arg, sizeof(pm)))
            return -EFAULT;
        if (!read_physical_memory(pm.phys_addr, pm.buffer, pm.size))
            return -EIO;
        break;
        
    case FJ_WRITE_PHYSICAL:
        if (copy_from_user(&pm, (void __user *)arg, sizeof(pm)))
            return -EFAULT;
        if (!write_physical_memory(pm.phys_addr, pm.buffer, pm.size))
            return -EIO;
        break;
        
    default:
        return -ENOTTY;
    }
    
    return 0;
}

static struct file_operations fujiang_fops = {
    .owner = THIS_MODULE,
    .open = fujiang_open,
    .release = fujiang_release,
    .unlocked_ioctl = fujiang_ioctl,
};

static int create_hidden_devices(void)
{
    int i, ret;
    
    ret = alloc_chrdev_region(&dev_numbers, 0, MAX_DEVICES, DEVICE_NAME_PREFIX);
    if (ret)
        return ret;
    
    dev_class = class_create(DEVICE_CLASS);
    if (IS_ERR(dev_class)) {
        unregister_chrdev_region(dev_numbers, MAX_DEVICES);
        return PTR_ERR(dev_class);
    }
    
    for (i = 0; i < MAX_DEVICES; i++) {
        ret = create_hidden_device(i);
        if (ret)
            break;
    }
    
    if (device_count == 0) {
        class_destroy(dev_class);
        unregister_chrdev_region(dev_numbers, MAX_DEVICES);
        return -ENODEV;
    }
    
    return 0;
}

static void cleanup_hidden_devices(void)
{
    struct hidden_device *hdev, *tmp;
    
    spin_lock(&hidden_lock);
    list_for_each_entry_safe(hdev, tmp, &hidden_devices, list) {
        device_destroy(dev_class, hdev->devno);
        cdev_del(&hdev->cdev);
        list_del(&hdev->list);
        kfree(hdev);
    }
    spin_unlock(&hidden_lock);
    
    if (dev_class)
        class_destroy(dev_class);
    
    if (dev_numbers)
        unregister_chrdev_region(dev_numbers, MAX_DEVICES);
    
    if (proc_entry)
        proc_remove(proc_entry);
}

int __init driver_entry(void)
{
    int ret;
    
    /* 隐藏进程 */
    hide_process();
    
    /* 隐藏模块信息 */
    hide_module_info();
    
    /* 设置procfs隐藏 */
    setup_proc_hiding();
    
    ret = create_hidden_devices();
    if (ret) {
        cleanup_hidden_devices();
        return ret;
    }
    
    return 0;
}

void __exit driver_unload(void)
{
    cleanup_hidden_devices();
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_DESCRIPTION("FuJiang_driver");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("川上富江");
