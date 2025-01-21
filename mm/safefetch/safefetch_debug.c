#include <linux/mm.h>
#include <linux/swap.h>
#include "safefetch_debug.h"

volatile int df_cacher_log_level = 0;
volatile int df_cacher_assert_level = 0;
volatile unsigned long global_allocations = 0;
spinlock_t allocations_lock;
spinlock_t df_sample_lock;

static ssize_t allocations_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{

    struct task_struct *iter, *process; 

    for_each_process_thread(iter, process){
        if (DF_ALLOCATIONS(process)){
           printk("%s has %ld in transit allocations. [Initialized %d]\n", process->comm, DF_ALLOCATIONS(process), DEBUG_TASK_INITIALIZED(process));
        }
    }
    return sprintf(buf, "%ld", global_allocations);
}
static ssize_t allocations_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        global_allocations = 0;
        return count;
}

static ssize_t log_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", df_cacher_log_level);
}
static ssize_t log_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        sscanf(buf,"%d",&df_cacher_log_level);
        return count;
}

static ssize_t assert_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", df_cacher_assert_level);
}
static ssize_t assert_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        sscanf(buf,"%d",&df_cacher_assert_level);
        return count;
}

struct kobj_attribute df_cacher_log_attr = __ATTR(df_cacher_log_level, 0660, log_show, log_store);

struct kobj_attribute df_cacher_assert_attr = __ATTR(df_cacher_assert_level, 0660, assert_show, assert_store);
struct kobj_attribute allocations_attr = __ATTR(global_allocations, 0660, allocations_show, allocations_store);

void init_safefetch_debug_layer(void) {
    //This Function will be called from Init function
    /*Creating a directory in /sys/kernel/ */
    struct kobject *kobj_ref = kobject_create_and_add("dfcacher", kernel_kobj);

    if (!kobj_ref){
        printk(KERN_INFO"[SafeFetch] Cannot create kobj_ref......\n");
        goto end;
    }
    printk(KERN_INFO"[SafeFetch] Successfully created kobj_ref......\n");

    if(sysfs_create_file(kobj_ref, &df_cacher_log_attr.attr)){
      printk(KERN_INFO"[SafeFetch] Cannot create sysfs file......\n");
      goto log_sysfs;
    }

    if(sysfs_create_file(kobj_ref, &df_cacher_assert_attr.attr)){
      printk(KERN_INFO"[SafeFetch] Cannot create sysfs file......\n");
      goto assert_sysfs;
    }

    if(sysfs_create_file(kobj_ref, &allocations_attr.attr)){
      printk(KERN_INFO"[SafeFetch] Cannot create sysfs file for allocations number......\n");
      goto allocations_error;
    }

    spin_lock_init(&allocations_lock);
end:

    printk(KERN_INFO"[SafeFetch] Succesfully initialized debugging layer......\n");
    return;
allocations_error:
    sysfs_remove_file(kernel_kobj, &allocations_attr.attr); 
assert_sysfs:
    sysfs_remove_file(kernel_kobj, &df_cacher_assert_attr.attr);  
log_sysfs:
    sysfs_remove_file(kernel_kobj, &df_cacher_log_attr.attr);
    kobject_put(kobj_ref); 
}
