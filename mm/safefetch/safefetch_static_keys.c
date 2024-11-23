#include <linux/mm.h>
#include <linux/swap.h>
#include "page_cache.h"


DEFINE_STATIC_KEY_FALSE(safefetch_copy_from_user_key);
DEFINE_STATIC_KEY_FALSE(safefetch_hooks_key);
DEFINE_STATIC_KEY_FALSE(safefetch_adaptive_key);
DEFINE_STATIC_KEY_FALSE(safefetch_rbtree_key);

EXPORT_SYMBOL(safefetch_copy_from_user_key);

#ifdef SAFEFETCH_FLOATING_ADAPTIVE_WATERMARK
extern uint8_t SAFEFETCH_ADAPTIVE_WATERMARK;
#endif

volatile int copy_from_user_key_ctrl = 0;
volatile int hooks_key_ctrl = 0;
volatile int defense_config_ctrl  = -1;
volatile int storage_regions_ctrl = -1;
volatile uint8_t adaptive_watermark_ctrl = -1;


static ssize_t hooks_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", hooks_key_ctrl);
}
static ssize_t hooks_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        int val;
        sscanf(buf,"%d",&val);
        // WARNING. Only enable the hooks once (disabling this after enabling
        // it will cause race conditions or missing cleanups).
        if ((hooks_key_ctrl != val) && (val == 0 || val == 1)){
           hooks_key_ctrl = val;
           if (hooks_key_ctrl){
              static_branch_enable(&safefetch_hooks_key);
           } else {
              static_branch_disable(&safefetch_hooks_key);
           }
        }
        

        return count;
}

static ssize_t copy_from_user_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", copy_from_user_key_ctrl);
}
static ssize_t copy_from_user_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        int val;
        sscanf(buf,"%d",&val);
        // Nothing to do if we already have it activated or deactivated.
        if ((copy_from_user_key_ctrl != val) && (val == 0 || val == 1)){
           copy_from_user_key_ctrl = val;
           if (copy_from_user_key_ctrl){
              static_branch_enable(&safefetch_copy_from_user_key);
           } else {
              static_branch_disable(&safefetch_copy_from_user_key);
           }
        }
        return count;
}

static ssize_t defense_config_ctrl_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", defense_config_ctrl);
}

// Warning. This function must be called with safefetch_copy_from_user_key
// disabled. Previously the assumption was to also disable the hook key 
// but this causes race conditions. So, after enabling the hook key once
// never disable it (we cannot toggle back to baseline in other words).
static ssize_t defense_config_ctrl_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        int val;
        sscanf(buf,"%d",&val);

        if (val == defense_config_ctrl){
            return count;
        }

        if (val == 0) { // Linked list configuration
            static_branch_disable(&safefetch_adaptive_key);
            static_branch_disable(&safefetch_rbtree_key);
        } else if (val == 1) { // RB-Tree configuration.
            static_branch_disable(&safefetch_adaptive_key);
            static_branch_enable(&safefetch_rbtree_key);
        } else if (val == 2) { // Adaptive configuration
            static_branch_disable(&safefetch_rbtree_key);
            static_branch_enable(&safefetch_adaptive_key);
        }

        defense_config_ctrl = val;

        return count;
}

static ssize_t storage_regions_ctrl_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", storage_regions_ctrl);
}

// Warning. This function must be called with safefetch_copy_from_user_key
// disabled. Previously the assumption was to also disable the hook key 
// but this causes race conditions. So, after enabling the hook key once
// never disable it (we cannot toggle back to baseline in other words).
static ssize_t storage_regions_ctrl_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{

        size_t metadata, storage;
        uint8_t order = 0;
        sscanf(buf,"%ld %ld %hhd",&metadata, &storage, &order);

        printk("Supplied METADATA: %ld and STORAGE: %ld and ORDER: %d\n", metadata, storage, order);
        
        df_resize_page_caches(metadata, storage, order);

        return count;
}

static ssize_t adaptive_watermark_ctrl_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%hhd", adaptive_watermark_ctrl);
}

// Warning. This function must be called with safefetch_copy_from_user_key
// disabled. Previously the assumption was to also disable the hook key 
// but this causes race conditions. So, after enabling the hook key once
// never disable it (we cannot toggle back to baseline in other words).
static ssize_t adaptive_watermark_ctrl_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        adaptive_watermark_ctrl = 0;

        sscanf(buf,"%hhd",&adaptive_watermark_ctrl);

             
#ifdef SAFEFETCH_FLOATING_ADAPTIVE_WATERMARK
        if (adaptive_watermark_ctrl && (((adaptive_watermark_ctrl + 1) & adaptive_watermark_ctrl) == 0)) {
            SAFEFETCH_ADAPTIVE_WATERMARK = adaptive_watermark_ctrl;
            printk("Supplied ADAPTIVE watermark %hhd\n", SAFEFETCH_ADAPTIVE_WATERMARK);
        }
#endif

        return count;
}

#if 0
static ssize_t defense_full_ctrl_show(struct kobject *kobj, 
                struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d", defense_full_ctrl);
}

// TODO, this sysfs entry is deprecated. Remove it.
static ssize_t defense_full_ctrl_store(struct kobject *kobj, 
                struct kobj_attribute *attr,const char *buf, size_t count)
{
        int val;
        sscanf(buf,"%d",&val);

        if (val == defense_full_ctrl){
            return count;
        }

        if (val == 0) { // Linked list configuration
            static_branch_disable(&safefetch_copy_from_user_key);
            static_branch_disable(&safefetch_hooks_key);
            static_branch_disable(&safefetch_adaptive_key);
            static_branch_disable(&safefetch_rbtree_key);
            static_branch_enable(&safefetch_hooks_key);
            static_branch_enable(&safefetch_copy_from_user_key);
        } else if (val == 1) { // RB-Tree configuration.
            static_branch_disable(&safefetch_copy_from_user_key);
            static_branch_disable(&safefetch_hooks_key);
            static_branch_disable(&safefetch_adaptive_key);
            static_branch_enable(&safefetch_rbtree_key);
            static_branch_enable(&safefetch_hooks_key);
            static_branch_enable(&safefetch_copy_from_user_key);
        } else if (val == 2) { // Adaptive configuration
            static_branch_disable(&safefetch_copy_from_user_key);
            static_branch_disable(&safefetch_hooks_key);
            static_branch_enable(&safefetch_adaptive_key);
            static_branch_disable(&safefetch_rbtree_key);
            static_branch_enable(&safefetch_hooks_key);
            static_branch_enable(&safefetch_copy_from_user_key);
        } else if (val == 3) { // Full disable
            static_branch_disable(&safefetch_copy_from_user_key);
            static_branch_disable(&safefetch_hooks_key);
        } else if (val == 4) { // Full disable
            static_branch_enable(&safefetch_hooks_key);
            static_branch_enable(&safefetch_copy_from_user_key);
        }

        defense_full_ctrl = val;

        return count;
}
#endif

struct kobj_attribute copy_from_user_key_ctrl_attr = __ATTR(copy_from_user_key_ctrl, 0660, copy_from_user_show, copy_from_user_store);

struct kobj_attribute hooks_key_ctrl_attr = __ATTR(hooks_key_ctrl, 0660, hooks_show, hooks_store);

struct kobj_attribute defense_config_ctrl_attr = __ATTR(defense_config_ctrl, 0660, defense_config_ctrl_show, defense_config_ctrl_store);

struct kobj_attribute storage_regions_ctrl_attr = __ATTR(storage_regions_ctrl, 0660, storage_regions_ctrl_show, storage_regions_ctrl_store);

struct kobj_attribute adaptive_watermark_ctrl_attr = __ATTR(adaptive_watermark_ctrl, 0660, adaptive_watermark_ctrl_show, adaptive_watermark_ctrl_store);

void init_safefetch_skey_layer(void) {
    //This Function will be called from Init function
    /*Creating a directory in /sys/kernel/ */
    struct kobject *kobj_ref = kobject_create_and_add("dfcacher_keys", kernel_kobj);

    if (!kobj_ref){
        printk(KERN_INFO"[SafeFetch-keys] Cannot create kobj_ref......\n");
        goto end;
    }

    if(sysfs_create_file(kobj_ref, &copy_from_user_key_ctrl_attr.attr)){
      printk(KERN_INFO"[SafeFetch-keys] Cannot create sysfs file for copy_from_user control......\n");
      goto fail_copy_key;
    }

    if(sysfs_create_file(kobj_ref, &hooks_key_ctrl_attr.attr)){
      printk(KERN_INFO"[SafeFetch-keys] Cannot create sysfs file for hook control......\n");
      goto fail_hooks_key;
    }

    if(sysfs_create_file(kobj_ref, &defense_config_ctrl_attr.attr)){
      printk(KERN_INFO"[SafeFetch-keys] Cannot create sysfs file for defense control......\n");
      goto fail_defense_key;
    }

    if(sysfs_create_file(kobj_ref, &storage_regions_ctrl_attr.attr)){
      printk(KERN_INFO"[SafeFetch-keys] Cannot create sysfs file for storage region control......\n");
      goto fail_storage_key;
    }

    if(sysfs_create_file(kobj_ref, &adaptive_watermark_ctrl_attr.attr)){
      printk(KERN_INFO"[SafeFetch-keys] Cannot create sysfs file for storage region control......\n");
      goto fail_adaptive_key;
    }


    printk(KERN_INFO"[SafeFetch-keys] Successfully created references to control DFCACHER......\n");

    return;

fail_adaptive_key: 
    sysfs_remove_file(kernel_kobj, &adaptive_watermark_ctrl_attr.attr); 
fail_storage_key:
    sysfs_remove_file(kernel_kobj, &storage_regions_ctrl_attr.attr); 
fail_defense_key:
    sysfs_remove_file(kernel_kobj, &defense_config_ctrl_attr.attr);  
fail_hooks_key:
    sysfs_remove_file(kernel_kobj, &hooks_key_ctrl_attr.attr);  
fail_copy_key:
    sysfs_remove_file(kernel_kobj, &copy_from_user_key_ctrl_attr.attr);
    kobject_put(kobj_ref);

end:
    return;
}
