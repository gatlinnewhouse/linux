#ifndef __PAGE_CACHE_C__
#define __PAGE_CACHE_C__

#include <linux/mem_range.h>
#include <linux/delay.h> 
#include "page_cache.h"

struct kmem_cache *df_metadata_cache, *df_storage_cache;
size_t safefetch_metadata_cache_size = 0;
size_t safefetch_storage_cache_size = 0;
uint8_t safefetch_slow_path_order = 0;

void df_init_page_alloc_array(void){

    df_metadata_cache = kmem_cache_create("df_metadata_cache",
			METADATA_CACHE_SIZE, 0, SLAB_PANIC, NULL);

    df_storage_cache = kmem_cache_create("df_storage_cache",
			STORAGE_CACHE_SIZE, 0, SLAB_PANIC, NULL);

    safefetch_metadata_cache_size = METADATA_CACHE_SIZE;
    safefetch_storage_cache_size = STORAGE_CACHE_SIZE;

    printk("Page_Cache: Page cache enabled\n");
}

// WARNING - this functions needs to be called with the copy_from_user hook disabled.
// Removes all regions in tranzit so we can switch to a different cache region.
#define MAX_WAIT_FIXUP 200000
static void fixup_in_tranzit_regions(void){
    struct task_struct *iter, *process; 
    unsigned int cleanups = 0;
    unsigned long int wait_time;
    unsigned int state;

    /* Wait such that all processes have enough time to shrink their regions */
    for_each_process_thread(iter, process){
        wait_time = 0;
        while (SAFEFETCH_TASK_MEM_RANGE_INIT_FLAG(process)) {
             usleep_range(10, 20);
             wait_time++;
             if (wait_time >= MAX_WAIT_FIXUP) {
                 state = READ_ONCE(process->state);
                 // Who'se the hogging task and why?
                 printk(KERN_WARNING"Waited but task %s did not finish [%d %d %d %d %d 0x%x]", process->comm, 
                                                                                       state & TASK_INTERRUPTIBLE,
                                                                                       state & TASK_DEAD,
                                                                                       state & EXIT_TRACE,
                                                                                       current == process,
                                                                                       !!(process->flags & PF_KTHREAD),
                                                                                       state);
                 // Lets force the cleanup of this task here and see if something bad happens.
                 destroy_region(DF_TASK_STORAGE_REGION_ALLOCATOR(process));
                 destroy_region(DF_TASK_METADATA_REGION_ALLOCATOR(process));
                 SAFEFETCH_TASK_RESET_MEM_RANGE(process);
                    
                 break;            
             }
        }
    }

    /* Warning - if a task dies now we may be hitting a race condition */
    // What we could do in case we want to force deletion ourselves it to
    // set a bit in the task  to skip its destroy_regions.
    for_each_process_thread(iter, process){
       if (!(process->flags & PF_KTHREAD)) {
            /* Destroy some regions */
            cleanups += (unsigned int)(DF_TASK_STORAGE_REGION_ALLOCATOR(process)->initialized | 
                                       DF_TASK_METADATA_REGION_ALLOCATOR(process)->initialized);

            destroy_region(DF_TASK_STORAGE_REGION_ALLOCATOR(process));
            destroy_region(DF_TASK_METADATA_REGION_ALLOCATOR(process));
       }
    }

    printk("We cleaned up %d regions\n", cleanups);
}

void df_resize_page_caches(size_t _metadata_size, size_t _storage_size, uint8_t _order){

    /* First destroy all in tranzit safefetch regions such that taks will
       pickup regions from the newly assigned slab caches */
    fixup_in_tranzit_regions();

    /* After this we can freely reinitialize the slab caches as no task should
       be using them */
    if (_metadata_size != safefetch_metadata_cache_size) {
        kmem_cache_destroy(df_metadata_cache);
        df_metadata_cache =  kmem_cache_create("df_metadata_cache",
			_metadata_size, 0, SLAB_PANIC, NULL);

        safefetch_metadata_cache_size = _metadata_size;

        WARN_ON(!df_metadata_cache);
    }
    
    if (_storage_size != safefetch_storage_cache_size) {
        kmem_cache_destroy(df_storage_cache);
        df_storage_cache = kmem_cache_create("df_storage_cache",
			_storage_size, 0, SLAB_PANIC, NULL);
        safefetch_storage_cache_size = _storage_size;

        WARN_ON(!df_storage_cache);
    }

    safefetch_slow_path_order = _order;

    printk("Initialized new allocator having METADATA_SIZE: %ld STORAGE_SIZE: %ld ORDER: %d\n", safefetch_metadata_cache_size, safefetch_storage_cache_size, safefetch_slow_path_order);
   
}

#endif
