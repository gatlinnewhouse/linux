#include <linux/mm.h>
#include <linux/swap.h>
#include "safefetch_debug.h"

#include "page_cache.h"
#include <linux/mem_range.h>
#include <linux/safefetch_static_keys.h>

#ifdef SAFEFETCH_MEASURE_DEFENSE

char global_monitored_task[SAFEFETCH_MONITOR_TASK_SIZE] = {'x', 'x' , 'o' ,'x', 'o', 0} ;
int  global_monitored_syscall = -2;
uint64_t global_search_time[SAFEFETCH_MEASURE_MAX];
uint64_t global_search_count = 0;
uint64_t rdmsr_ovr = 0;
EXPORT_SYMBOL(global_search_time);
EXPORT_SYMBOL(global_search_count);
EXPORT_SYMBOL(global_monitored_task);
EXPORT_SYMBOL(global_monitored_syscall);
EXPORT_SYMBOL(rdmsr_ovr);
#endif


/*
 * This file contains the top level code.
 * It has the functions that will be hooked from specific locations within
 * the linux kernel based on the current control flow.
 * It also contains the main content for performing the defense
 */

// This function initialises the protection structures that needed for the defense
// This function is called once during booting
// Calling location: init/main.c:start_kernel()
// Return: None
inline void df_startup(void){
    printk(KERN_INFO "[SafeFetch] Initialising SafeFetch...");
#ifdef SAFEFETCH_RBTREE_MEM_RANGE
    printk(KERN_INFO "[SafeFetch] Using RB-tree memory range data structure");
#elif defined(SAFEFETCH_ADAPTIVE_MEM_RANGE)
    printk(KERN_INFO "[SafeFetch] Using ADAPTIVE memory range data structure");
#elif defined(SAFEFETCH_STATIC_KEYS)
    printk(KERN_INFO "[SafeFetch] Using STATIC_KEYS memory range data structure");
#else
    printk(KERN_INFO "[SafeFetch] Using Linked list memory range data structure");
#endif

    df_init_page_alloc_array();
    printk(KERN_INFO "[SafeFetch] - Pre-page allocation enabled");
    printk(KERN_INFO "[SafeFetch] - Metadata Page Cache Size %d", (uint32_t)safefetch_metadata_cache_size);
    printk(KERN_INFO "[SafeFetch] - Data Page Cache Size %d", (uint32_t)safefetch_storage_cache_size);

}

// This function is called every time a task is being duplicated.
// It resets the pointers inside the task struct so no double usages occur.
// Calling location: kernel/fork.c:dup_task_struct()
// Return: None
inline void df_task_dup(struct task_struct *tsk){
    SAFEFETCH_TASK_RESET_MEM_RANGE(tsk);

    tsk->df_prot_struct_head.df_metadata_allocator.initialized = 0;
    tsk->df_prot_struct_head.df_storage_allocator.initialized = 0;

#if defined(SAFEFETCH_DEBUG)
    tsk->df_stats.traced = 0;
    tsk->df_stats.check_next_access = 0;
    tsk->df_stats.syscall_count = 0;
    tsk->df_stats.in_irq = 0;
    tsk->df_stats.num_fetches = 0;
    tsk->df_stats.num_defrags = 0;
#endif

#ifdef SAFEFETCH_MEASURE_DEFENSE
    df_init_measure_structs(tsk);
#endif

    //tsk->df_prot_struct_head.df_metadata_allocator.extended = 0;
    //tsk->df_prot_struct_head.df_storage_allocator.extended = 0;

    //init_region_allocator(&(tsk->df_prot_struct_head.df_metadata_allocator), METADATA);
    //init_region_allocator(&(tsk->df_prot_struct_head.df_storage_allocator), STORAGE);
}

#if defined(SAFEFETCH_DEBUG) || defined(SAFEFETCH_STATIC_KEYS)
void df_sysfs_init(void){
#ifdef SAFEFETCH_DEBUG
     init_safefetch_debug_layer();
     printk(KERN_INFO "[SafeFetch] - Initialized sysfs debug interface");
#endif
#ifdef SAFEFETCH_STATIC_KEYS
     init_safefetch_skey_layer();
#endif
}
#endif

#ifdef SAFEFETCH_DEBUG

#if  defined(SAFEFETCH_DEBUG_COLLECT_SAMPLES) || defined(SAFEFETCH_MEASURE_MEMORY_CONSUMPTION)
LIST_HEAD(sample_list_node);
EXPORT_SYMBOL(sample_list_node);
DEFINE_SPINLOCK(df_sample_lock);
EXPORT_SYMBOL(df_sample_lock);

#define FILTER_TOTAL_SIZE 14
char* sample_filter[FILTER_TOTAL_SIZE] = { "bw_", "lat_", "nginx", "apache", "redis", "git", "openssl", "pybench", "ipc-benchmark", "create_threads", "create_processe", "launch_programs", "create_files", "mem_alloc" };

bool check_filter(void){
    int i;
    for (i = 0; i < FILTER_TOTAL_SIZE; i++){
        if (strncmp(current->comm, sample_filter[i], strlen(sample_filter[i])) == 0){
            return true;
        }
    }
    return false;
}

#endif

#if defined(SAFEFETCH_DEBUG_COLLECT_SAMPLES)
#warning "Building with debug and sample collection"
static inline void collect_sample(void){
   struct df_sample_struct sample;
   struct df_sample_link *link;
   link = kmalloc(sizeof(struct df_sample_link), GFP_KERNEL);
   memset(&sample, 0, sizeof(struct df_sample_struct));
   strncpy(sample.comm, current->comm, TASK_NAME_SIZE);
   sample.comm[TASK_NAME_SIZE-1] = 0;
   sample.syscall_nr = DF_SYSCALL_NR;
   sample.nfetches = DF_SYSCALL_FETCHES;
   sample.ndefrags = DF_SYSCALL_DEFRAGS;
   sample.sys_count = DF_SYSCALL_COUNT;
   sample.pid = current->pid;
   dump_region_stats(&(sample.mranges), &(sample.dranges), &(sample.dkmallocs), &(sample.max_kmalloc));
   dump_range_stats_extended(&(sample.rsize), &(sample.min_size), &(sample.max_size), &(sample.avg_size), &(sample.total_size));

   if (sample.rsize){
      sample.mranges++;
      sample.dranges++;
   }

   memcpy(&(link->sample), &sample, sizeof(struct df_sample_struct));

   spin_lock(&df_sample_lock);
   list_add_tail(&(link->node), &(sample_list_node));
   spin_unlock(&df_sample_lock);
}
#elif defined(SAFEFETCH_MEASURE_MEMORY_CONSUMPTION)
#warning "Building with debug and memory collection"
static inline void collect_sample(void){
   struct df_sample_struct sample;
   struct df_sample_link *link;
   // Only collect sizes for specific processes
   if (!check_filter())
       return;
   memset(&sample, 0, sizeof(struct df_sample_struct));
   dump_mem_consumption(current, &(sample.metadata), &(sample.data), &(sample.pins));

   // Skip syscalls that do not allocate any data.
   if (!(sample.metadata))
      return;

   sample.metadata >>= 10;
   sample.data     >>= 10;
   sample.pins     >>= 10;

   link = kmalloc(sizeof(struct df_sample_link), GFP_KERNEL);
   
   strncpy(sample.comm, current->comm, TASK_NAME_SIZE);
   sample.comm[TASK_NAME_SIZE-1] = 0;
   sample.syscall_nr = DF_SYSCALL_NR;
   sample.pid = current->pid;
   sample.rss =  get_mm_rss(current->mm) << 2;
   
   memcpy(&(link->sample), &sample, sizeof(struct df_sample_struct));

   spin_lock(&df_sample_lock);
   list_add_tail(&(link->node), &(sample_list_node));
   spin_unlock(&df_sample_lock);
}
#endif
// This function is called on every syscall start
// It initialises the data structures needed for the safefetch defense
// Calling location: arch/x86/entry/common.c:do_syscall_64()
// Return: None
void df_debug_syscall_entry(int sys_nr, struct pt_regs *regs){
   int same_syscall = 0;

   // Mark the pending copies from user as access ok.
#if defined(SAFEFETCH_DEBUG_TRACING)
   current->df_stats.check_next_access = 0;
#endif
   if (current->df_stats.pending == PENDING_RESTART_DELIVERED){
      SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_SIGNAL_CHAINING, "[SafeFetch][Signals][Task %s][Sys %d][Previous %d] Delivered restart to syscall from RIP 0x%lx (orig ax: 0x%ld ax: 0x%lx)\n", current->comm, sys_nr, DF_SYSCALL_NR, regs->ip, regs->orig_ax, regs->ax);  
      current->df_stats.pending = 0;
      same_syscall = 1;
   }

   if (SAFEFETCH_MEM_RANGE_INIT_FLAG) {
      SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_SIGNAL_CHAINING, "[SafeFetch][Signals][Task %s][Sys %d][Previous %d] Major error, some init flag not set correctly from RIP 0x%lx (orig ax: 0x%ld ax: 0x%lx) [%d]\n", current->comm, sys_nr, DF_SYSCALL_NR, regs->ip, regs->orig_ax, regs->ax, same_syscall);
      current->df_stats.pending = PENDING_RESTART;
      SAFEFETCH_RESET_MEM_RANGE();
   } else {
      current->df_stats.pending = 0;
   }


   DF_SYSCALL_NR = sys_nr;
   DF_SYSCALL_FETCHES = 0;
   DF_SYSCALL_DEFRAGS = 0;
   current->df_stats.syscall_count++;
}

// This function is called on every syscall termination.
// It clears the used memory ranges
// Calling location: arch/x86/entry/common.c:do_syscall_64()
// Return: None
void df_debug_syscall_exit(void){
   int dranges, mranges, dkmalloc;
   int rsize;
   uint64_t avg_size;
   size_t max;

   if (current->df_stats.pending == PENDING_RESTART){
       current->df_stats.pending = PENDING_RESTART_DELIVERED;
   }
#if defined(SAFEFETCH_DEBUG_COLLECT_SAMPLES) || defined(SAFEFETCH_MEASURE_MEMORY_CONSUMPTION)
   SAFEFETCH_DEBUG_RUN(5, collect_sample());
#endif

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
   check_pins();
#endif
}

// This function is called every time a process dies
// It destroys all the allocated memory attached to this process
// Calling location: kernel/exit.c:do_exit()
// Return: None
inline void df_debug_task_destroy(struct task_struct *tsk){
   tsk->df_stats.pending = 0;
   tsk->df_stats.syscall_nr = -1;
}

#endif

// This function intercepts a get_user instruction of 1 byte
// It will insert the data into the protection structure and then
// copies back the double fetch protected data for that specific memory
// area into the kernel destination.
// Calling location: arch/x86/include/asm/uaccess.h:do_get_user_call
// Return: Response code (-1 = failure)
inline int df_get_user1(unsigned long long user_src, unsigned char user_val, unsigned long long kern_dst){
#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return 0;
    }
#endif
    copy_range_loop((unsigned char*)user_src, user_val, (unsigned char*)kern_dst);
}

// This function intercepts a get_user instruction of 2 bytes
// It will insert the data into the protection structure and then
// copies back the double fetch protected data for that specific memory
// area into the kernel destination.
// Calling location: arch/x86/include/asm/uaccess.h:do_get_user_call
// Return: Response code (-1 = failure)
inline int df_get_user2(unsigned long long user_src, unsigned short user_val, unsigned long long kern_dst){
#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return 0;
    }
#endif
    copy_range_loop((unsigned short*)user_src, user_val, (unsigned short*)kern_dst);
}

// This function intercepts a get_user instruction of 4 bytes
// It will insert the data into the protection structure and then
// copies back the double fetch protected data for that specific memory
// area into the kernel destination.
// Calling location: arch/x86/include/asm/uaccess.h:do_get_user_call
// Return: Response code (-1 = failure)
inline int df_get_user4(unsigned long long user_src, unsigned int user_val, unsigned long long kern_dst){
#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return 0;
    }
#endif
    copy_range_loop((unsigned int*)user_src, user_val, (unsigned int*)kern_dst);
}

// This function intercepts a get_user instruction of 8 bytes
// It will insert the data into the protection structure and then
// copies back the double fetch protected data for that specific memory
// area into the kernel destination.
// Calling location: arch/x86/include/asm/uaccess.h:do_get_user_call
// Return: Response code (-1 = failure)
inline int df_get_user8(unsigned long long user_src, unsigned long user_val, unsigned long long kern_dst){
#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return 0;
    }
#endif
    copy_range_loop((unsigned long*)user_src, user_val, (unsigned long*)kern_dst);
}

// This function intercepts a get_user instruction of 8 unsigned bytes
// It will insert the data into the protection structure and then
// copies back the double fetch protected data for that specific memory
// area into the kernel destination.
// Calling location: arch/x86/include/asm/uaccess.h:do_get_user_call
// Return: Response code (-1 = failure)
inline int df_get_useru8(unsigned long long user_src, long unsigned int user_val, unsigned long long kern_dst){
#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return 0;
    }
#endif
    copy_range_loop((unsigned long*)user_src, user_val, (unsigned long*)kern_dst);
}

// This function intercepts a copy from user instruction
// It will insert the data into the protection structure and then
// copies back the double fetch protected data for that specific memory
// area into the kernel destination.
// Calling location: arch/x86/include/asm/uaccess.h:do_get_user_call
// Return: Response code (-1 = failure)
inline unsigned long df_copy_from_user(
        unsigned long long user_src,
        unsigned long long kern_dst,
        unsigned long user_size){
    unsigned long ret;

#if defined(SAFEFETCH_DEBUG) && (defined(SAFEFETCH_DEBUG_TRACING) || defined(SAFEFETCH_DEBUG_LEAKS) || defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES))
    if (in_nmi() || current->df_stats.traced){
       return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
#endif

#ifdef DFCACHER_PERF_SETUP
    #warning "DFCACHER perf build"
    // Switch off defense for nmi interrupts.
    if (unlikely(in_irq_ctx())){
       return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
#endif

#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
#endif

    if (unlikely(!user_size)) {
       return 0;
    }

    ret = copy_range(user_src, kern_dst, user_size); 

    if (unlikely(ret == -1)){
       printk(KERN_INFO "[SafeFetch][Warning] df_copy_from_user: Failed copy_range reverting to default implementation\n");
       return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
    
    return ret;
}

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
inline unsigned long df_copy_from_user_pinning(
        unsigned long long user_src,
        unsigned long long kern_dst,
        unsigned long user_size){
    unsigned long ret;

#if defined(SAFEFETCH_DEBUG) && (defined(SAFEFETCH_DEBUG_TRACING) || defined(SAFEFETCH_DEBUG_LEAKS) || defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES))
    if (in_nmi() || current->df_stats.traced){
       return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
#endif

#ifdef DFCACHER_PERF_SETUP
    #warning "DFCACHER perf build"
    // Switch off defense for nmi interrupts.
    if (unlikely(in_irq_ctx())){
       return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
#endif

#ifdef SAFEFETCH_WHITELISTING
    if (IS_WHITELISTED(current)) {
        return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
#endif

    if (unlikely(!user_size)) {
       return 0;
    }

    ret = copy_range_pinning(user_src, kern_dst, user_size); 

    if (unlikely(ret == -1)){
       SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning] df_copy_from_user: Failed copy_range reverting to default implementation\n");
       return COPY_FUNC((void *)kern_dst, (__force void *)user_src, user_size);
    }
    
    return ret;
}
#endif

#ifdef SAFEFETCH_DEBUG
EXPORT_SYMBOL(df_debug_syscall_entry);
EXPORT_SYMBOL(df_debug_syscall_exit);
EXPORT_SYMBOL(df_debug_task_destroy);
#endif

EXPORT_SYMBOL(df_startup);
EXPORT_SYMBOL(df_task_dup);
EXPORT_SYMBOL(df_get_user1);
EXPORT_SYMBOL(df_get_user2);
EXPORT_SYMBOL(df_get_user4);
EXPORT_SYMBOL(df_get_user8);
EXPORT_SYMBOL(df_get_useru8);
EXPORT_SYMBOL(df_copy_from_user);
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
EXPORT_SYMBOL(df_copy_from_user_pinning);
#endif
