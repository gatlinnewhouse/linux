#ifndef __SAFEFETCH_DEBUG_H__
#define __SAFEFETCH_DEBUG_H__

//#define SAFEFETCH_DEBUG
#ifdef SAFEFETCH_DEBUG

#define DF_SYSCALL_NR get_current()->df_stats.syscall_nr
#define DF_SYSCALL_FETCHES get_current()->df_stats.num_fetches
#define DF_SYSCALL_DEFRAGS get_current()->df_stats.num_defrags
#define DF_SYSCALL_COUNT get_current()->df_stats.syscall_count
#define DF_INC_FETCHES DF_SYSCALL_FETCHES++
#define DF_INC_DEFRAGS DF_SYSCALL_DEFRAGS++
#define DF_ALLOCATIONS(tsk) tsk->df_stats.nallocations
#define DEBUG_TASK_INITIALIZED(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.initialized

// Enable this in order to check in tranzit allocations.
// #define SAFEFETCH_DEBUG_LEAKS

// TODO when we split the implementation in standalone compilation units
// these way of defining variables will be a problem.
extern volatile int df_cacher_log_level;
extern volatile int df_cacher_assert_level;
extern volatile unsigned long global_allocations;
extern spinlock_t allocations_lock;
extern spinlock_t df_sample_lock;

void init_safefetch_debug_layer(void);

#define SAFEFETCH_DEBUG_LOG(log_level, ...) if ((log_level) <= df_cacher_log_level) printk(KERN_INFO __VA_ARGS__)
#define SAFEFETCH_DEBUG_ASSERT(log_level, assertion, ...) if ((log_level) <= df_cacher_assert_level) { if (!(assertion)) printk(KERN_INFO __VA_ARGS__); }
#define SAFEFETCH_DEBUG_RUN(log_level, run_func) if ((log_level) <= df_cacher_log_level)  { run_func; }
#else
#define SAFEFETCH_DEBUG_LOG(log_level, ...) 
#define SAFEFETCH_DEBUG_ASSERT(log_level, assertion, ...)
#define SAFEFETCH_DEBUG_RUN(log_level, run_func)
#define DF_INC_FETCHES 
#define DF_INC_DEFRAGS
#endif


#define SAFEFETCH_LOG_ERROR 1
#define SAFEFETCH_LOG_WARNING 2
#define SAFEFETCH_LOG_INFO 3
#define SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY 20
#define SAFEFETCH_LOG_INFO_REGION_FUNCTIONALITY 10 //10
// Just keep it fully activated by default for debug builds
#define SAFEFETCH_LOG_SIGNAL_CHAINING 10 
// Set to 5 when running debug syscall stats
#define SAFEFETCH_LOG_INFO_DFCACHER_STATS 40 
#define SAFEFETCH_IRQ_FUNCTIONALITY 4

#define SAFEFETCH_ASSERT_ALL 1



#endif
