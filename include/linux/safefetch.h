#ifndef SAFEFETCH_EXTERN_FUNC
#define SAFEFETCH_EXTERN_FUNC

#include <linux/region_allocator.h>

#ifdef SAFEFETCH_MEASURE_DEFENSE


// These are defined in safefetch.c 
extern char global_monitored_task[];
extern int  global_monitored_syscall;
extern uint64_t global_search_time[];
extern uint64_t global_search_count;
extern uint64_t rdmsr_ovr;

#define SAFEFETCH_MEASURE_MAX 1200
#define SAFEFETCH_MONITOR_TASK_SIZE 40

struct df_measure_struct {
     uint64_t *search_time;
     uint64_t *insert_time;
     uint64_t counter;
};

#define df_activate_measure_structs(tsk, sysnr) {                                                                          \
     if ((!strcmp(tsk->comm, global_monitored_task)) && (global_monitored_syscall == sysnr)) {                             \
        tsk->df_prot_struct_head.df_measures.search_time =  kmalloc(SAFEFETCH_MEASURE_MAX * sizeof(uint64_t), GFP_KERNEL); \
        tsk->df_prot_struct_head.df_measures.insert_time =  kmalloc(SAFEFETCH_MEASURE_MAX * sizeof(uint64_t), GFP_KERNEL); \
        memset(tsk->df_prot_struct_head.df_measures.search_time, 0, SAFEFETCH_MEASURE_MAX * sizeof(uint64_t));             \
        memset(tsk->df_prot_struct_head.df_measures.insert_time, 0, SAFEFETCH_MEASURE_MAX * sizeof(uint64_t));             \
        tsk->df_prot_struct_head.df_measures.counter = 0;                                                                  \
     }                                                                                                                     \
}

#define df_init_measure_structs(tsk) {                                             \
     tsk->df_prot_struct_head.df_measures.search_time = NULL;                      \
     tsk->df_prot_struct_head.df_measures.insert_time = NULL;                      \
     tsk->df_prot_struct_head.df_measures.counter = 0;                             \
}

// TODO all of these are macros so we bypass an error due to stupid inclusion order.
#define df_init_current_measure_structs(tsk) { \
     tsk->df_prot_struct_head.df_measures.search_time =  kmalloc(SAFEFETCH_MEASURE_MAX * sizeof(uint64_t), GFP_KERNEL); \
     tsk->df_prot_struct_head.df_measures.insert_time =  kmalloc(SAFEFETCH_MEASURE_MAX * sizeof(uint64_t), GFP_KERNEL); \
     memset(tsk->df_prot_struct_head.df_measures.search_time, 0, SAFEFETCH_MEASURE_MAX * sizeof(uint64_t));             \
     memset(tsk->df_prot_struct_head.df_measures.insert_time, 0, SAFEFETCH_MEASURE_MAX * sizeof(uint64_t));             \
     tsk->df_prot_struct_head.df_measures.counter = 0;                                                                  \
}

#define df_destroy_measure_structs(){                                                                                                                        \
     if (current->df_prot_struct_head.df_measures.search_time) {                                                                                             \
         kfree(current->df_prot_struct_head.df_measures.search_time);                                                                                        \
         kfree(current->df_prot_struct_head.df_measures.insert_time);                                                                                        \
     }                                                                                                                                                       \
     current->df_prot_struct_head.df_measures.search_time = NULL;                                                                                            \
     current->df_prot_struct_head.df_measures.insert_time = NULL;                                                                                            \
     current->df_prot_struct_head.df_measures.counter = 0;                                                                                                   \
}

#if 0
#define df_destroy_measure_structs(){                                                                                                                        \
     if (current->df_prot_struct_head.df_measures.search_time) {                                                                                             \
         memset(global_search_time, 0, SAFEFETCH_MEASURE_MAX * sizeof(uint64_t));                                                                            \
         global_search_count = current->df_prot_struct_head.df_measures.counter;                                                                             \
         memcpy(global_search_time, current->df_prot_struct_head.df_measures.search_time , current->df_prot_struct_head.df_measures.counter * sizeof(uint64_t));                          \
         kfree(current->df_prot_struct_head.df_measures.search_time);                                                                                        \
         kfree(current->df_prot_struct_head.df_measures.insert_time);                                                                                        \
     }                                                                                                                                                       \
     current->df_prot_struct_head.df_measures.search_time = NULL;                                                                                            \
     current->df_prot_struct_head.df_measures.insert_time = NULL;                                                                                            \
     current->df_prot_struct_head.df_measures.counter = 0;                                                                                                   \
}
#endif
#endif

/* This struct is inserted into every task struct
 * It contains the pointers to all the required information and
 * data structures for our protection mechanism.
 * --> df_snapshot_first_mr: ptr towards the first inserted protection memory range
 * --> safefetch_first_node: ptr towards the root node of the memory range rb tree
 * --> base_page_mem_range_allocator: ptr towards the first pre-allocated page for memory range allocation
 * --> curr_page_mem_range_allocator: ptr towards the current page for memory range allocation
 * --> base_page_prot_allocator: ptr towards the first pre-allocated page for memory protection allocation
 * --> curr_page_prot_allocator: ptr towards the current page for memory protection allocation
 */

/* This is the data structure that is added to every task struct for every running task
 * It contains the pointer to the caching data structure
 * It also contains the pointers needed for the custom allocators
 */
struct df_prot_struct {
    struct range_allocator df_mem_range_allocator;
    struct region_allocator df_metadata_allocator;
    struct region_allocator df_storage_allocator;
#ifdef SAFEFETCH_MEASURE_DEFENSE
    struct df_measure_struct df_measures;
#endif
#ifdef SAFEFETCH_WHITELISTING
    unsigned is_whitelisted:1;
#endif

};

#ifdef SAFEFETCH_WHITELISTING
#define IS_WHITELISTED(current) (current->df_prot_struct_head.is_whitelisted)
#endif

// SafeFetch startup hook which is executed at boottime
extern void df_startup(void);

#ifdef SAFEFETCH_DEBUG

#define PENDING_RESTART 1
#define PENDING_RESTART_DELIVERED 2

struct df_stats_struct {

    int syscall_nr;
    unsigned long long syscall_count;
    unsigned long long num_fetches;
    unsigned long long num_defrags;
    unsigned long long cumm_metadata_size;
    unsigned long long cumm_backing_size;
    unsigned long long num_4k_copies; // number of copy from users larger than 1page
    unsigned long long num_8b_copies; // number of copies smaller than 8 bytes
    unsigned long long num_other_copies; // all other copies.
    unsigned long nallocations;
    unsigned pending:2;
    unsigned check_next_access:1;
    unsigned traced:1;
    unsigned in_irq:1;
    
};

#define TASK_NAME_SIZE 25
#if defined(SAFEFETCH_DEBUG_COLLECT_SAMPLES)
struct df_sample_struct {
    char comm[TASK_NAME_SIZE];
    int syscall_nr;
    pid_t pid;
    uint64_t sys_count;
    uint64_t min_size;
    uint64_t max_size;
    uint64_t avg_size;
    uint64_t total_size;
    uint64_t nfetches;
    uint64_t ndefrags;
    int rsize;
    int mranges;
    int dranges;
    int dkmallocs;
    size_t max_kmalloc;
};

struct df_sample_link {
   struct df_sample_struct sample;
   struct list_head node;
};
#elif defined(SAFEFETCH_MEASURE_MEMORY_CONSUMPTION)
struct df_sample_struct {
    char comm[TASK_NAME_SIZE];
    int syscall_nr;
    pid_t pid;
    uint64_t rss;
    uint64_t metadata;
    uint64_t data;
    uint64_t pins;
};

struct df_sample_link {
   struct df_sample_struct sample;
   struct list_head node;
};
#endif

#ifdef SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES
struct df_bug_struct {
    int syscall_nr;
    int func;
};
#define MAX_SYSCALL_REPORTS 3
#define MAX_REPORTS 200


#endif


// All of these were replaced with macros so use them as debug functions
extern void df_debug_syscall_entry(int sys_nr, struct pt_regs *regs);
extern void df_debug_syscall_exit(void);
extern void df_debug_task_destroy(struct task_struct *tsk);
#endif

#if defined(SAFEFETCH_DEBUG) || defined(SAFEFETCH_STATIC_KEYS)
extern void df_sysfs_init(void);
#endif



// SafeFetch task duplication hook
extern void df_task_dup(struct task_struct *tsk);
// SafeFetch task destruction hook

// SafeFetch get_user familiy hooks
extern int df_get_user1(unsigned long long user_src, unsigned char user_val,  unsigned long long kern_dst);
extern int df_get_user2(unsigned long long user_src, unsigned short user_val, unsigned long long kern_dst);
extern int df_get_user4(unsigned long long user_src, unsigned int user_val,   unsigned long long kern_dst);
extern int df_get_user8(unsigned long long user_src, unsigned long user_val,  unsigned long long kern_dst);
extern int df_get_useru8(unsigned long long user_src, long unsigned int user_val, unsigned long long kern_dst);

// SafeFetch copy_from_user hook
extern unsigned long df_copy_from_user(unsigned long long from, unsigned long long to, unsigned long size);
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
extern unsigned long df_copy_from_user_pinning(unsigned long long from, unsigned long long to, unsigned long size);
#endif
#endif
