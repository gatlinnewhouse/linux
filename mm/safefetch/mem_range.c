// Include the data structures needed by the defense
#include <linux/mem_range.h>
#include "safefetch_debug.h"

#ifdef SAFEFETCH_MEASURE_DEFENSE
#include <linux/dfcache_measuring.h>
#endif

#if defined(SAFEFETCH_FLOATING_ADAPTIVE_WATERMARK) && defined(SAFEFETCH_STATIC_KEYS)
#warning "SafeFetch Using Adaptive Watermark Scheme"
uint8_t SAFEFETCH_ADAPTIVE_WATERMARK = 63;
#else
#warning "SafeFetch NOT Using Adaptive Watermark Scheme"
#endif

struct mem_range* create_mem_range(unsigned long long user_begin,
        unsigned long user_size){
    struct mem_range *new_mr;

    new_mr = (struct mem_range *) allocate_from_region(DF_CUR_METADATA_REGION_ALLOCATOR, sizeof(struct mem_range));

    if(!new_mr){
        printk(KERN_EMERG "ERROR: Couldn't allocate new mem range");
        return NULL;
    }

    // Set the pointer to the correct values
    new_mr->mr_begin = user_begin;
    new_mr->mr_end = user_begin + user_size - 1;

    // Initialise the data structure related values
    //SAFEFETCH_MEM_RANGE_STRUCT_INIT(new_mr);

    new_mr->mr_prot_loc = allocate_from_region(DF_CUR_STORAGE_REGION_ALLOCATOR, user_size);

    if(!new_mr->mr_prot_loc){
        printk(KERN_EMERG "[%s] ERROR: Couldn't allocate user memory area %ld\n", current->comm, user_size);
        return NULL;
    }

#if defined(SAFEFETCH_PIN_BUDDY_PAGES)
    new_mr->is_trap = 0;
#endif

    // Return newly created memory range
    return new_mr;
}

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
struct mem_range* create_pin_range(unsigned long long user_begin, unsigned long user_size,
        unsigned long long kern_loc){
    struct mem_range *new_mr;

    new_mr = (struct mem_range *) allocate_from_region(DF_CUR_METADATA_REGION_ALLOCATOR, sizeof(struct mem_range));

    if(!new_mr){
        printk(KERN_EMERG "ERROR: Couldn't allocate new mem range");
        return NULL;
    }

    // Set the pointer to the correct values
    new_mr->mr_begin = user_begin;
    new_mr->mr_end = user_begin + user_size - 1;

    // Initialise the data structure related values
    //SAFEFETCH_MEM_RANGE_STRUCT_INIT(new_mr);

#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
    new_mr->mr_prot_loc = pin_compound_pages(DF_CUR_STORAGE_REGION_ALLOCATOR, (void *)kern_loc, user_size);
#else
    new_mr->mr_prot_loc = pin_compound_pages(DF_CUR_STORAGE_REGION_ALLOCATOR, (void *)kern_loc);
#endif

    if(!new_mr->mr_prot_loc){
        printk(KERN_EMERG "ERROR: Couldn't allocate user memory area");
        return NULL;
    }

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
    new_mr->mr_check_loc = kmalloc(user_size, GFP_ATOMIC);
    memcpy(new_mr->mr_check_loc, (void *) kern_loc, user_size);
#endif

    new_mr->is_trap = 1;

    // Return newly created memory range
    return new_mr;
}
void copy_from_page_pin(void * kern_dst, unsigned long long pin_virt_addr, unsigned long long user_size){
   void *src;
   struct page *page;
   
   unsigned long long page_reminder = PAGE_SIZE - (pin_virt_addr & (PAGE_SIZE - 1));
   page = virt_to_page(pin_virt_addr);
   src = kmap_atomic(page);

   if (page_reminder >= user_size){
      memcpy(kern_dst, (void *)pin_virt_addr, user_size);
      kunmap_atomic(src);
      return;
   } else {
      memcpy(kern_dst, (void *)pin_virt_addr, page_reminder);
   }
   kunmap_atomic(src);
   user_size -= page_reminder;
   kern_dst += page_reminder;
   pin_virt_addr = ALIGN_DOWN(pin_virt_addr, PAGE_SIZE) + PAGE_SIZE;
      

   while (user_size){
      page = virt_to_page(pin_virt_addr);
      src = kmap_atomic(page);
      if (user_size >= PAGE_SIZE){
         memcpy(kern_dst, src, PAGE_SIZE); 
         kunmap_atomic(src);
      } else {
         memcpy(kern_dst, src, user_size);
         kunmap_atomic(src);
         return;
     }

     pin_virt_addr += PAGE_SIZE;
     kern_dst += PAGE_SIZE;
     user_size -= PAGE_SIZE;
   }
}
#endif

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_TRACING)
// Started out nice but now all debugging functionality is sloppily
// added all over the place. Find a way to merge all debugging functionality
// (macros, functions) in the same place.
#define SAFEFETCH_JUST_INTERRUPTS_WHILE_TASK_BLOCKED

// This function warns us about interrupts that happen while no syscalls are in
// tranzit.
static inline void warn_dfcache_use(void) {
   if (current->df_stats.check_next_access){
         current->df_stats.traced = 1;
         WARN_ON(1);
         current->df_stats.traced = 0;
   }
}

// This warns us about interrupts that use DFCACHER while a syscall is blocked.
static inline void warn_dfcache_use_on_blocked(void) {
    if (!in_task() && !current->df_stats.check_next_access){
         current->df_stats.traced = 1;
         WARN_ON(SAFEFETCH_MEM_RANGE_INIT_FLAG);
         current->df_stats.traced = 0;
    }
}
#endif

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES)
#warning "Compiling SafeFetch with vulnerability reporting"
struct df_bug_struct* vuln_reports[MAX_REPORTS] = {NULL};
DEFINE_SPINLOCK(df_exploit_lock);
static inline void dump_vulnerability(int func){
   int i;
   int max_tries = 0;
   spin_lock(&df_exploit_lock);
   if (vuln_reports[0] == NULL)
       memset(vuln_reports, 0, MAX_REPORTS * sizeof(struct df_bug_struct*));

   for (i = 0; i < MAX_REPORTS; i++){
       if (max_tries == MAX_SYSCALL_REPORTS){
           break;
       }
       if (vuln_reports[i] == NULL){
            // Report bug


            current->df_stats.traced = 1;
            printk("=====Bug in Syscal:%d Comm:%s\n", DF_SYSCALL_NR, current->comm);       
            WARN_ON(1);
            printk("=====End of Bug:%d Comm:%s\n", DF_SYSCALL_NR, current->comm);
            current->df_stats.traced = 0;
           



            vuln_reports[i] = kmalloc(sizeof(struct df_bug_struct), GFP_ATOMIC); 
            memset(vuln_reports[i], 0, sizeof(struct df_bug_struct));
            vuln_reports[i]->func = func;
            vuln_reports[i]->syscall_nr = DF_SYSCALL_NR;

           
            break;
              
       }
       if (vuln_reports[i]->syscall_nr == DF_SYSCALL_NR && vuln_reports[i]->func == func){
           max_tries++;
       }
   }
   spin_unlock(&df_exploit_lock);

}
#endif

#ifndef SAFEFETCH_RBTREE_MEM_RANGE

// DEBUGING UTILITIES
#ifdef SAFEFETCH_DEBUG
static inline void __mem_range_dump_ll(void){
   struct list_head *item;
   struct mem_range *next_range;
   unsigned int list_size = 0;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       return;
   }
   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====Start of mem_range_dump(LLIST)====<\n");
   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
        next_range = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
        printk(KERN_INFO"[SafeFetch][ModuleDebug] [0x%llx - 0x%llx] size: 0x%llx\n",  next_range->mr_begin, next_range->mr_end, next_range->mr_end - next_range->mr_begin + 1);
        list_size++;
   }
   printk(KERN_INFO"[SafeFetch][ModuleDebug] MemRangeSize: %d\n",  list_size);
   printk(KERN_INFO"[SafeFetch][ModuleDebug] Mem Struct Size: %ld\n",  sizeof(struct mem_range));
   printk("[SafeFetch][ModuleDebug] Number of double fetches: %lld\n", DF_SYSCALL_FETCHES);
   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====End of mem_range_dump(LLIST)====<\n");
}

static inline void __dump_range_ll(unsigned long long start){
   struct list_head *item;
   struct mem_range *next_range;
   int i, size;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       return;
   }
   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====Start of dump_range====<\n");
   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
        next_range = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
        if (next_range->mr_begin == start){
           size = next_range->mr_end - next_range->mr_begin + 1;
           for (i = 0; i < size;  i++){
               if ( (i % 8) == 0) {
                  printk("\n");
               }
               printk(KERN_CONT"0x%x ", *((unsigned char *)(next_range->mr_prot_loc+i)));

           }
           printk("\n");
           break;
        }
   }

   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====End of dump_range====<\n");
}

static inline void __dump_range_stats_ll(int *range_size, unsigned long long *avg_size){
   struct list_head *item;
   struct mem_range *next_range;
   int rsize = 0;
   uint64_t msize = 0;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       *range_size = 0;
       *avg_size = 0;
       return;
   }
   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
        next_range = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
        msize += next_range->mr_end - next_range->mr_begin + 1;
        rsize++;
   }

   *range_size = rsize;
   *avg_size = (unsigned long long) msize / rsize;
   
}

static inline void __dump_range_stats_extended_ll(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
   struct list_head *item;
   struct mem_range *next_range;
   int rsize = 0;
   uint64_t msize = 0, intermediate_size = 0;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       *range_size = 0;
       *min_size = 0;
       *max_size = 0;
       *avg_size = 0;
       *total_size = 0;
       return;
   }
   *min_size = 0;
   *max_size = 0;
   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
        next_range = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
        intermediate_size = next_range->mr_end - next_range->mr_begin + 1;
        msize += intermediate_size;
        if (intermediate_size > *max_size){
           *max_size = intermediate_size;
        }
        if (*min_size == 0 || (*min_size > intermediate_size)){
           *min_size = intermediate_size;
        } 
        rsize++;
   }

   *range_size = rsize;
   *total_size = msize;
   *avg_size = (unsigned long long) msize / rsize;
   
}
#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
#warning "Debuggin Page Pinning"
static inline void __check_pins_ll(void){
   struct list_head *item;
   struct mem_range *next_range;
   size_t size;
   void *intermediate_buff;
   int val;

   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG)
       return;

   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
        next_range = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
        if (next_range->is_trap){
           size = next_range->mr_end - next_range->mr_begin + 1;
           intermediate_buff = kmalloc(size, GFP_KERNEL);
           copy_from_page_pin(intermediate_buff, (unsigned long long)next_range->mr_prot_loc, size);
           if ((val = memcmp(intermediate_buff, next_range->mr_check_loc, size)) != 0){
                printk("[SafeFetch][Page_Pinning][Sys %d][Comm %s] Buffers Differ At Some point %d %ld\n", DF_SYSCALL_NR, current->comm, val, size);
           }

           kfree(intermediate_buff);
           kfree(next_range->mr_check_loc);
        }
   }

}
#endif

#endif

// Search for the first overlapping range or return the first range after which our
// copy chunk should be placed. 
static inline struct mem_range* __search_range_ll(unsigned long long user_begin, unsigned long long user_end){

   struct list_head *item;
   struct mem_range *next_range, *prev_range;

   prev_range = NULL;

   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
	 next_range = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
         // Range fully encapsulates our requested copy chunk.
         if (likely((user_begin > next_range->mr_end))) {
            // Remember last range.
            prev_range = next_range;
            continue;
         }
         else if (likely((user_end < next_range->mr_begin))){
            // Return previous range.
            break;
         }
         else if (next_range->mr_begin <= user_begin && next_range->mr_end >= user_end){
            next_range->overlapping = df_range_encapsulates;
            return next_range;
         }
         else {
             //  In this case the memory region intersects our user buffer.
             // ((user_begin <= next_range->mr_begin && user_end >= next_range->mr_begin) or
             // (next_range->mr_end <= user_end && next_range->mr_end >= user_begin))
             next_range->overlapping = df_range_overlaps;
             return next_range;
         }  
   }

   if (prev_range){
      /* We are returning the range after which we must add the new chunk */
      prev_range->overlapping = df_range_previous;
   }

#if defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) || defined (SAFEFETCH_STATIC_KEYS) 
   // We are about to add a new range in the link list, increment the counter
   // If we reached the watermark on the next copy from user we switch to the 
   // rb-tree implementation.
   IF_SAFEFETCH_STATIC_BRANCH_LIKELY_WRAPPER(safefetch_adaptive_key){
      SAFEFETCH_INCREMENT_COPIES(current);
   }
#endif

   return prev_range;
}
// @mr position from where we start copying into the new mr
// @new_mr new memory region where we will copy old mrs.
static inline void __defragment_mr_ll(struct mem_range *new_mr, struct mem_range *mr){
    struct mem_range *mr_next;
    unsigned long long split_mr_begin, mr_offset, mr_size;
#ifdef SAFEFETCH_DEBUG
    unsigned long long nranges = 0, nbytes = 0;
#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
    size_t new_size;
    char * intermediary;
#endif
#endif

    // Add our new_mr just before the first mr we will remove.
    list_add_tail(&(SAFEFETCH_MR_NODE_LL(new_mr)), &(SAFEFETCH_MR_NODE_LL(mr)));

#if defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) || defined (SAFEFETCH_STATIC_KEYS) 
   // We are about to add a new range in the link list, increment the counter
   // If we reached the watermark on the next copy from user we switch to the 
   // rb-tree implementation.
   IF_SAFEFETCH_STATIC_BRANCH_LIKELY_WRAPPER(safefetch_adaptive_key){
      SAFEFETCH_INCREMENT_COPIES(current);
   }
#endif

    // Iterate over all previous mrs that span across the user buffer and 
    // copy these mrs into the new mr.
    list_for_each_entry_safe_from(mr, mr_next, &(SAFEFETCH_HEAD_NODE_LL(current)), SAFEFETCH_NODE_MEMBER_LL) {
       // This might be the last mr that must be patched.
       // If not this is past the user buffer address so simply break the loop
       // as all remaining ranges are past this.
       if (mr->mr_end > new_mr->mr_end) {
           // The begining of the new Split mr will be new_mr->mr_end + 1.
           split_mr_begin = new_mr->mr_end + 1;
           // Split mr only if this is the last mr that intersects the user buffer.
           if (split_mr_begin > mr->mr_begin){
                  // Copy [mr->mr_begin, split_mr_begin) to the new protection range
                  mr_offset = mr->mr_begin - new_mr->mr_begin;
                  mr_size = split_mr_begin - mr->mr_begin;
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
                  if (!mr->is_trap)
                      memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
                  else 
                      copy_from_page_pin(new_mr->mr_prot_loc + mr_offset, (unsigned long long)mr->mr_prot_loc, mr_size);
                 
#else
                  memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
#endif

                  // Split the old mr
                  mr->mr_prot_loc = (char *) (mr->mr_prot_loc + mr_size);
                  mr->mr_begin =  split_mr_begin;
#ifdef SAFEFETCH_DEBUG

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING) 
                  // In case we do defragmentation adjust the check location.
                  new_size = mr->mr_end - mr->mr_begin + 1;
                  intermediary = kmalloc(new_size, GFP_ATOMIC);
                  memcpy(intermediary, mr->mr_check_loc + mr_size, new_size);
                  kfree(mr->mr_check_loc);
                  mr->mr_check_loc = intermediary;
#endif

                 nranges++;
                 nbytes += mr_size;
                 SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  defragment_mem_range: [0x%llx] Split Fragment at 0x%llx of size 0x%llx\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, mr->mr_begin, mr_size);
#endif
           } 
           // If not this mr is past the user buffer so don't do anything.

           break;
        }
        /* Copy previous mr to the new mr */
        mr_offset = mr->mr_begin - new_mr->mr_begin;
        mr_size = mr->mr_end - mr->mr_begin + 1;
        
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
        if (!mr->is_trap)
           memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
        else
           copy_from_page_pin(new_mr->mr_prot_loc + mr_offset, (unsigned long long)mr->mr_prot_loc, mr_size);
#else
        memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
#endif

#if defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) || defined (SAFEFETCH_STATIC_KEYS) 
                 // We are about to add a new range in the link list, increment the counter
                 // If we reached the watermark on the next copy from user we switch to the 
                 // rb-tree implementation.
        IF_SAFEFETCH_STATIC_BRANCH_LIKELY_WRAPPER(safefetch_adaptive_key){
                     SAFEFETCH_DECREMENT_COPIES(current);
                 }
#endif
        /*  Remove this range now */
        list_del(&(SAFEFETCH_MR_NODE_LL(mr)));

#ifdef SAFEFETCH_DEBUG
        nranges++;
        nbytes += mr_size;
        SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  defragment_mem_range: [0x%llx] Fragment at 0x%llx of size 0x%llx\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, mr->mr_begin, mr_size);
#endif

   }

   SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  defragment_mem_range: Defragmented %lld ranges totaling 0x%llx bytes for 0x%llx\n", current->comm, DF_SYSCALL_NR, nranges, nbytes, new_mr->mr_begin); 
}

#endif // !defined(SAFEFETCH_RBTREE_MEM_RANGE)

#if defined(SAFEFETCH_RBTREE_MEM_RANGE) || defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) || defined(SAFEFETCH_STATIC_KEYS)

#ifdef SAFEFETCH_DEBUG
// Just a small test to see that the rb_trees are indeed resonably balanced. 
// Walk the rb-tree first left then right and output the sizes.
static noinline void __mem_range_debug_balance(void){
   unsigned int depth;
   struct rb_node *mr_node = (&SAFEFETCH_HEAD_NODE_RB(current))->rb_node;

   depth = 0;
   while(mr_node){
         depth++;
         mr_node = mr_node->rb_left;
   }

   printk(KERN_INFO"[SafeFetch][ModuleDebug] Depth_left: %d\n",  depth);


   mr_node = (&SAFEFETCH_HEAD_NODE_RB(current))->rb_node;
   depth = 0;
   while(mr_node){
         mr_node = mr_node->rb_right;
         depth++;
   }

   printk(KERN_INFO"[SafeFetch][ModuleDebug] Depth_right: %d\n",  depth);

}

static inline void __mem_range_dump_rb(void){
   struct rb_node *mr_node;
   struct mem_range *next_range;
   unsigned int list_size = 0;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       return;
   }
   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====Start of mem_range_dump(RBTREE)====<\n");
   mr_node = rb_first(&SAFEFETCH_HEAD_NODE_RB(current));
   do {
        next_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
        printk(KERN_INFO"[SafeFetch][ModuleDebug] [0x%llx - 0x%llx] size: 0x%llx\n",  next_range->mr_begin, next_range->mr_end, next_range->mr_end - next_range->mr_begin + 1);
        mr_node = rb_next(&SAFEFETCH_MR_NODE_RB(next_range));
        list_size++;
    
    } while (mr_node);

   printk(KERN_INFO"[SafeFetch][ModuleDebug] MemRangeSize: %d\n",  list_size);
   printk("[SafeFetch][ModuleDebug] Number of double fetches: %lld\n", DF_SYSCALL_FETCHES);
   printk(KERN_INFO"[SafeFetch][ModuleDebug] Mem Struct Size: %ld\n",  sizeof(struct mem_range));
   __mem_range_debug_balance();
   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====End of mem_range_dump(RBTREE)====<\n");
}

static inline void __dump_range_rb(unsigned long long start){
   struct rb_node *mr_node;
   struct mem_range *next_range;
   int i, size;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       return;
   }
   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====Start of dump_range====<\n");
   mr_node = rb_first(&SAFEFETCH_HEAD_NODE_RB(current));
   do {
        next_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
        if (next_range->mr_begin == start){
           size = next_range->mr_end - next_range->mr_begin + 1;
           for (i = 0; i < size;  i++){
               if ( (i % 8) == 0) {
                  printk("\n");
               }
               printk(KERN_CONT"0x%x ", *((unsigned char *)(next_range->mr_prot_loc+i)));
           }
           printk("\n");
           break;
        }
        mr_node = rb_next(&SAFEFETCH_MR_NODE_RB(next_range));
    
    } while (mr_node);

   printk(KERN_INFO"[SafeFetch][ModuleDebug]>====End of dump_range====<\n");
}

static inline void __dump_range_stats_rb(int *range_size, unsigned long long *avg_size){
   struct rb_node *mr_node;
   struct mem_range *next_range;
   int rsize = 0;
   uint64_t msize = 0;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       *range_size = 0;
       *avg_size = 0;
       return;
   }
   mr_node = rb_first(&SAFEFETCH_HEAD_NODE_RB(current));
   do {
        next_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
        msize += next_range->mr_end - next_range->mr_begin + 1;
        rsize++;
        mr_node = rb_next(&SAFEFETCH_MR_NODE_RB(next_range));
    } while (mr_node);

    *range_size = rsize;
    *avg_size = (unsigned long long) msize / rsize;
}

static inline void __dump_range_stats_extended_rb(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
   struct rb_node *mr_node;
   struct mem_range *next_range;
   int rsize = 0;
   uint64_t msize = 0, intermediate_size = 0;
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
       *range_size = 0;
       *min_size = 0;
       *max_size = 0;
       *avg_size = 0;
       *total_size = 0;
       return;
   }
   mr_node = rb_first(&SAFEFETCH_HEAD_NODE_RB(current));
   *min_size = 0;
   *max_size = 0;
   do {
        next_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
        intermediate_size = next_range->mr_end - next_range->mr_begin + 1;
        msize += intermediate_size;
        rsize++;
        if (intermediate_size > *max_size){
           *max_size = intermediate_size;
        }
        if (*min_size == 0 || (*min_size > intermediate_size)){
           *min_size = intermediate_size;
        } 
        mr_node = rb_next(&SAFEFETCH_MR_NODE_RB(next_range));
    } while (mr_node);

    *range_size = rsize;
    *total_size = msize;
    *avg_size = (unsigned long long) msize / rsize;
}

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
static inline void __check_pins_rb(void){
   struct mem_range *next_range;
   struct rb_node *mr_node;
   size_t size;
   void *intermediate_buff;
   int val;

   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG)
       return;

   mr_node = rb_first(&SAFEFETCH_HEAD_NODE_RB(current));
   do {
        next_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
        if (next_range->is_trap){
           size = next_range->mr_end -next_range->mr_begin + 1;
           intermediate_buff = kmalloc(size, GFP_KERNEL);
           copy_from_page_pin(intermediate_buff, (unsigned long long)next_range->mr_prot_loc, size);
           if ((val = memcmp(intermediate_buff, next_range->mr_check_loc, size)) != 0){
                printk("[SafeFetch][Page_Pinning][Sys %d][Comm %s] Buffers Differ At Some point %d %ld\n", DF_SYSCALL_NR, current->comm, val, size);
           }

           kfree(intermediate_buff);
           kfree(next_range->mr_check_loc);
        }
        mr_node = rb_next(&SAFEFETCH_MR_NODE_RB(next_range));
   } while (mr_node);

}
#endif

#endif

// Search for the first overlapping range or return the first range after which our
// copy chunk should be placed. 
static inline struct mem_range* __search_range_rb(unsigned long long user_begin, unsigned long long user_end){

   struct rb_node *mr_node;
   struct mem_range *next_range, *prev_range;

   prev_range = NULL;

   mr_node = (&SAFEFETCH_HEAD_NODE_RB(current))->rb_node;

   while(mr_node){
         next_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
         // Check if entry is on the right
         if (likely((user_begin > next_range->mr_end))){
            mr_node = mr_node->rb_right;
         }
         // Check if entry is on the left
         else if (likely((user_end < next_range->mr_begin))){
            mr_node = mr_node->rb_left;
         }
         // Range fully encapsulates our requested copy chunk.
         else if (next_range->mr_begin <= user_begin && next_range->mr_end >= user_end){
            next_range->overlapping = df_range_encapsulates;
            return next_range;
         }
         else {
             //  In this case the memory region intersects our user buffer.
             // ((user_begin <= next_range->mr_begin && user_end >= next_range->mr_begin) or
             // (next_range->mr_end <= user_end && next_range->mr_end >= user_begin))
             // TODO this can be further optimized if we do rb_prev in defragment_mr
             // to save one more iteration over the RB-Tree.
             while((mr_node = rb_prev(mr_node))) {
                prev_range = rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB);
                if (prev_range->mr_end < user_begin){
                    break;
                }
                next_range = prev_range;
             }
             next_range->overlapping = df_range_overlaps;
             return next_range;
         }

         prev_range = next_range;
   }
   
   if (prev_range){
      /* We are returning the range closest to where we need to insert the node */
      prev_range->overlapping = df_range_previous;
   }

   return prev_range;
}

// @mr position from where we start copying into the new mr
// @new_mr new memory region where we will copy old mrs.
static inline void __defragment_mr_rb(struct mem_range *new_mr, struct mem_range *mr){
    struct rb_node *mr_node, *prev_node;
    struct rb_node **position;
    unsigned long long split_mr_begin, mr_offset, mr_size;
#ifdef SAFEFETCH_DEBUG
    unsigned long long nranges = 0, nbytes = 0;
#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
    size_t new_size;
    char * intermediary;
#endif
#endif

    prev_node = NULL;

    do {
       // This might be the last mr that must be patched.
       // If not this is past the user buffer address so simply break the loop
       // as all remaining ranges are past this.
       if (mr->mr_end > new_mr->mr_end) {
           // The begining of the new Split mr will be new_mr->mr_end + 1.
           split_mr_begin = new_mr->mr_end + 1;
           // Split mr only if this is the last mr that intersects the user buffer.
           if (split_mr_begin > mr->mr_begin){
                  // Copy [mr->mr_begin, split_mr_begin) to the new protection range
                  mr_offset = mr->mr_begin - new_mr->mr_begin;
                  mr_size = split_mr_begin - mr->mr_begin;

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
                  if (!mr->is_trap)
                      memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
                  else
                      copy_from_page_pin(new_mr->mr_prot_loc + mr_offset, (unsigned long long)mr->mr_prot_loc, mr_size);
#else
                  memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
#endif

                  // Split the old mr
                  mr->mr_prot_loc = (char *) (mr->mr_prot_loc + mr_size);
                  mr->mr_begin =  split_mr_begin;
#ifdef SAFEFETCH_DEBUG
#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING) 
                  // In case we do defragmentation adjust the check location.
                  new_size = mr->mr_end - mr->mr_begin + 1;
                  intermediary = kmalloc(new_size, GFP_ATOMIC);
                  memcpy(intermediary, mr->mr_check_loc + mr_size, new_size);
                  kfree(mr->mr_check_loc);
                  mr->mr_check_loc = intermediary;
#endif
                 nranges++;
                 nbytes += mr_size;
                 SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  defragment_mem_range: [0x%llx] Split Fragment at 0x%llx of size 0x%llx\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, mr->mr_begin, mr_size);
#endif
           } 
           // If not this mr is past the user buffer so don't do anything.

           break;
        }

        // Erase the node in the previous iteration
        if (prev_node) {
           rb_erase(prev_node, &SAFEFETCH_HEAD_NODE_RB(current));
        }

        /* Copy previous mr to the new mr */
        mr_offset = mr->mr_begin - new_mr->mr_begin;
        mr_size = mr->mr_end - mr->mr_begin + 1;
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
        if (!mr->is_trap)
           memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
        else
           copy_from_page_pin(new_mr->mr_prot_loc + mr_offset, (unsigned long long)mr->mr_prot_loc, mr_size);
#else
        memcpy(new_mr->mr_prot_loc + mr_offset, mr->mr_prot_loc, mr_size);
#endif

#ifdef SAFEFETCH_DEBUG
        nranges++;
        nbytes += mr_size;
        SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  defragment_mem_range: [0x%llx] Fragment at 0x%llx of size 0x%llx\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, mr->mr_begin, mr_size);
#endif

        mr_node = rb_next(&SAFEFETCH_MR_NODE_RB(mr));

        // Keep track of previous mr node.
        prev_node = &SAFEFETCH_MR_NODE_RB(mr);

        mr = (mr_node) ? rb_entry(mr_node, struct mem_range, SAFEFETCH_NODE_MEMBER_RB) : NULL ;
    
    } while (mr);

    if (prev_node){
       // If we have a previous node, then replace it with our new node.
       rb_replace_node(prev_node, &SAFEFETCH_MR_NODE_RB(new_mr), &SAFEFETCH_HEAD_NODE_RB(current));
    } else {
       // If not then we split the previous mr, which now is exactly the mr before which we need to include our new node.
       prev_node = &(SAFEFETCH_MR_NODE_RB(mr));
       position = &(prev_node->rb_left);
       while ((*position)) {
           prev_node = *position;
           position = &((*position)->rb_right);
       }
       rb_link_node(&SAFEFETCH_MR_NODE_RB(new_mr), prev_node, position);
       rb_insert_color(&SAFEFETCH_MR_NODE_RB(new_mr), &SAFEFETCH_HEAD_NODE_RB(current));
         
    }

   SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  defragment_mem_range: Defragmented %lld ranges totaling 0x%llx bytes for 0x%llx\n", current->comm, DF_SYSCALL_NR, nranges, nbytes, new_mr->mr_begin); 
}
#endif // defined(SAFEFETCH_RBTREE_MEM_RANGE) || defined(SAFEFETCH_ADAPTIVE_MEM_RANGE)

#if !defined(SAFEFETCH_RBTREE_MEM_RANGE) && !defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) && !defined(SAFEFETCH_STATIC_KEYS)
// Link List main hooks

struct mem_range* search_range(unsigned long long user_begin, unsigned long long user_end) {

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_TRACING)
#ifndef SAFEFETCH_JUST_INTERRUPTS_WHILE_TASK_BLOCKED
   warn_dfcache_use();
#endif
   warn_dfcache_use_on_blocked();
#endif  
   /* We could replace this with a bit check on the current struct */
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
      /* Laizy initialization of metadata/data regions */
      if (unlikely(!initialize_regions())){
         return NULL;
      } 
      SAFEFETCH_MEM_RANGE_ROOT_INIT_LL();
      return NULL;
   }

   return __search_range_ll(user_begin, user_end);
}

void defragment_mr(struct mem_range *new_mr, struct mem_range *mr){
     __defragment_mr_ll(new_mr, mr);
}

#ifdef SAFEFETCH_DEBUG

void dump_range_stats(int *range_size, unsigned long long *avg_size){
     __dump_range_stats_ll(range_size, avg_size);
}

void mem_range_dump(void){
     __mem_range_dump_ll();
}

void dump_range(unsigned long long start){
     __dump_range_ll(start);
}

void dump_range_stats_extended(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
      __dump_range_stats_extended_ll(range_size, min_size, max_size, avg_size, total_size);
}

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
void check_pins(void){
    __check_pins_ll();
}
#endif

#endif

#elif defined(SAFEFETCH_RBTREE_MEM_RANGE)
// NOTES: RB-tree main hooks

struct mem_range* search_range(unsigned long long user_begin, unsigned long long user_end) {
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_TRACING)
#ifndef SAFEFETCH_JUST_INTERRUPTS_WHILE_TASK_BLOCKED
   warn_dfcache_use();
#endif
   warn_dfcache_use_on_blocked();
#endif

   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
         if (unlikely(!initialize_regions())){ 
            return NULL;
         }
         SAFEFETCH_MEM_RANGE_ROOT_INIT_RB();
         return NULL;
   }

   return __search_range_rb(user_begin, user_end);
}

void defragment_mr(struct mem_range *new_mr, struct mem_range *mr){
    __defragment_mr_rb(new_mr, mr);
}

#ifdef SAFEFETCH_DEBUG

void dump_range_stats(int *range_size, unsigned long long *avg_size){
    __dump_range_stats_rb(range_size, avg_size);
}

void mem_range_dump(void){
    __mem_range_dump_rb();
}

void dump_range(unsigned long long start){
    __dump_range_rb(start);
}

void dump_range_stats_extended(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
      __dump_range_stats_extended_rb(range_size, min_size, max_size, avg_size, total_size);
}

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
void check_pins(){
    __check_pins_rb();
}
#endif

#endif

#else 
// NOTES: Adaptive implementation hooks.

// Just add this functionality from a newer kernel version
static inline int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
}

#define CONVERT_LIMIT SAFEFETCH_ADAPTIVE_WATERMARK + 1

noinline void convert_to_rbtree(uint8_t nelem){
   uint8_t i, step, parent, level;
   struct list_head *item;
#if defined(SAFEFETCH_FLOATING_ADAPTIVE_WATERMARK) && defined(SAFEFETCH_STATIC_KEYS)
   struct mem_range *range_vector[64];
#else
   struct mem_range *range_vector[CONVERT_LIMIT];
#endif
   i = 1;
   list_for_each(item, &(SAFEFETCH_HEAD_NODE_LL(current))) {
         range_vector[i++] = list_entry(item, struct mem_range, SAFEFETCH_NODE_MEMBER_LL);
   }

   level = nelem >> 1;
   SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_RB(range_vector[level]);

   while ((level = level >> 1)){
      step = level << 2;
      for ( i = level; i < nelem; i += step){
          parent = i + level;
          rb_link_node(&SAFEFETCH_MR_NODE_RB(range_vector[i]), &SAFEFETCH_MR_NODE_RB(range_vector[parent]), &(SAFEFETCH_MR_NODE_RB(range_vector[parent]).rb_left));
          rb_insert_color(&SAFEFETCH_MR_NODE_RB(range_vector[i]), &SAFEFETCH_HEAD_NODE_RB(current)); 
          rb_link_node(&SAFEFETCH_MR_NODE_RB(range_vector[parent+level]), &SAFEFETCH_MR_NODE_RB(range_vector[parent]), &(SAFEFETCH_MR_NODE_RB(range_vector[parent]).rb_right));
          rb_insert_color(&SAFEFETCH_MR_NODE_RB(range_vector[parent+level]), &SAFEFETCH_HEAD_NODE_RB(current));
      }
   } 
}

safefetch_inline_attr struct mem_range* __search_range_rb_noinline_hook(unsigned long long user_begin, unsigned long long user_end) {
   return __search_range_rb(user_begin, user_end);
}

safefetch_inline_attr struct mem_range* __search_range_ll_noinline_hook(unsigned long long user_begin, unsigned long long user_end) {
   return __search_range_ll(user_begin, user_end);
}

safefetch_inline_attr void __defragment_mr_ll_noinline_hook(struct mem_range *new_mr, struct mem_range *mr){
   __defragment_mr_ll(new_mr, mr);
}

safefetch_inline_attr void __defragment_mr_rb_noinline_hook(struct mem_range *new_mr, struct mem_range *mr){
   __defragment_mr_rb(new_mr, mr);
}

static inline struct mem_range* __search_range_adaptive(unsigned long long user_begin, unsigned long long user_end) {

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_TRACING)
#ifndef SAFEFETCH_JUST_INTERRUPTS_WHILE_TASK_BLOCKED
   warn_dfcache_use();
#endif
   warn_dfcache_use_on_blocked();
#endif

   /* We could replace this with a bit check on the current struct */
   if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
        /* Laizy initialization of metadata/data regions */
        if (unlikely(!initialize_regions())){
           return NULL;
        }
        SAFEFETCH_MEM_RANGE_ROOT_INIT_LL();
        SAFEFETCH_RESET_ADAPTIVE(current);
        SAFEFETCH_RESET_COPIES(current);
        return NULL;
   }

   if (likely(!SAFEFETCH_IS_ADAPTIVE(current))) {
      // Move previous check outside of function. This helps 
      if (SAFEFETCH_CHECK_COPIES(current)){                                       
          SAFEFETCH_SET_ADAPTIVE(current); 
          // TODO Build rb-tree.
          convert_to_rbtree(CONVERT_LIMIT);
          // Now search the new range in the rb-tree
          return __search_range_rb_noinline_hook(user_begin, user_end);                                                             
      } 

      return __search_range_ll_noinline_hook(user_begin, user_end);
   }
    
   return __search_range_rb_noinline_hook(user_begin, user_end);

}

static inline void __defragment_mr_adaptive(struct mem_range *new_mr, struct mem_range *mr){
     likely(!SAFEFETCH_IS_ADAPTIVE(current)) ?  __defragment_mr_ll_noinline_hook(new_mr, mr) : __defragment_mr_rb_noinline_hook(new_mr, mr);
}

#ifdef SAFEFETCH_DEBUG

static inline void __dump_range_stats_adaptive(int *range_size, unsigned long long *avg_size){
    !SAFEFETCH_IS_ADAPTIVE(current) ? __dump_range_stats_ll(range_size, avg_size) : __dump_range_stats_rb(range_size, avg_size);
}

static inline void __mem_range_dump_adaptive(void){
    !SAFEFETCH_IS_ADAPTIVE(current) ?  __mem_range_dump_ll() : __mem_range_dump_rb();
}

static inline void __dump_range_adaptive(unsigned long long start){
    !SAFEFETCH_IS_ADAPTIVE(current) ? __dump_range_ll(start) : __dump_range_rb(start);
}

void __dump_range_stats_extended_adaptive(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
     !SAFEFETCH_IS_ADAPTIVE(current) ?  __dump_range_stats_extended_ll(range_size, min_size, max_size, avg_size, total_size) : __dump_range_stats_extended_rb(range_size, min_size, max_size, avg_size, total_size);
}

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
static void __check_pins_adaptive(void){
    !SAFEFETCH_IS_ADAPTIVE(current) ? __check_pins_ll() : __check_pins_rb();
}
#endif

#endif

#if defined(SAFEFETCH_ADAPTIVE_MEM_RANGE)
// Adittional layer of indirection (so we can use the previous hooks in the static key
// implementation.
struct mem_range* search_range(unsigned long long user_begin, unsigned long long user_end) {

   return __search_range_adaptive(user_begin, user_end);
}

void defragment_mr(struct mem_range *new_mr, struct mem_range *mr){
    __defragment_mr_adaptive(new_mr, mr);
}

#ifdef SAFEFETCH_DEBUG

void dump_range_stats(int *range_size, unsigned long long *avg_size){
    __dump_range_stats_adaptive(range_size, avg_size);
}

void mem_range_dump(void){
    __mem_range_dump_adaptive();
}

void dump_range(unsigned long long start){
    __dump_range_adaptive(start);
}

void dump_range_stats_extended(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
    __dump_range_stats_extended_adaptive(range_size, min_size, max_size, avg_size, total_size);
}

#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
void check_pins(void){
    __check_pins_adaptive();
}
#endif
#endif

#elif defined(SAFEFETCH_STATIC_KEYS) // SAFEFETCH_ADAPTIVE_MEM_RANGE
// TODO Static key implementation goes here.
struct mem_range* search_range(unsigned long long user_begin, unsigned long long user_end) {

   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
       return __search_range_adaptive(user_begin, user_end);
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
             if (unlikely(!initialize_regions())){ 
                return NULL;
             }
             SAFEFETCH_MEM_RANGE_ROOT_INIT_RB();
             return NULL;
       }
       return __search_range_rb(user_begin, user_end);
     } else {
       // The else branch is simply the link list implementation.
       if (!SAFEFETCH_MEM_RANGE_INIT_FLAG){
             /* Laizy initialization of metadata/data regions */
             if (unlikely(!initialize_regions())){
                return NULL;
             } 
             SAFEFETCH_MEM_RANGE_ROOT_INIT_LL();
             return NULL;
       }
       return __search_range_ll(user_begin, user_end);
     }
   }
   
}
void defragment_mr(struct mem_range *new_mr, struct mem_range *mr){

   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
       __defragment_mr_adaptive(new_mr, mr);
       return;
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       __defragment_mr_rb(new_mr, mr);
       return;
     } else {
       // The else branch is simply the link list implementation.
       __defragment_mr_ll(new_mr, mr);
       return;
     }
   }
}

#ifdef SAFEFETCH_DEBUG

void dump_range_stats(int *range_size, unsigned long long *avg_size){

   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
       __dump_range_stats_adaptive(range_size, avg_size);
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       __dump_range_stats_rb(range_size, avg_size);
     } else {
       // The else branch is simply the link list implementation.
       __dump_range_stats_ll(range_size, avg_size);
     }
   }
}

void mem_range_dump(void){

   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
       __mem_range_dump_adaptive();
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       __mem_range_dump_rb();
     } else {
       // The else branch is simply the link list implementation.
       __mem_range_dump_ll();
     }
   }
}

void dump_range(unsigned long long start){
   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
       __dump_range_adaptive(start);
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       __dump_range_rb(start);
     } else {
       // The else branch is simply the link list implementation.
       __dump_range_ll(start);
     }
   }
}

void dump_range_stats_extended(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size){
   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
      __dump_range_stats_extended_adaptive(range_size, min_size, max_size, avg_size, total_size);
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       __dump_range_stats_extended_rb(range_size, min_size, max_size, avg_size, total_size);
     } else {
       // The else branch is simply the link list implementation.
       __dump_range_stats_extended_ll(range_size, min_size, max_size, avg_size, total_size);
     }
   }
}
#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
void check_pins(void){
   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
      __check_pins_adaptive();
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       __check_pins_rb();
     } else {
       // The else branch is simply the link list implementation.
       __check_pins_ll();
     }
   }
}
#endif

#endif // SAFEFETCH_DEBUG

#endif // SAFEFETCH_STATIC_KEYS


#endif

#ifdef SAFEFETCH_DEBUG
EXPORT_SYMBOL(dump_range);
EXPORT_SYMBOL(mem_range_dump);
#endif

#define PATCH_COPY_FUNCTION_RETURN(user, ret) if (!(user -= ret)) return ret

// TODO Pattern this function when porting the RBTREE
unsigned long copy_range( unsigned long long user_src, unsigned long long kern_dst, unsigned long user_size){
    /* Get nearby range */
    unsigned long long mr_offset, user_end, new_mr_begin, new_mr_size;
    struct mem_range *new_mr, *mr;
    unsigned long ret;

    user_end = user_src + user_size - 1;
#ifdef SAFEFETCH_MEASURE_DEFENSE
    #warning "SafeFetch Measuring defense"
    MEASURE_FUNC_AND_COUNT(mr = search_range(user_src, user_end);, current->df_prot_struct_head.df_measures.search_time, current->df_prot_struct_head.df_measures.counter);
#else
    /* Search for the range closest to our copy from user */
    mr = search_range(user_src, user_end);
#endif
    
    /* If no mr we either have no ranges previously copied from user or all ranges are
       larger than this range. Add the range at begining of the list.
       In case of a RB-Tree if mr == NULL then we have an empty RB-Tree so add
       the new mr as root. */
    if (!mr){
         /* Default to a normal copy and add range into the datastructure */

         /* First copy everything in the kernel destination just in case we 
            copy less then the specified ammount of bytes */
         ret = COPY_FUNC((void *) kern_dst, (__force void *)user_src, user_size);

         /* If ret != 0 we haven't copied all bytes so trim the size of the buffer. */
         if (ret) {
             SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning][Task %s][Sys %d] copy_range: Copied less bytes required(0x%lx bytes) copied(0x%lx bytes)\n", current->comm, DF_SYSCALL_NR, user_size, user_size-ret);
             //user_size -= ret;
             PATCH_COPY_FUNCTION_RETURN(user_size, ret);
         }

         new_mr = create_mem_range(user_src, user_size);

         /* Now simply returns -1 */
         ASSERT_OUT_OF_MEMORY(new_mr);

         /* Add the node at the begining */
         //list_add(&(new_mr->node), &(SAFEFETCH_HEAD_NODE));
#ifdef SAFEFETCH_MEASURE_DEFENSE
         MEASURE_FUNC(SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(new_mr);, current->df_prot_struct_head.df_measures.insert_time, (current->df_prot_struct_head.df_measures.counter - 1));
#else
         SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(new_mr);
#endif


         memcpy(new_mr->mr_prot_loc, (void *) kern_dst, user_size);

         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 3, "[SafeFetch][Info][Task %s][Sys %d] copy_range: Created new region @ at 0x%llx with size(0x%llx bytes)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1 );

    }
    else if (mr->overlapping == df_range_previous) {
         /* First copy everything in the kernel destination just in case we 
            copy less then the specified ammount of bytes */
         ret = COPY_FUNC((void *) kern_dst, (__force void *)user_src, user_size);

         /* If ret != 0 we haven't copied all bytes so trim the size of the buffer. */
         if (ret) {
             SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning][Task %s][Sys %d] copy_range: Copied less bytes required(0x%lx bytes) copied(0x%lx bytes)\n", current->comm, DF_SYSCALL_NR, user_size, user_size-ret);
             //user_size -= ret;
             PATCH_COPY_FUNCTION_RETURN(user_size, ret);
         }

         /* Just add the range after to this one */
         new_mr = create_mem_range(user_src, user_size);

         ASSERT_OUT_OF_MEMORY(new_mr);

         /* Add the node between mr and mr->next */
         //list_add(&(new_mr->node), &(mr->node));
#ifdef SAFEFETCH_MEASURE_DEFENSE
         MEASURE_FUNC(SAFEFETCH_MEM_RANGE_STRUCT_INSERT(mr, new_mr);, current->df_prot_struct_head.df_measures.insert_time, (current->df_prot_struct_head.df_measures.counter - 1));
#else
         SAFEFETCH_MEM_RANGE_STRUCT_INSERT(mr, new_mr);
#endif

         /* Now copy kernel destination into the new protection structure */ 

         memcpy(new_mr->mr_prot_loc, (void *) kern_dst, user_size);

         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 3, "[SafeFetch][Info][Task %s][Sys %d] copy_range: Created new region at 0x%llx with size(0x%llx bytes)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1 );

    } 
    else if (mr->overlapping == df_range_overlaps){
         /* Our new range goes from min(user_src, mr->mr_begin) to user_end */
         new_mr_begin = user_src <= mr->mr_begin ? user_src : mr->mr_begin;
         new_mr_size = user_end - new_mr_begin + 1;

         new_mr = create_mem_range(new_mr_begin, new_mr_size);

         ASSERT_OUT_OF_MEMORY(new_mr);

         mr_offset = user_src - new_mr_begin;

         // First copy-in the user buffer from userspace.
          
         ret = COPY_FUNC(new_mr->mr_prot_loc + mr_offset, (__force void *)user_src, user_size);

         if (ret) {
            SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning][Task %s][Sys %d] copy_range: Copied less bytes required(0x%lx bytes) copied(0x%lx bytes)\n", current->comm, DF_SYSCALL_NR, user_size, user_size-ret);
            new_mr->mr_end -= ret;
            // This we can optimize if we first copy in the kernel buffer and do defragmentation on the spot.
            //user_size -= ret;
            PATCH_COPY_FUNCTION_RETURN(user_size, ret);
         }

         // Copy fragments to new_mr and add new_mr to the data structure
         defragment_mr(new_mr, mr);

         /* Copy the new range in the kernel destination */
         memcpy((void *) kern_dst, new_mr->mr_prot_loc + mr_offset, user_size);

         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  copy_range: Overlapping previous region at 0x%llx with size(0x%llx bytes) offset(0x%llx) copy(0x%lx)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1, mr_offset, user_size);

         DF_INC_DEFRAGS;

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES)
         SAFEFETCH_DEBUG_RUN(5, dump_vulnerability(0));
#endif
     
    } else if (mr->overlapping == df_range_encapsulates) {
        /* If range encapsulates our copy chunk then copy from range */
        mr_offset = user_src - mr->mr_begin;

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
        if (!mr->is_trap)
           memcpy((void *) kern_dst, mr->mr_prot_loc + mr_offset, user_size);
        else
           copy_from_page_pin((void *) kern_dst, (unsigned long long)mr->mr_prot_loc + mr_offset, user_size);
#else
        memcpy((void *) kern_dst, mr->mr_prot_loc + mr_offset, user_size);
#endif

        SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY - 1, "[SafeFetch][Info][Task %s][Sys %d] copy_range: Double fetch from region at 0x%llx with size(0x%llx bytes) offset(0x%llx)\n", current->comm, DF_SYSCALL_NR, mr->mr_begin, mr->mr_end - mr->mr_begin + 1, mr_offset);
#ifdef SAFEFETCH_DEBUG
        DF_SYSCALL_FETCHES++;
#endif

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES)
        SAFEFETCH_DEBUG_RUN(5, dump_vulnerability(1));
#endif
        return 0;

    }

    return ret;
}

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
// TODO Pattern this function when porting the RBTREE
unsigned long copy_range_pinning( unsigned long long user_src, unsigned long long kern_dst, unsigned long user_size){
    /* Get nearby range */
    unsigned long long mr_offset, user_end, new_mr_begin, new_mr_size;
    struct mem_range *new_mr, *mr;
    unsigned long ret;

    user_end = user_src + user_size - 1;

    /* Search for the range closest to our copy from user */
    mr = search_range(user_src, user_end);
    
    /* If no mr we either have no ranges previously copied from user or all ranges are
       larger than this range. Add the range at begining of the list.
       In case of a RB-Tree if mr == NULL then we have an empty RB-Tree so add
       the new mr as root. */
    if (!mr){
         /* Default to a normal copy and add range into the datastructure */

         /* First copy everything in the kernel destination just in case we 
            copy less then the specified ammount of bytes */
         ret = COPY_FUNC((void *) kern_dst, (__force void *)user_src, user_size);

         /* If ret != 0 we haven't copied all bytes so trim the size of the buffer. */
         if (ret) {
             SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning][Task %s][Sys %d] copy_range: Copied less bytes required(0x%lx bytes) copied(0x%lx bytes)\n", current->comm, DF_SYSCALL_NR, user_size, user_size-ret);
             //user_size -= ret;
             PATCH_COPY_FUNCTION_RETURN(user_size, ret);
         }

         new_mr = create_pin_range(user_src, user_size, kern_dst);

         /* Now simply returns -1 */
         ASSERT_OUT_OF_MEMORY(new_mr);

         /* Add the node at the begining */
         //list_add(&(new_mr->node), &(SAFEFETCH_HEAD_NODE));
         SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(new_mr);

         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 3, "[SafeFetch][Info][Task %s][Sys %d] copy_range: Created new region @ at 0x%llx with size(0x%llx bytes)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1 );

    }
    else if (mr->overlapping == df_range_previous) {
         /* First copy everything in the kernel destination just in case we 
            copy less then the specified ammount of bytes */
         ret = COPY_FUNC((void *) kern_dst, (__force void *)user_src, user_size);

         /* If ret != 0 we haven't copied all bytes so trim the size of the buffer. */
         if (ret) {
             SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning][Task %s][Sys %d] copy_range: Copied less bytes required(0x%lx bytes) copied(0x%lx bytes)\n", current->comm, DF_SYSCALL_NR, user_size, user_size-ret);
             //user_size -= ret;
             PATCH_COPY_FUNCTION_RETURN(user_size, ret);
         }

         /* Just add the range after to this one */
         new_mr = create_pin_range(user_src, user_size, kern_dst);

         ASSERT_OUT_OF_MEMORY(new_mr);

         /* Add the node between mr and mr->next */
         //list_add(&(new_mr->node), &(mr->node));
         SAFEFETCH_MEM_RANGE_STRUCT_INSERT(mr, new_mr);


         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 3, "[SafeFetch][Info][Task %s][Sys %d] copy_range: Created new region at 0x%llx with size(0x%llx bytes)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1 );

    } 
    else if (mr->overlapping == df_range_overlaps){

         /* Our new range goes from min(user_src, mr->mr_begin) to user_end */
         new_mr_begin = user_src <= mr->mr_begin ? user_src : mr->mr_begin;
         new_mr_size = user_end - new_mr_begin + 1;

         new_mr = create_mem_range(new_mr_begin, new_mr_size);

         ASSERT_OUT_OF_MEMORY(new_mr);

         mr_offset = user_src - new_mr_begin;

         // First copy-in the user buffer from userspace.
          
         ret = COPY_FUNC(new_mr->mr_prot_loc + mr_offset, (__force void *)user_src, user_size);

         if (ret) {
            SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_WARNING, "[SafeFetch][Warning][Task %s][Sys %d] copy_range: Copied less bytes required(0x%lx bytes) copied(0x%lx bytes)\n", current->comm, DF_SYSCALL_NR, user_size, user_size-ret);
            new_mr->mr_end -= ret;
            //user_size -= ret;
            PATCH_COPY_FUNCTION_RETURN(user_size, ret);
         }

         // Copy fragments to new_mr and add new_mr to the data structure
         defragment_mr(new_mr, mr);

         /* Copy the new range in the kernel destination */
         memcpy((void *) kern_dst, new_mr->mr_prot_loc + mr_offset, user_size);

         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 1, "[SafeFetch][Info][Task %s][Sys %d]  copy_range: Overlapping previous region at 0x%llx with size(0x%llx bytes) offset(0x%llx) copy(0x%lx)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1, mr_offset, user_size);

         DF_INC_DEFRAGS;
     
    } else if (mr->overlapping == df_range_encapsulates) {

        /* If range encapsulates our copy chunk then copy from range */
        mr_offset = user_src - mr->mr_begin;

        if (!mr->is_trap)
           memcpy((void *) kern_dst, mr->mr_prot_loc + mr_offset, user_size);
        else
           copy_from_page_pin((void *) kern_dst, (unsigned long long)mr->mr_prot_loc + mr_offset, user_size);

        SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY - 1, "[SafeFetch][Info][Task %s][Sys %d] copy_range: Double fetch from region at 0x%llx with size(0x%llx bytes) offset(0x%llx)\n", current->comm, DF_SYSCALL_NR, mr->mr_begin, mr->mr_end - mr->mr_begin + 1, mr_offset);
#ifdef SAFEFETCH_DEBUG
        DF_SYSCALL_FETCHES++;
#endif
        return 0;

    }

    return ret;
}
#endif
