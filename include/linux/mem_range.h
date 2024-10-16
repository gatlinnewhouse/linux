#ifndef __MEM_RANGE_H__
#define __MEM_RANGE_H__
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/safefetch_static_keys.h>
#include <linux/region_allocator.h>

#define safefetch_inline_attr noinline


#define COPY_FUNC copy_user_generic
#define ASSERT_OUT_OF_MEMORY(mr) if (unlikely(!mr)) return -1;

unsigned long copy_range( unsigned long long user_src, unsigned long long kern_dst, unsigned long user_size);
struct mem_range* search_range(unsigned long long user_begin, unsigned long long user_end);
struct mem_range* create_mem_range(unsigned long long user_begin, unsigned long user_size);
void defragment_mr(struct mem_range *new_mr, struct mem_range *mr);
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
unsigned long copy_range_pinning( unsigned long long user_src, unsigned long long kern_dst, unsigned long user_size);
#endif

#ifdef SAFEFETCH_DEBUG
void dump_range_stats(int *range_size, unsigned long long *avg_size); 
void mem_range_dump(void);
void dump_range(unsigned long long start);
void dump_range_stats_extended(int *range_size, uint64_t *min_size, uint64_t *max_size, unsigned long long *avg_size, uint64_t *total_size);
#if defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
void check_pins(void);
#endif
#endif

//static inline struct mem_range* search_range(unsigned long long user_begin, unsigned long long user_end);

#define SAFEFETCH_TASK_MEM_RANGE_INIT_FLAG(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.initialized
#define SAFEFETCH_MEM_RANGE_INIT_FLAG SAFEFETCH_TASK_MEM_RANGE_INIT_FLAG(current)

#define SAFEFETCH_TASK_RESET_MEM_RANGE(tsk){      \
    SAFEFETCH_TASK_MEM_RANGE_INIT_FLAG(tsk) = 0;  \
};

#define SAFEFETCH_RESET_MEM_RANGE(){              \
    SAFEFETCH_TASK_RESET_MEM_RANGE(current);      \
};

#if !defined(SAFEFETCH_RBTREE_MEM_RANGE) && !defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) && !defined(SAFEFETCH_STATIC_KEYS)

#define SAFEFETCH_HEAD_NODE_LL(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.node
#define SAFEFETCH_NODE_MEMBER_LL node
#define SAFEFETCH_MR_NODE_LL(mr) mr->node

#elif defined(SAFEFETCH_RBTREE_MEM_RANGE)

#define SAFEFETCH_HEAD_NODE_RB(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.node
#define SAFEFETCH_NODE_MEMBER_RB node
#define SAFEFETCH_MR_NODE_RB(mr) mr->node

#else

#define SAFEFETCH_HEAD_NODE_LL(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.ll_node
#define SAFEFETCH_HEAD_NODE_RB(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.rb_node
#define SAFEFETCH_NODE_MEMBER_LL ll_node
#define SAFEFETCH_NODE_MEMBER_RB rb_node
#define SAFEFETCH_MR_NODE_LL(mr) mr->ll_node
#define SAFEFETCH_MR_NODE_RB(mr) mr->rb_node

#ifdef SAFEFETCH_FLOATING_ADAPTIVE_WATERMARK
extern uint8_t SAFEFETCH_ADAPTIVE_WATERMARK;
#else
#define SAFEFETCH_ADAPTIVE_WATERMARK 63
#endif

#define SAFEFETCH_COPIES(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.ncopies

#ifndef SAFEFETCH_USE_SHIFT_COUNTER
#define SAFEFETCH_RESET_COPIES(tsk)     SAFEFETCH_COPIES(tsk) = (SAFEFETCH_ADAPTIVE_WATERMARK - 1)
#define SAFEFETCH_INCREMENT_COPIES(tsk) SAFEFETCH_COPIES(tsk)--
#define SAFEFETCH_DECREMENT_COPIES(tsk) SAFEFETCH_COPIES(tsk)++
#define SAFEFETCH_CHECK_COPIES(tsk) SAFEFETCH_COPIES(tsk) == 0
#else
#warning "SafeFetch Using shift counter"
#define SAFEFETCH_RESET_COPIES(tsk)     SAFEFETCH_COPIES(tsk) = ((uint64_t)1 << (SAFEFETCH_ADAPTIVE_WATERMARK - 1))
#define SAFEFETCH_INCREMENT_COPIES(tsk) SAFEFETCH_COPIES(tsk) >>= 1
#define SAFEFETCH_DECREMENT_COPIES(tsk) SAFEFETCH_COPIES(tsk) <<= 1
#define SAFEFETCH_CHECK_COPIES(tsk) ((uint8_t)SAFEFETCH_COPIES(tsk) & 1)

#endif


#define SAFEFETCH_RESET_ADAPTIVE(tsk) tsk->df_prot_struct_head.df_mem_range_allocator.adaptive = 0
#define SAFEFETCH_SET_ADAPTIVE(tsk)   tsk->df_prot_struct_head.df_mem_range_allocator.adaptive = 1
#define SAFEFETCH_IS_ADAPTIVE(tsk)    tsk->df_prot_struct_head.df_mem_range_allocator.adaptive



#endif

// This code snippet initialises the root pointer of the data structure
#define SAFEFETCH_MEM_RANGE_ROOT_INIT_LL(){                                     \
        SAFEFETCH_MEM_RANGE_TASK_ROOT_INIT_LL(current)                          \
};

#define SAFEFETCH_MEM_RANGE_TASK_ROOT_INIT_LL(tsk){                             \
        INIT_LIST_HEAD(&(SAFEFETCH_HEAD_NODE_LL(tsk)));                         \
        SAFEFETCH_TASK_MEM_RANGE_INIT_FLAG(tsk) = 1;                            \
};

#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_LL(prev_mr, mr)  list_add(&(SAFEFETCH_MR_NODE_LL(mr)), &(SAFEFETCH_MR_NODE_LL(prev_mr)));
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_LL(mr)  list_add(&(SAFEFETCH_MR_NODE_LL(mr)), &(SAFEFETCH_HEAD_NODE_LL(current)));

#define SAFEFETCH_MEM_RANGE_ROOT_INIT_RB(){                                     \
        SAFEFETCH_MEM_RANGE_TASK_ROOT_INIT_RB(current);                         \
};

#define SAFEFETCH_MEM_RANGE_TASK_ROOT_INIT_RB(tsk){                             \
        SAFEFETCH_HEAD_NODE_RB(tsk) = RB_ROOT;                                  \
        SAFEFETCH_TASK_MEM_RANGE_INIT_FLAG(tsk) = 1;                            \
};

#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_RB(prev_mr, mr){                                                                      \
    if(mr->mr_begin < prev_mr->mr_begin){                                                                                       \
        rb_link_node(&SAFEFETCH_MR_NODE_RB(mr), &SAFEFETCH_MR_NODE_RB(prev_mr), &(SAFEFETCH_MR_NODE_RB(prev_mr).rb_left));      \
    } else {                                                                                                                    \
        /* Entry is on the right side of parent */                                                                              \
        rb_link_node(&SAFEFETCH_MR_NODE_RB(mr), &SAFEFETCH_MR_NODE_RB(prev_mr), &(SAFEFETCH_MR_NODE_RB(prev_mr).rb_right));     \
    }                                                                                                                           \
    rb_insert_color(&SAFEFETCH_MR_NODE_RB(mr), &SAFEFETCH_HEAD_NODE_RB(current));                                               \
};

#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_RB(mr){                                              \
   rb_link_node(&SAFEFETCH_MR_NODE_RB(mr), NULL, &(SAFEFETCH_HEAD_NODE_RB(current).rb_node));       \
   rb_insert_color(&SAFEFETCH_MR_NODE_RB(mr), &SAFEFETCH_HEAD_NODE_RB(current));                    \
};


#if !defined(SAFEFETCH_RBTREE_MEM_RANGE) && !defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) && !defined(SAFEFETCH_STATIC_KEYS)
// Default Linked list insertion functions.
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(mr) SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_LL(mr)
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT(prev_mr, mr) SAFEFETCH_MEM_RANGE_STRUCT_INSERT_LL(prev_mr, mr)

#elif defined(SAFEFETCH_RBTREE_MEM_RANGE)
// Rb-tree insertion functions.
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(mr) SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_RB(mr)
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT(prev_mr, mr) SAFEFETCH_MEM_RANGE_STRUCT_INSERT_RB(prev_mr, mr)

#else
// TODO adaptive builds make use of both LL and RB macros.
// The root insertion will always happen in the linked list setup.
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_ADAPTIVE(mr) SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_LL(mr)

#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ADAPTIVE(prev_mr, mr) {         \
   if (likely(!SAFEFETCH_IS_ADAPTIVE(current))) {                          \
       SAFEFETCH_MEM_RANGE_STRUCT_INSERT_LL(prev_mr, mr);                  \
   }                                                                       \
   else {                                                                  \
       SAFEFETCH_MEM_RANGE_STRUCT_INSERT_RB(prev_mr, mr);                  \
   }                                                                       \
}

#endif

#if defined(SAFEFETCH_ADAPTIVE_MEM_RANGE)
/* Dfcacher Adaptive insertion hooks. */
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_ADAPTIVE
#define SAFEFETCH_MEM_RANGE_STRUCT_INSERT SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ADAPTIVE

#elif defined(SAFEFETCH_STATIC_KEYS) // SAFEFETCH_ADAPTIVE_MEM_RANGE
// Really hacky just to escape the incomplete type mess 
static inline void SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(struct mem_range *mr){
   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
      SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_ADAPTIVE(mr);
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_RB(mr);
     } else {
       // The else branch is simply the link list implementation.
       SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT_LL(mr);
     }
   }
}

static inline void SAFEFETCH_MEM_RANGE_STRUCT_INSERT(struct mem_range *prev_mr, struct mem_range *mr){
   // Make this wrapper unlikely so we balance the extra jumps added by
   // the static key implementation to all defense versions.
   IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_adaptive_key){
      SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ADAPTIVE(prev_mr, mr);
   } else {
     // If the rb-tree key is on make this branch unlikely so we incur 
     // one jump if we fall-through here (safefetch_adaptive_key == False)
     // We will force a jump in the link list implementation by forcing
     // the extra adaptive implementation in the link-list as likely.
     IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(safefetch_rbtree_key){
       SAFEFETCH_MEM_RANGE_STRUCT_INSERT_RB(prev_mr, mr);
     } else {
       // The else branch is simply the link list implementation.
       SAFEFETCH_MEM_RANGE_STRUCT_INSERT_LL(prev_mr, mr);
     }
   }
}
#endif

//(struct mem_range *prev_mr, struct mem_range *mr)

#if defined(SAFEFETCH_DEBUG) && (defined(SAFEFETCH_DEBUG_TRACING) || defined(SAFEFETCH_DEBUG_LEAKS) || defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES))

#define safefetch_traced()({                                                               \
    if (in_nmi() || current->df_stats.traced){                                            \
        return 0;                                                                         \
    }                                                                                     \
})
#else
#define safefetch_traced()
#endif

#ifdef DFCACHER_PERF_SETUP

//#define in_irq_ctx() (in_nmi() | in_hardirq() | in_serving_softirq())
#define in_irq_ctx() in_nmi()	

#define safefetch_in_nmi()({                                                               \
    if (unlikely(in_irq_ctx())) {                                                         \
        return 0;                                                                         \
    }                                                                                     \
})

#else

#define safefetch_in_nmi() 

#endif

#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_COLLECT_VULNERABILITIES)
#define macro_dump_vulnerability(X) SAFEFETCH_DEBUG_RUN(5, dump_vulnerability(X));
#else
#define macro_dump_vulnerability(X)
#endif

#define copy_range_loop(user_src, user_val, kern_dst)({                                   \
                                                                                          \
    unsigned long long mr_offset, user_end, new_mr_begin, new_mr_size;                    \
    struct mem_range *new_mr, *mr;                                                        \
                                                                                          \
    safefetch_traced();                                                                    \
    safefetch_in_nmi();                                                                    \
                                                                                          \
    user_end = ((unsigned long long) user_src) + sizeof(__inttype(*user_src)) - 1;        \
                                                                                          \
    mr = search_range((unsigned long long) user_src, user_end);                           \
    if (!mr){                                        \
         new_mr = create_mem_range((unsigned long long) user_src, sizeof(__inttype(*user_src)));    \
         ASSERT_OUT_OF_MEMORY(new_mr);                                                    \
         *((__inttype(*user_src)*)(new_mr->mr_prot_loc)) = (__inttype(*user_src))user_val;\
         /* *(kern_dst) = *((__inttype(*user_src)*)(new_mr->mr_prot_loc)); */             \
         /*list_add(&(new_mr->node), &(SAFEFETCH_HEAD_NODE));*/                           \
         SAFEFETCH_MEM_RANGE_STRUCT_INSERT_ROOT(new_mr);                                  \
         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 4, "[SafeFetch][Info][Task %s][Sys %d] copy_range_loop: Created new region @ at 0x%llx with size(0x%llx bytes)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1 ); \
         return 0;                                                                        \
    }                                                                                     \
                                                                                          \
    if (mr->overlapping == df_range_previous) {                                              \
         new_mr = create_mem_range((unsigned long long) user_src, sizeof(__inttype(*user_src)));             \
         ASSERT_OUT_OF_MEMORY(new_mr);                                                    \
         *((__inttype(*user_src)*)(new_mr->mr_prot_loc)) = (__inttype(*user_src))user_val;\
         /* *(kern_dst) = *((__inttype(*user_src)*)(new_mr->mr_prot_loc)); */             \
         /*list_add(&(new_mr->node), &(mr->node));*/                                      \
         SAFEFETCH_MEM_RANGE_STRUCT_INSERT(mr, new_mr);                                   \
         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 4, "[SafeFetch][Info][Task %s][Sys %d] copy_range_loop: Created new region at 0x%llx with size(0x%llx bytes)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1 ); \
    }                                                                                     \
    else if (mr->overlapping == df_range_encapsulates) {                                  \
         mr_offset = ((unsigned long long) user_src) - mr->mr_begin;                      \
        *(kern_dst) = *((__force __inttype(*user_src)*)(mr->mr_prot_loc + mr_offset));    \
         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY, "[SafeFetch][Info][Task %s][Sys %d] copy_range_loop: Double fetch from region at 0x%llx with size(0x%llx bytes) offset(0x%llx)\n", current->comm, DF_SYSCALL_NR, mr->mr_begin, mr->mr_end - mr->mr_begin + 1, mr_offset);                                                           \
        DF_INC_FETCHES;                                                                   \
        macro_dump_vulnerability(3)                                                       \
    }                                                                                     \
    else if (mr->overlapping == df_range_overlaps){                                       \
         new_mr_begin = ((unsigned long long) user_src) <= mr->mr_begin ? ((unsigned long long) user_src) : mr->mr_begin;               \
         new_mr_size = user_end - new_mr_begin + 1;                                       \
         new_mr = create_mem_range(new_mr_begin, new_mr_size);                            \
         ASSERT_OUT_OF_MEMORY(new_mr);                                                    \
         mr_offset = ((unsigned long long) user_src) - new_mr_begin;                        \
         *((__inttype(*user_src)*)(new_mr->mr_prot_loc + mr_offset))  = (__inttype(*user_src)) user_val;  \
         defragment_mr(new_mr, mr);                                                        \
         *(kern_dst) = *((__force __inttype(*user_src)*)(new_mr->mr_prot_loc + mr_offset)); \
         SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_MEM_RANGE_FUNCTIONALITY + 2, "[SafeFetch][Info][Task %s][Sys %d]  copy_range_loop: Overlapping previous region at 0x%llx with size(0x%llx bytes) offset(0x%llx) copy(0x%llx)\n", current->comm, DF_SYSCALL_NR, new_mr->mr_begin, new_mr->mr_end - new_mr->mr_begin + 1, mr_offset, user_end - (unsigned long long)user_src + 1);                               \
         DF_INC_DEFRAGS;                                                                    \
         macro_dump_vulnerability(4)                                                        \
    }                                                                                       \
    return 0;                                                                               \
})

#endif
