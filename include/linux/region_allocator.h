#ifndef __REGION_ALLOCATOR_H__
#define __REGION_ALLOCATOR_H__

struct region_allocator {
   struct mem_region *first; // First region in the allocator.
   size_t region_size; // Default Region Allocator bytes
   struct kmem_cache *cache;  // default cache used for allocations.
   struct list_head extra_ranges; // All extra ranges (apart from the first)
   struct list_head free_ranges;  // A list containing only those extra ranges that still have some bytes.
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
   struct list_head buddy_pages;
   unsigned pinning:1;
#endif
   unsigned extended:1; // Does the region based allocator contain more than the preallocated page.
   unsigned initialized:1; // If the region allocator contains at least the first page.
};

#define BYTE_GRANULARITY(allocator) allocator->region_size

#define ASSERT_ALLOCATION_FAILURE(region, message) { \
  if (unlikely(!region)) {                           \
         printk(KERN_EMERG message);                 \
         return 0;                                   \
  }                                                  \
}


struct mem_region {
    unsigned long long ptr; // ptr to the next free byte in the region.
    size_t remaining;
    struct list_head extra_ranges; // linked list of all allocated ranges for a range allocator (except the first).
    struct list_head free_ranges; // linked list of all free ranges.
#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
    size_t size;
#endif
    unsigned is_cached:1;
};

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
struct mem_pin {
    void *ptr;
#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
    size_t size;
#endif
    struct list_head pin_link;
};
#endif

#define REGION_PTR(region) region->ptr
#define REGION_REMAINING_BYTES(region) region->remaining
#define REGION_RANGES(region) &(region->extra_ranges)
#define REGION_FREELIST(region) &(region->free_ranges)

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
#define PIN_LINK(pin) &(pin->pin_link)
#endif

#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
#define REGION_SIZE(region) region->size
#endif

#define REGION_CHECKS
#define ADAPTIVE_REGION_ALLOCATOR
//#define REGION_CHECKS_EXTENDED
#define REGION_ALLOCATOR_LARGER_ORDER_ALLOCATIONS

struct range_allocator {
#if !defined(SAFEFETCH_RBTREE_MEM_RANGE) && !defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) && !defined(SAFEFETCH_STATIC_KEYS)
   struct list_head node;
#elif defined(SAFEFETCH_RBTREE_MEM_RANGE)
   struct rb_root node;
#else
   union {
       struct list_head ll_node;
       struct rb_root rb_node;
    };
#endif
#if defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) || defined(SAFEFETCH_STATIC_KEYS)
#ifndef SAFEFETCH_USE_SHIFT_COUNTER
   uint8_t ncopies;
#else
   uint64_t ncopies;
#endif
   unsigned adaptive:1;
#endif 
   unsigned initialized:1;

};

//#define SAFEFETCH_LINKEDLIST_MEM_RANGE
// Enum that indicates the current state of a memory range structure
enum overlapping_types {
    // We returned the previous range after which we should add our cfu range.
    df_range_previous,
    // Mem range struct fully contains the copy from user
    df_range_encapsulates,
    // Mem range overlaps the copy from user
    df_range_overlaps
};


/* The protection memory range structure.
 * For every copy_from_user/get_user structure there will be a memory range created
 * These structs will be chained as a linked list for every syscall within every task
 * This structure contains:
 * -- the user space memory boundaries that is being copied to kernel space
 * -- Pointer to the protected memory region for that specific user space memory area
 * -- The current state of this memory range
 * -- Pointer to the next memory range structure in the linked list
 */
struct mem_range {
#if  !defined(SAFEFETCH_RBTREE_MEM_RANGE) && !defined(SAFEFETCH_ADAPTIVE_MEM_RANGE) && !defined(SAFEFETCH_STATIC_KEYS)
    struct list_head node;    
#elif defined(SAFEFETCH_RBTREE_MEM_RANGE)
    struct rb_node node;
#else
    union {
       struct list_head ll_node;
       struct rb_node rb_node;
    };
#endif
    unsigned long long mr_begin;
    unsigned long long mr_end;
    void *mr_prot_loc;
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_PIN_BUDDY_PAGES) && defined(SAFEFETCH_DEBUG_PINNING)
    void *mr_check_loc;
#endif
    unsigned overlapping:2;
#if defined(SAFEFETCH_PIN_BUDDY_PAGES)
    unsigned is_trap:1;
#endif
};


#define REGION_LOW_WATERMARK sizeof(struct mem_range) 


bool init_region_allocator(struct region_allocator *allocator, u8 cache_type);
void shrink_region(struct region_allocator *allocator);
void destroy_region(struct region_allocator *allocator);
void* allocate_from_region(struct region_allocator *allocator, size_t alloc_size);

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
void* pin_compound_pages(struct region_allocator *allocator, void *kern_loc);
#endif

#ifdef SAFEFETCH_DEBUG
void dump_region_stats(int *mregions, int *dregions, int *dkmalloc, size_t *dkmallocmax);
#endif

#define DF_CUR_METADATA_REGION_ALLOCATOR (&(current->df_prot_struct_head.df_metadata_allocator))
#define DF_CUR_STORAGE_REGION_ALLOCATOR  (&(current->df_prot_struct_head.df_storage_allocator))
#define DF_TASK_METADATA_REGION_ALLOCATOR(tsk) (&(tsk->df_prot_struct_head.df_metadata_allocator))
#define DF_TASK_STORAGE_REGION_ALLOCATOR(tsk)  (&(tsk->df_prot_struct_head.df_storage_allocator))
#define DF_CUR_MEM_RANGE_ALLOCATOR  (&(current->df_prot_struct_head.df_mem_range_allocator))

#ifdef SAFEFETCH_MEASURE_DEFENSE
#define DF_CUR_MEASURE_STRUCT  (&(current->df_prot_struct_head.df_measures))
#define DF_TASK_MEASURE_STRUCT(tsk)  (&(tsk->df_prot_struct_head.df_measures))
#endif


#ifdef DFCACHER_INLINE_FUNCTIONS
// Called on syscall exit to remove extra regions except one.
#define reset_regions(){                                      \
    if (SAFEFETCH_MEM_RANGE_INIT_FLAG) {                      \
       shrink_region(DF_CUR_STORAGE_REGION_ALLOCATOR);        \
       shrink_region(DF_CUR_METADATA_REGION_ALLOCATOR);       \
       SAFEFETCH_RESET_MEM_RANGE();                           \
    }                                                         \
}
// Called on process exit to destroy regions.
#define destroy_regions(){                                 \
    destroy_region(DF_CUR_STORAGE_REGION_ALLOCATOR);       \
    destroy_region(DF_CUR_METADATA_REGION_ALLOCATOR);      \
    SAFEFETCH_RESET_MEM_RANGE();                           \
}
// Called by DFCACHE's memory range subsistem to initialize regions used to allocate memory ranges                                              
#define initialize_regions() init_region_allocator(DF_CUR_METADATA_REGION_ALLOCATOR, METADATA) &&  \
                             init_region_allocator(DF_CUR_STORAGE_REGION_ALLOCATOR, STORAGE)

#else
noinline void reset_regions(void);
noinline void destroy_regions(void);                                             
noinline bool initialize_regions(void);
#endif

#endif
