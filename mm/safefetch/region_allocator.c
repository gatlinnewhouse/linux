//#include <linux/region_allocator.h>
#include "page_cache.h"
#include <linux/mem_range.h>
#include "safefetch_debug.h"

#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
#warning "SafeFetch: Measuring memory consumption"
void dump_mem_consumption(struct task_struct *tsk, unsigned long long *total_metadata_region_size, 
                                             unsigned long long *total_data_region_size, 
                                             unsigned long long *total_pin_size){
    struct region_allocator *allocator;
    struct list_head *item;
    struct mem_region *next_region;
    struct mem_pin *next_pin;

    unsigned long long total_size = 0;
  
    allocator = DF_TASK_METADATA_REGION_ALLOCATOR(tsk);
    if (!(allocator->initialized))
         goto mconsume_skip;

    total_size += REGION_SIZE(allocator->first);
    
    if (!(allocator->extended)){
         goto mconsume_skip;
    }
    list_for_each(item, &(allocator->extra_ranges)) {
	 next_region = list_entry(item, struct mem_region, extra_ranges);
         total_size += REGION_SIZE(next_region);
    }

mconsume_skip:

    *total_metadata_region_size = total_size;
    total_size = 0;

    allocator = DF_TASK_STORAGE_REGION_ALLOCATOR(tsk);

    if (!(allocator->initialized))
         goto dconsume_skip;

    total_size += REGION_SIZE(allocator->first);

    if (!(allocator->extended)){
         goto dconsume_skip;
    }
    list_for_each(item, &(allocator->extra_ranges)) {
	 next_region = list_entry(item, struct mem_region, extra_ranges);
         total_size += REGION_SIZE(next_region);
    } 

dconsume_skip:

    *total_data_region_size = total_size;
    total_size = 0;

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
    if (allocator->pinning) {
      list_for_each(item, &(allocator->buddy_pages)) {
         next_pin = list_entry(item, struct mem_pin, pin_link);
         total_size += REGION_SIZE(next_pin);
      }
    }
#endif

    *total_pin_size = total_size;
}

EXPORT_SYMBOL(dump_mem_consumption);
#endif

#ifdef SAFEFETCH_DEBUG
void dump_region_stats(int *mregions, int *dregions, int *dkmalloc, size_t *dkmallocmax){
    struct region_allocator *allocator;
    struct list_head *item;
    struct mem_region *next_region;
    int regions, kmallocs;
    size_t kmallocmax;
  
    allocator = DF_CUR_METADATA_REGION_ALLOCATOR;
    regions = 0;
    if (!(allocator->extended)){
         goto mskip;
    }
    list_for_each(item, &(allocator->extra_ranges)) {
	 next_region = list_entry(item, struct mem_region, extra_ranges);
         regions++;

    }

mskip:

    *mregions = regions;

    allocator = DF_CUR_STORAGE_REGION_ALLOCATOR;
    regions = 0;
    kmallocs = 0; 
    kmallocmax = 0;  

    if (!(allocator->extended)){
         goto dskip;
    }
    list_for_each(item, &(allocator->extra_ranges)) {
	 next_region = list_entry(item, struct mem_region, extra_ranges);
         regions++;
         if (!(next_region->is_cached)){
            kmallocs++;
            if (REGION_REMAINING_BYTES(next_region) > kmallocmax){
                kmallocmax = REGION_REMAINING_BYTES(next_region);
            }
         }

    } 

dskip:

    *dregions = regions;
    *dkmalloc = kmallocs;
    *dkmallocmax = kmallocmax;
}

#endif

#ifndef DFCACHER_INLINE_FUNCTIONS
#warning "Region functions not inlined"
// TODO Find a smarter way to do all of these includes (looks sloppy now)
// Called on syscall exit to remove extra regions except one.
noinline void reset_regions(void) {    
  if (SAFEFETCH_MEM_RANGE_INIT_FLAG) {  
    /* Reset the range first if by some unfortunate incident 
       we get rescheduled by an interrupt here (that uses current)
       as long as we mark the mem_range as uninitialized and 
       as long as the interrupt uses less than the first region
       there should be no concurency issue and after the interrupt
       is over we can cleanup any extra range. In case the interrupt
       happens prior to the flag being set than the interrupt just
       adds to the extended regions which we will clean after the
       interrupt ends.
    */
    SAFEFETCH_RESET_MEM_RANGE();                         
    shrink_region(DF_CUR_STORAGE_REGION_ALLOCATOR);        
    shrink_region(DF_CUR_METADATA_REGION_ALLOCATOR);
#ifdef SAFEFETCH_DEBUG
    WARN_ON(SAFEFETCH_MEM_RANGE_INIT_FLAG);
#endif
  }   
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_TRACING)
  #warning "We have tracing enabled with debugging."
  // Check all accesses from interrupt context
  current->df_stats.check_next_access = 1;
#endif  

}
// Called on process exit to destroy regions.
noinline void destroy_regions(void) { 
    SAFEFETCH_RESET_MEM_RANGE();                              
    destroy_region(DF_CUR_STORAGE_REGION_ALLOCATOR);       
    destroy_region(DF_CUR_METADATA_REGION_ALLOCATOR); 
}
// Called by DFCACHE's memory range subsistem to initialize regions used to allocate memory ranges                                              
noinline bool initialize_regions(void){                                            
    return init_region_allocator(DF_CUR_METADATA_REGION_ALLOCATOR, METADATA) && init_region_allocator(DF_CUR_STORAGE_REGION_ALLOCATOR, STORAGE);     
}
#else
#warning "Region functions inlined"
#endif

// Return: The pointer to the beginning of the allocated page
static struct mem_region* create_new_region(struct region_allocator* allocator, size_t alloc_size){
    struct mem_region *new_region;
#ifdef REGION_ALLOCATOR_LARGER_ORDER_ALLOCATIONS
    size_t to_allocate;
#endif
    // Take into consideration that the newly allocated region must also contain a header.
    size_t nbytes = (alloc_size + sizeof(struct mem_region));
    // We can allocate from our special allocator.
    if(nbytes <= BYTE_GRANULARITY(allocator)){   
        new_region = (struct mem_region *) df_allocate_chunk(allocator->cache);
        ASSERT_ALLOCATION_FAILURE(new_region, "create_new_region: Problem when allocating new region in region allocator!");

        // Also allocate the new region but only fixup the pointer after we return it to the caller.
        REGION_REMAINING_BYTES(new_region) = BYTE_GRANULARITY(allocator) - nbytes;
        // If region is cached then we must dealocate it through the slab cache else kfree it.
        new_region->is_cached = 1;
#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
        REGION_SIZE(new_region) = BYTE_GRANULARITY(allocator);
#endif

    } else {
#ifdef REGION_ALLOCATOR_LARGER_ORDER_ALLOCATIONS
        #warning "We are using higher order allocations"
        to_allocate = ((nbytes >> PAGE_SHIFT) + 1);
        if (to_allocate != 1) {
           to_allocate <<= (safefetch_slow_path_order + PAGE_SHIFT);
        } 
        else {
           // In case we have less than PAGE_SIZE bytes allocate only one page.
           to_allocate <<= PAGE_SHIFT;
        }
        new_region = (struct mem_region *) df_allocate_chunk_slowpath(to_allocate);
#else
        new_region = (struct mem_region *) df_allocate_chunk_slowpath(nbytes);
#endif
        ASSERT_ALLOCATION_FAILURE(new_region, "create_new_region: Problem when allocating new region in region allocator!");
        // No point in initializing the remaining bytes for this region. It's always 0.
        new_region->is_cached = 0;
#ifdef REGION_ALLOCATOR_LARGER_ORDER_ALLOCATIONS
        // For debugging purposes keep track of how large of an allocation we had in case of kmalloc chunks
        REGION_REMAINING_BYTES(new_region) = to_allocate - nbytes;
#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
        REGION_SIZE(new_region) = to_allocate;
#endif
#endif


        SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_REGION_FUNCTIONALITY, "[SafeFetch][Info][Task %s][Sys %d] create_new_region: Serving allocation from kmalloc.", current->comm, DF_SYSCALL_NR);
    }

    REGION_PTR(new_region) = (unsigned long long)(new_region + 1);
    
    return new_region;
    
}

/* Initialize allocator based on an underlying page cache */
bool init_region_allocator(struct region_allocator *allocator, u8 cache_type){
    struct mem_region *first_region = allocator->first;

    if (likely(allocator->initialized)){
       // Expect at least a couple of syscalls in the proces so it's most likely that the allocator
       // is already intialized so reset the base of the region. 
       REGION_REMAINING_BYTES(first_region) = BYTE_GRANULARITY(allocator) - sizeof(struct mem_region); 
       REGION_PTR(first_region) = (unsigned long long)(first_region + 1);

       // No need to mark the allocator as not extended. We do this once we shrink the region now (as it seems necesary).
       //allocator->extended = 0;
       return true;       
    }

    switch(cache_type){
         case METADATA:
                        BYTE_GRANULARITY(allocator) = safefetch_metadata_cache_size;
                        allocator->cache = df_metadata_cache;
                        break;
         case STORAGE:
                        BYTE_GRANULARITY(allocator) = safefetch_storage_cache_size;
                        allocator->cache = df_storage_cache;
                        break;
    }

    /* Create first range  */
    first_region = (struct mem_region *) df_allocate_chunk(allocator->cache);

    if (!first_region){
       printk(KERN_EMERG "init_region_allocator: Problem when allocating new region in region allocator!");
       allocator->first = 0;
       return false;
    }

    REGION_REMAINING_BYTES(first_region) = BYTE_GRANULARITY(allocator) - sizeof(struct mem_region);
    REGION_PTR(first_region) = (unsigned long long)(first_region + 1);

#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
    REGION_SIZE(first_region) = BYTE_GRANULARITY(allocator);
#endif

    /* Initialize allocator */
    allocator->first = first_region;
    /* Allocator has only the first region */
    allocator->extended = 0; 
    /* Now allocator is initialized */
    allocator->initialized = 1;
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
    allocator->pinning = 0;
#endif

    return true;
}

static __always_inline void __shrink_region(struct region_allocator *allocator){
    struct list_head *item, *next;
    struct mem_region *next_region;
#ifdef SAFEFETCH_PIN_BUDDY_PAGES
    void *frag;
#endif

#ifdef SAFEFETCH_DEBUG
    int num_freed_regions = 0;
#endif

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
    if (unlikely(allocator->pinning)) {
      list_for_each(item, &(allocator->buddy_pages)) {
         // Decrement ref on each page and remove the page if necessary.
#if 0
	 page = (void *) (list_entry(item, struct mem_pin, pin_link)->ptr);
         if (put_page_testzero(page)) {
            free_the_page(page, compound_order(page));
         }
#endif
         frag =  (list_entry(item, struct mem_pin, pin_link)->ptr);
         page_frag_free(frag);
      }
      allocator->pinning = 0;
   }
#endif

    if (likely(!(allocator->extended))) {
        // TODO Add slowpath check (might be useful for debugging fork)
        return;
    }

    /* Remove all extra regions allocated for the syscall. Must be
       list_for_each_safe else we may release regions and at the same
       time some will grab it and modify our linked lists. */
    list_for_each_safe(item, next, &(allocator->extra_ranges)) {
	 next_region = list_entry(item, struct mem_region, extra_ranges);
         if (next_region->is_cached){
            df_free_chunk(allocator->cache, (void *)next_region);
         } else {
            df_free_chunk_slowpath(next_region);
         }
#ifdef SAFEFETCH_DEBUG
         num_freed_regions++;
#endif
    }
    // Don't free linked list as we're simply going to reinitialize the list once another
    // task grabs those pages. However mark the allocator as not extended anymore.
    // If the process receives a signal in the middle of handling a syscall after the 
    // region is shrinked we might attempt to shrink the region again.
    allocator->extended = 0;

    SAFEFETCH_DEBUG_ASSERT(SAFEFETCH_LOG_INFO_REGION_FUNCTIONALITY, (num_freed_regions == 0), "[SafeFetch][Info][Task %s][Sys %d] shrink_region: Removed %d regions.", current->comm, DF_SYSCALL_NR, num_freed_regions);
    return;
    
}

void shrink_region(struct region_allocator *allocator){

#if 0
    // Now if any of the two allocators are not initialized the mem_range_init flag
    // is not set to 1. 
    // TODO once we guarded shrink_region and destroy_region with the mem_range
    // initialization flag the test for allocator->initialized only becomes relevant
    // in case the initialization failed via kmalloc. There must be a faster way
    // to do this. Also, now this condition became unlikely given that this code will
    // mostly execute ONLY if the allocator is initialized (under the guard of the
    // mem_range flag).
    if (unlikely(!(allocator->initialized))){
#ifdef REGION_CHECKS_EXTENDED
        printk("[Task %s] [K %llx] shrink_region: Error allocator is not initialized\n", current->comm, current->flags & PF_KTHREAD);
#endif
        return;
    }
#endif
    __shrink_region(allocator);
}

void destroy_region(struct region_allocator *allocator){

     /* We assume that the process will call at least one copy from user so 
        it has at least the first region initialized. */
     if (unlikely(!(allocator->initialized))){
#ifdef REGION_CHECKS_EXTENDED
        printk("[Task %s] [K %llx] destroy_region: Error allocator is not initialized\n", current->comm, current->flags & PF_KTHREAD);
#endif
        return;
     }

#ifdef REGION_CHECKS_EXTENDED
     if (!(allocator->first)){
        printk("[Task %s] [K %llx] destroy_region: Error default region is missing\n", current->comm, current->flags & PF_KTHREAD);
        return;
     }
#endif
    // Shrink region if appropriate.
    __shrink_region(allocator);

    // Remove our first chunk and release everything (We need to call this last with
    // page pinning because page pinning might allocate page pins in the first region)
    df_free_chunk(allocator->cache, (void*)allocator->first);

    // Mark allocator as uninitialized.
    allocator->initialized = 0;
}


void* allocate_from_region(struct region_allocator *allocator, size_t alloc_size){
    unsigned long long ptr;
    struct list_head *item;
    struct mem_region *next_region = allocator->first;
#ifdef ADAPTIVE_REGION_ALLOCATOR
    struct mem_region *to_flip;
#endif


    if (unlikely(!(allocator->initialized))){
#ifdef REGION_CHECKS_EXTENDED
       printk("[Task %s] [K %d] allocate_from_region: Error ALLOCATOR not initialized\n", current->comm, current->flags & PF_KTHREAD );
#endif
       return 0;
    }

#ifdef REGION_CHECKS_EXTENDED
    if (!next_region){
       printk("[Task %s] [K %d] allocate_from_region: Error DEFAULT region is missing\n", current->comm, current->flags & PF_KTHREAD);
       return 0;
    }
#endif

    // Fast path allocates from the first region.
    if (alloc_size <= REGION_REMAINING_BYTES(next_region)){
       ptr = REGION_PTR(next_region);
       REGION_REMAINING_BYTES(next_region) = REGION_REMAINING_BYTES(next_region) - alloc_size;
       REGION_PTR(next_region) = ptr + alloc_size;
       return (void *)ptr;
    }

    // If allocator was not extended then prepare to extend the allocator.
    if (!(allocator->extended)) {
       INIT_LIST_HEAD(&(allocator->extra_ranges)); 
       INIT_LIST_HEAD(&(allocator->free_ranges));
       allocator->extended = 1;  
       SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_REGION_FUNCTIONALITY, "[SafeFetch][Info][Task %s][Sys %d] allocate_from_region: Extending allocator.", current->comm, DF_SYSCALL_NR);
       goto slow_path;    
    }

    list_for_each(item, &(allocator->free_ranges)) {
	 next_region = list_entry(item, struct mem_region, free_ranges);
         /* We found a range that can fit our needs */
	 if (alloc_size <= REGION_REMAINING_BYTES(next_region)){
             ptr = REGION_PTR(next_region);
             REGION_REMAINING_BYTES(next_region) = REGION_REMAINING_BYTES(next_region) - alloc_size;
             REGION_PTR(next_region) = ptr + alloc_size;
             
             /* If we're bellow the watermark remove the region from the list of free regions */
             if (REGION_REMAINING_BYTES(next_region) < REGION_LOW_WATERMARK)
                list_del(item);

             SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_REGION_FUNCTIONALITY, "[SafeFetch][Info][Task %s][Sys %d] allocate_from_region: Serving allocation from freelist.", current->comm, DF_SYSCALL_NR);
           
             return (void *)ptr;
         }
    }

    /* If we did not find any suitable region we must create a new region and insert it in  */
slow_path:

    SAFEFETCH_DEBUG_LOG(SAFEFETCH_LOG_INFO_REGION_FUNCTIONALITY, "[SafeFetch][Info][Task %s][Sys %d] allocate_from_region: Executing slow_path.", current->comm, DF_SYSCALL_NR);

    next_region = create_new_region(allocator, alloc_size);

    if (!next_region){
        return 0;
    } 

    ptr = REGION_PTR(next_region);

#ifndef REGION_ALLOCATOR_LARGER_ORDER_ALLOCATIONS
    // Only add cached regions to the list of free ranges
    if (next_region->is_cached){
        // Setup the next region pointer
        REGION_PTR(next_region) = ptr + alloc_size; 

#ifdef ADAPTIVE_REGION_ALLOCATOR
        // In case we have more  bytes in the next allocated region then flip the main region
        // to avoid scenarios where large allocations are served from the main page and region
        // allocation goes to slow path too often.
        if (REGION_REMAINING_BYTES(next_region) > REGION_REMAINING_BYTES(allocator->first)){
           to_flip = allocator->first;
           allocator->first = next_region;
           next_region = to_flip;
        }
        
#endif  // As an optimization do not add the new region in the free region list if
        // it's bellow a low watermark.
        if (REGION_REMAINING_BYTES(next_region) >= REGION_LOW_WATERMARK)
             list_add(REGION_FREELIST(next_region), &(allocator->free_ranges));

    } 
#else // REGION_ALLOCATOR_LARGER_ORDER_ALLOCATIONS 
    REGION_PTR(next_region) = ptr + alloc_size; 

#ifdef ADAPTIVE_REGION_ALLOCATOR
    // In case we have more  bytes in the next allocated region then flip the main region
    // to avoid scenarios where large allocations are served from the main page and region
    // allocation goes to slow path too often.
    if (next_region->is_cached && (REGION_REMAINING_BYTES(next_region) > REGION_REMAINING_BYTES(allocator->first))){
        to_flip = allocator->first;
        allocator->first = next_region;
        next_region = to_flip;
    }
        
#endif 
    if (REGION_REMAINING_BYTES(next_region) >= REGION_LOW_WATERMARK)
        list_add(REGION_FREELIST(next_region), &(allocator->free_ranges));
   
#endif

    list_add(REGION_RANGES(next_region), &(allocator->extra_ranges));

    return (void *)ptr;
       
}

#ifdef SAFEFETCH_PIN_BUDDY_PAGES
#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
void* pin_compound_pages(struct region_allocator *allocator, void *kern_loc, unsigned long usize){
#else
void* pin_compound_pages(struct region_allocator *allocator, void *kern_loc){
#endif
    struct mem_pin *pin;
    struct page *page = virt_to_head_page(kern_loc);
    // Increase page refcount 
    if (!get_page_unless_zero(page))
       return NULL;

    // Use our advanced region allocator to keep track that we pinned this page.
    pin = (struct mem_pin*) allocate_from_region(allocator, sizeof(struct mem_pin));
    // Either the head page or the virtual address of this page would work.
    pin->ptr = (void*) kern_loc;

    if (!allocator->pinning){
       INIT_LIST_HEAD(&(allocator->buddy_pages)); 
       allocator->pinning = 1;
    }
   
    list_add(PIN_LINK(pin), &(allocator->buddy_pages));

#ifdef SAFEFETCH_MEASURE_MEMORY_CONSUMPTION
    REGION_SIZE(pin) = usize;
#endif
         

    return kern_loc;
}
#endif


