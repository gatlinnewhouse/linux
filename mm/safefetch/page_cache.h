#ifndef __PAGE_CACHE_H__
#define __PAGE_CACHE_H__

/*
    if (strcmp(current->comm, "bash") == 0) {
        current->df_stats.traced = 1;
        WARN_ON(1);
        current->df_stats.traced = 0;
    }
*/
#include <linux/slab.h>
#include <asm/processor.h>
#include "safefetch_debug.h"
extern struct kmem_cache *df_metadata_cache, *df_storage_cache;

#if 0
#define NUM_METADATA_PAGES 1
#define NUM_BACKING_STORAGE_PAGES 1
#endif

#ifndef METADATA_CACHE_SIZE
#define METADATA_CACHE_SIZE PAGE_SIZE
#else
#warning Using User Supplied Cache for Metadata
#endif
#ifndef STORAGE_CACHE_SIZE
#define STORAGE_CACHE_SIZE PAGE_SIZE
#else
#warning Using User Supplied Cache for Storage
#endif

extern size_t safefetch_metadata_cache_size, safefetch_storage_cache_size; 
extern uint8_t safefetch_slow_path_order;
void df_init_page_alloc_array(void);
void df_resize_page_caches(size_t _metadata_size, size_t _storage_size, uint8_t _order);

#define PAGE_SHIFT 12

enum df_cache_type {
   METADATA, 
   STORAGE    
};

static __always_inline void *df_allocate_metadata_chunk(void){
    return kmem_cache_alloc(df_metadata_cache, GFP_ATOMIC);
}

static __always_inline void *df_allocate_storage_chunk(void){
    return kmem_cache_alloc(df_storage_cache, GFP_ATOMIC);
}

static __always_inline void df_release_metadata_chunk(void *obj){ 
    kmem_cache_free(df_metadata_cache, obj);
    return;
}

static __always_inline void df_release_storage_chunk(void *obj){
    kmem_cache_free(df_storage_cache, obj);
    return;
}

static __always_inline void* df_allocate_page(u8 cache_type){
   switch (cache_type){
          case METADATA:
                      return df_allocate_metadata_chunk();
          case STORAGE:
                      return df_allocate_storage_chunk();
   }
   return 0;
}

static __always_inline void df_free_page(void *obj, u8 cache_type){
   switch (cache_type){
          case METADATA:
                      df_release_metadata_chunk(obj);
                      return;
          case STORAGE:
                      df_release_storage_chunk(obj);
                      return;
   }
   return;
}

static __always_inline void* df_allocate_chunk(struct kmem_cache *cache){
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_LEAKS)
    unsigned long iflags;
    spin_lock_irqsave(&allocations_lock, iflags);
    global_allocations++;
    DF_ALLOCATIONS(current)++;
    spin_unlock_irqrestore(&allocations_lock, iflags);
#endif
    gfp_t flags = unlikely(in_atomic()) ? GFP_ATOMIC : GFP_KERNEL; 
    return kmem_cache_alloc(cache, flags);
}

static __always_inline void df_free_chunk(struct kmem_cache *cache, void *obj){
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_LEAKS)
    unsigned long iflags;
    spin_lock_irqsave(&allocations_lock, iflags);
    global_allocations--;
    DF_ALLOCATIONS(current)--;
    spin_unlock_irqrestore(&allocations_lock, iflags);
#endif
    kmem_cache_free(cache, obj);
}

static  __always_inline void* df_allocate_chunk_slowpath(size_t size){
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_LEAKS)
    unsigned long iflags;
    spin_lock_irqsave(&allocations_lock, iflags);
    global_allocations++;
    DF_ALLOCATIONS(current)++;
    spin_unlock_irqrestore(&allocations_lock, iflags);
#endif
    gfp_t flags = unlikely(in_atomic()) ? GFP_ATOMIC : GFP_KERNEL; 
    return kmalloc(size, flags); 
}

static  __always_inline void df_free_chunk_slowpath(void *obj){
#if defined(SAFEFETCH_DEBUG) && defined(SAFEFETCH_DEBUG_LEAKS)
    unsigned long iflags;
    spin_lock_irqsave(&allocations_lock, iflags);
    global_allocations--;
    DF_ALLOCATIONS(current)--;
    spin_unlock_irqrestore(&allocations_lock, iflags);
#endif
    kfree(obj);
}





#endif
