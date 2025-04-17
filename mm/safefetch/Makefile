# SPDX-License-Identifier: GPL-2.0
obj-y := page_cache.o mem_range.o region_allocator.o safefetch.o
obj-$(CONFIG_SAFEFETCH_DEBUG)   += safefetch_debug.o
obj-$(CONFIG_SAFEFETCH_STATIC_KEYS)   += safefetch_static_keys.o
CFLAGS_REMOVE_page_cache.o=-Werror
CFLAGS_REMOVE_mem_range.o=-Werror
CFLAGS_REMOVE_region_allocator.o=-Werror
CFLAGS_REMOVE_safefetch.o=-Werror
KASAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n