#ifndef __SAFEFETCH_STATIC_KEYS_H__
#define __SAFEFETCH_STATIC_KEYS_H__

#ifdef SAFEFETCH_STATIC_KEYS
DECLARE_STATIC_KEY_FALSE(safefetch_copy_from_user_key);
DECLARE_STATIC_KEY_FALSE(safefetch_hooks_key);
DECLARE_STATIC_KEY_FALSE(safefetch_adaptive_key);
DECLARE_STATIC_KEY_FALSE(safefetch_rbtree_key);

#define IF_SAFEFETCH_STATIC_BRANCH_LIKELY_WRAPPER(key)   if (static_branch_likely(&key))
#define IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(key) if (static_branch_unlikely(&key))

void init_safefetch_skey_layer(void);
 
#else /* SAFEFETCH_STATIC_KEYS */

#define IF_SAFEFETCH_STATIC_BRANCH_LIKELY_WRAPPER(key)
#define IF_SAFEFETCH_STATIC_BRANCH_UNLIKELY_WRAPPER(key)
#endif

#endif
