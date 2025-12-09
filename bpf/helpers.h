#pragma once

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef memset
#define memset(s, c, n) __builtin_memset((s), (c), (n))
#endif

#ifndef memcpy
#define memcpy(d, s, n) __builtin_memcpy((d), (s), (n))
#endif

#ifndef memmove
#define memmove(d, s, n) __builtin_memmove((d), (s), (n))
#endif

/* __builtin_memcmp() is not yet fully useable unless llvm bug
 * https://llvm.org/bugs/show_bug.cgi?id=26218 gets resolved. Also
 * this one would generate a reloc entry (non-map), otherwise.
 */
// #ifndef memcmp
// #define memcmp(a, b, n) __builtin_memcmp((a), (b), (n))
// #endif
