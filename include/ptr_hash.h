/*
 * ptr_hash.h - C API for PtrHash, a minimal perfect hash function.
 *
 * Link against libptr_hash (cdylib) built with `cargo build --release`.
 *
 * Basic usage:
 *
 *     ptr_hash_status status;
 *     ptr_hash_t *ph = ptr_hash_build_u64(keys, n, PTR_HASH_VARIANT_DEFAULT, &status);
 *     if (!ph) {
 *         fprintf(stderr, "%s\n", ptr_hash_last_error());
 *         return 1;
 *     }
 *     uint64_t idx = ptr_hash_index_u64(ph, key);
 *     ptr_hash_free(ph);
 *
 * Handles are immutable after construction and may be queried concurrently
 * from multiple threads. Build functions are fallible and return NULL on error;
 * query functions return PTR_HASH_INDEX_INVALID for invalid input.
 */

#ifndef PTR_HASH_H
#define PTR_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(PTR_HASH_SHARED)
#ifdef PTR_HASH_BUILDING
#define PTR_HASH_API __declspec(dllexport)
#else
#define PTR_HASH_API __declspec(dllimport)
#endif
#else
#define PTR_HASH_API
#endif

/* Opaque handle. */
typedef struct ptr_hash_t ptr_hash_t;

/* Returned by query functions when the handle or arguments are invalid. */
#define PTR_HASH_INDEX_INVALID UINT64_MAX

/* Returned by batch query functions on error. */
#define PTR_HASH_BATCH_ERROR ((size_t)-1)

/* Status code returned by fallible functions. */
typedef enum ptr_hash_status {
    PTR_HASH_OK = 0,
    PTR_HASH_ERR_INVALID_ARGUMENT = 1,
    PTR_HASH_ERR_CONSTRUCTION_FAILED = 2,
    PTR_HASH_ERR_PANIC = 3
} ptr_hash_status;

/* Construction variants. */
typedef enum ptr_hash_variant {
    /* Minimal PHF returning values in [0, n). 3.0 bits/key. */
    PTR_HASH_VARIANT_DEFAULT = 0,
    /* Non-minimal PHF returning values in [0, max_index). 2.67 bits/key. */
    PTR_HASH_VARIANT_FAST = 1,
    /* Minimal PHF optimized for space and parallel construction. 2.15 bits/key. */
    PTR_HASH_VARIANT_COMPACT = 2
} ptr_hash_variant;

/* Library version, e.g. "2.1.3". */
PTR_HASH_API const char *ptr_hash_version(void);

/*
 * Error message for the most recent failed call on the calling thread.
 * The pointer is valid until the next failing call on the same thread.
 */
PTR_HASH_API const char *ptr_hash_last_error(void);

/*
 * Build a PHF over `n` uint64_t keys.
 *
 * `keys` may be NULL only when `n == 0`. The keys need not outlive the call.
 * Returns NULL on failure and stores the reason in `*status` when `status` is
 * non-NULL.
 */
PTR_HASH_API ptr_hash_t *ptr_hash_build_u64(const uint64_t *keys, size_t n,
                                            ptr_hash_variant variant,
                                            ptr_hash_status *status);

/*
 * Build a PHF over `n` byte-string keys.
 *
 * `keys[i]` points to `lengths[i]` bytes. Both arrays may be NULL only when
 * `n == 0`. The key bytes need not outlive the call.
 * Returns NULL on failure and stores the reason in `*status` when `status` is
 * non-NULL.
 */
PTR_HASH_API ptr_hash_t *ptr_hash_build_bytes(const uint8_t *const *keys,
                                              const size_t *lengths, size_t n,
                                              ptr_hash_variant variant,
                                              ptr_hash_status *status);

/* Free a handle. NULL is ignored. */
PTR_HASH_API void ptr_hash_free(ptr_hash_t *handle);

/* Number of keys in the PHF. Returns 0 for NULL. */
PTR_HASH_API size_t ptr_hash_len(const ptr_hash_t *handle);

/*
 * Upper bound on query results. Equals ptr_hash_len() for minimal variants and
 * is roughly 1.01 * ptr_hash_len() for the fast variant.
 */
PTR_HASH_API size_t ptr_hash_max_index(const ptr_hash_t *handle);

/* Returns 1 if the handle is a minimal PHF, 0 otherwise (including NULL). */
PTR_HASH_API int ptr_hash_is_minimal(const ptr_hash_t *handle);

/*
 * Look up one uint64_t key.
 * Returns PTR_HASH_INDEX_INVALID if the handle is NULL or holds byte-string keys.
 */
PTR_HASH_API uint64_t ptr_hash_index_u64(const ptr_hash_t *handle, uint64_t key);

/*
 * Look up one byte-string key.
 * Returns PTR_HASH_INDEX_INVALID if the handle is NULL, holds uint64_t keys, or
 * `key` is NULL with `len > 0`.
 */
PTR_HASH_API uint64_t ptr_hash_index_bytes(const ptr_hash_t *handle,
                                           const uint8_t *key, size_t len);

/*
 * Look up `n` uint64_t keys, writing results to `out`.
 * Returns `n` on success or PTR_HASH_BATCH_ERROR on error.
 * `keys` and `out` must each point to at least `n` elements.
 */
PTR_HASH_API size_t ptr_hash_index_batch_u64(const ptr_hash_t *handle,
                                             const uint64_t *keys, size_t n,
                                             uint64_t *out);

/*
 * Look up `n` byte-string keys, writing results to `out`.
 * Returns `n` on success or PTR_HASH_BATCH_ERROR on error.
 * `keys`, `lengths`, and `out` must each point to at least `n` elements.
 */
PTR_HASH_API size_t ptr_hash_index_batch_bytes(const ptr_hash_t *handle,
                                               const uint8_t *const *keys,
                                               const size_t *lengths, size_t n,
                                               uint64_t *out);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PTR_HASH_H */
