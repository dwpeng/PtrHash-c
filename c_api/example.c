#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "ptr_hash.h"

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "%s\n", msg);                                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

int main(void) {
    enum { N = 10000 };
    uint64_t *keys = malloc(N * sizeof(*keys));
    CHECK(keys != NULL, "out of memory");

    for (size_t i = 0; i < N; i++) {
        keys[i] = i * 2654435761u;
    }

    ptr_hash_status status;
    ptr_hash_t *ph =
        ptr_hash_build_u64(keys, N, PTR_HASH_VARIANT_DEFAULT, &status);
    if (ph == NULL) {
        fprintf(stderr, "build failed (%d): %s\n", (int)status,
                ptr_hash_last_error());
        free(keys);
        return 1;
    }

    /* Every key must map into [0, N) and the mapping must be injective. */
    unsigned char *seen = calloc(N, 1);
    CHECK(seen != NULL, "out of memory");
    for (size_t i = 0; i < N; i++) {
        uint64_t idx = ptr_hash_index_u64(ph, keys[i]);
        CHECK(idx < ptr_hash_len(ph), "index out of range");
        CHECK(!seen[idx], "duplicate index");
        seen[idx] = 1;
    }

    /* Batched lookups produce the same indices. */
    uint64_t *batch = malloc(N * sizeof(*batch));
    CHECK(batch != NULL, "out of memory");
    CHECK(ptr_hash_index_batch_u64(ph, keys, N, batch) == N, "batch failed");
    for (size_t i = 0; i < N; i++) {
        CHECK(batch[i] == ptr_hash_index_u64(ph, keys[i]), "batch mismatch");
    }

    printf("ptr_hash %s: %zu keys, max index %zu, minimal: %d\n",
           ptr_hash_version(), ptr_hash_len(ph), ptr_hash_max_index(ph),
           ptr_hash_is_minimal(ph));

    free(batch);
    free(seen);
    ptr_hash_free(ph);

    /* Byte-string keys work the same way. */
    const char *words[] = {"alpha", "beta", "gamma", "delta"};
    const size_t lengths[] = {5, 4, 5, 5};
    ptr_hash_t *bph = ptr_hash_build_bytes((const uint8_t *const *)words,
                                           lengths, 4, PTR_HASH_VARIANT_DEFAULT,
                                           &status);
    if (bph == NULL) {
        fprintf(stderr, "byte build failed (%d): %s\n", (int)status,
                ptr_hash_last_error());
        free(keys);
        return 1;
    }
    for (size_t i = 0; i < 4; i++) {
        uint64_t idx = ptr_hash_index_bytes(bph, (const uint8_t *)words[i],
                                            lengths[i]);
        CHECK(idx < ptr_hash_len(bph), "byte index out of range");
    }
    ptr_hash_free(bph);

    free(keys);
    return 0;
}
