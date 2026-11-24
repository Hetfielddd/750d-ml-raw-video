/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RAW14_COPY_H
#define RAW14_COPY_H
#include <stddef.h>
#include <stdint.h>

enum raw14_status {
    RAW14_OK = 0, RAW14_INVALID, RAW14_UNSUPPORTED, RAW14_BOUNDS,
    RAW14_OVERLAP, RAW14_BUSY, RAW14_NOT_READY, RAW14_BACKEND_FAILED
};

struct raw14_frame {
    void *data;
    size_t capacity;
    uint32_t width_pixels;
    uint32_t height_rows;
    size_t pitch_bytes;
    unsigned bits_per_pixel;
};

/* Must finish copying before returning; zero means success. Not an async DMA API. */
typedef int (*raw14_copy_fn)(void *ctx, void *dst, const void *src, size_t bytes);
typedef void (*raw14_complete_fn)(void *ctx, size_t bytes);

struct raw14_engine {
    raw14_copy_fn copy;
    void *copy_ctx;
    unsigned busy;
};

/* One caller at a time. busy detects reentrancy; it is not a thread/ISR lock.
 * Caller owns buffer lifetime and handles DMA cache aliases before submission.
 * Full row width only; source/destination vertical offsets preserve Bayer parity.
 * Completion fires exactly once after successful copy; never after rejection/failure.
 */
enum raw14_status raw14_copy_rows(struct raw14_engine *engine,
    const struct raw14_frame *dst, uint32_t dst_y,
    const struct raw14_frame *src, uint32_t src_y, uint32_t rows,
    raw14_complete_fn complete, void *complete_ctx);
#endif
