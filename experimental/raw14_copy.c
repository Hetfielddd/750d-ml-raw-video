/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_copy.h"

static enum raw14_status validate(const struct raw14_frame *frame)
{
    size_t expected_pitch;
    if (!frame || !frame->data || !frame->width_pixels || !frame->height_rows)
        return RAW14_INVALID;
    if (frame->bits_per_pixel != 14 || frame->width_pixels % 4)
        return RAW14_UNSUPPORTED;
    /* Divide first: four packed 14-bit pixels occupy seven bytes. */
    if (frame->width_pixels / 4 > SIZE_MAX / 7)
        return RAW14_BOUNDS;
    expected_pitch = (size_t)(frame->width_pixels / 4) * 7;
    if (frame->pitch_bytes != expected_pitch)
        return RAW14_UNSUPPORTED;
    if (frame->height_rows > SIZE_MAX / frame->pitch_bytes ||
        frame->capacity < frame->pitch_bytes * frame->height_rows)
        return RAW14_BOUNDS;
    if ((uintptr_t)frame->data > UINTPTR_MAX - frame->capacity)
        return RAW14_BOUNDS;
    return RAW14_OK;
}

enum raw14_status raw14_copy_rows(struct raw14_engine *engine,
    const struct raw14_frame *dst, uint32_t dst_y,
    const struct raw14_frame *src, uint32_t src_y, uint32_t rows,
    raw14_complete_fn complete, void *complete_ctx)
{
    enum raw14_status status;
    uintptr_t from, to;
    size_t bytes;
    int result;
    if (!engine || !complete || !rows)
        return RAW14_INVALID;
    if (engine->busy)
        return RAW14_BUSY;
    if (!engine->copy)
        return RAW14_NOT_READY;
    status = validate(src);
    if (status != RAW14_OK) return status;
    status = validate(dst);
    if (status != RAW14_OK) return status;
    if (src->width_pixels != dst->width_pixels || (src_y | dst_y | rows) & 1u)
        return RAW14_UNSUPPORTED;
    if (src_y > src->height_rows || rows > src->height_rows - src_y ||
        dst_y > dst->height_rows || rows > dst->height_rows - dst_y)
        return RAW14_BOUNDS;
    bytes = src->pitch_bytes * rows;
    from = (uintptr_t)src->data + src->pitch_bytes * src_y;
    to = (uintptr_t)dst->data + dst->pitch_bytes * dst_y;
    if (from < to + bytes && to < from + bytes)
        return RAW14_OVERLAP;
    engine->busy = 1;
    result = engine->copy(engine->copy_ctx, (void *)to, (const void *)from, bytes);
    if (result != 0) {
        engine->busy = 0;
        return RAW14_BACKEND_FAILED;
    }
    /* Keep busy through completion: callbacks cannot recursively reuse buffers. */
    complete(complete_ctx, bytes);
    engine->busy = 0;
    return RAW14_OK;
}
