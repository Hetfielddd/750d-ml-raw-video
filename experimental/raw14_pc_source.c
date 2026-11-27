/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_pc_source.h"

static int begin(void *context)
{
    struct raw14_pc_source *source = context;
    if (source->requested)
        return -1;
    source->requested = 1;
    return 0;
}

static int end(void *context)
{
    struct raw14_pc_source *source = context;
    unsigned i;
    if (source->leased_id)
        return -1;
    for (i = 0; i < RAW14_PC_BUFFERS; ++i)
        source->slots[i].ready_id = 0;
    source->pending_id = 0;
    source->requested = 0;
    return 0;
}

static int acquire(void *context, struct raw14_source_view *view)
{
    struct raw14_pc_source *source = context;
    const struct raw14_pc_slot *oldest = 0;
    unsigned i;
    if (!source->requested || source->leased_id)
        return -1;
    for (i = 0; i < RAW14_PC_BUFFERS; ++i) {
        const struct raw14_pc_slot *slot = &source->slots[i];
        if (slot->ready_id && (!oldest || slot->ready_id < oldest->ready_id))
            oldest = slot;
    }
    if (!oldest)
        return 1;
    source->leased_id = oldest->ready_id;
    *view = (struct raw14_source_view){oldest->frame, oldest->ready_id,
                                      oldest->timestamp_us, source->leased_id};
    return 0;
}

static int release(void *context, uint64_t cookie)
{
    struct raw14_pc_source *source = context;
    unsigned i;
    if (!cookie || source->leased_id != cookie)
        return -1;
    for (i = 0; i < RAW14_PC_BUFFERS; ++i) {
        if (source->slots[i].ready_id == cookie) {
            source->slots[i].ready_id = 0;
            source->leased_id = 0;
            return 0;
        }
    }
    return -1;
}

enum raw14_status raw14_pc_source_init(struct raw14_pc_source *source,
    const struct raw14_frame frames[RAW14_PC_BUFFERS], struct raw14_source_ops *ops)
{
    unsigned i;
    size_t bytes;
    uintptr_t a, b;
    if (!source || !frames || !ops)
        return RAW14_INVALID;
    for (i = 0; i < RAW14_PC_BUFFERS; ++i) {
        enum raw14_status status = raw14_validate_frame(&frames[i]);
        if (status != RAW14_OK)
            return status;
    }
    if (frames[0].width_pixels != frames[1].width_pixels ||
        frames[0].height_rows != frames[1].height_rows)
        return RAW14_INVALID;
    bytes = frames[0].pitch_bytes * frames[0].height_rows;
    a = (uintptr_t)frames[0].data;
    b = (uintptr_t)frames[1].data;
    if (a < b + bytes && b < a + bytes)
        return RAW14_OVERLAP;
    for (i = 0; i < RAW14_PC_BUFFERS; ++i)
        source->slots[i] = (struct raw14_pc_slot){frames[i], 0, 0};
    source->last_id = source->last_us = source->pending_id = source->leased_id = 0;
    source->pending_slot = source->requested = 0;
    source->frame_bytes = bytes;
    *ops = (struct raw14_source_ops){source, begin, end, acquire, release};
    return RAW14_OK;
}

enum raw14_status raw14_pc_source_arm(struct raw14_pc_source *source, unsigned slot,
    uint64_t timestamp_us, uint64_t *id)
{
    if (!source || !id || slot >= RAW14_PC_BUFFERS || timestamp_us < source->last_us)
        return RAW14_INVALID;
    if (!source->requested)
        return RAW14_NOT_READY;
    if (source->slots[slot].ready_id)
        return RAW14_BUSY;
    if (source->last_id == UINT64_MAX)
        return RAW14_BOUNDS;
    source->pending_slot = slot;
    source->slots[slot].timestamp_us = source->last_us = timestamp_us;
    *id = source->pending_id = ++source->last_id;
    return RAW14_OK;
}

enum raw14_status raw14_pc_source_complete(struct raw14_pc_source *source, uint64_t id, size_t bytes)
{
    if (!source || !id)
        return RAW14_INVALID;
    if (source->pending_id != id)
        return RAW14_NOT_READY;
    source->pending_id = 0;
    if (bytes != source->frame_bytes)
        return RAW14_BOUNDS;
    source->slots[source->pending_slot].ready_id = id;
    return RAW14_OK;
}
