/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_queue.h"

static void increment(uint32_t *value)
{
    if (*value != UINT32_MAX) ++*value;
}

enum raw14_queue_status raw14_queue_init(struct raw14_queue *q,
    const struct raw14_frame *buffers, unsigned count, uint64_t session)
{
    unsigned i, j;
    if (!q || !buffers || count < 2 || count > RAW14_QUEUE_MAX_SLOTS || !session)
        return RAW14_Q_INVALID;
    /* Validate all input before changing q, including a possible re-init. */
    for (i = 0; i < count; ++i) {
        if (raw14_validate_frame(&buffers[i]) != RAW14_OK || buffers[i].height_rows % 2)
            return RAW14_Q_INVALID;
        if (buffers[i].width_pixels != buffers[0].width_pixels ||
            buffers[i].height_rows != buffers[0].height_rows)
            return RAW14_Q_INVALID;
        for (j = 0; j < i; ++j) {
            uintptr_t a = (uintptr_t)buffers[i].data;
            uintptr_t b = (uintptr_t)buffers[j].data;
            if (a < b + buffers[j].capacity && b < a + buffers[i].capacity)
                return RAW14_Q_INVALID;
        }
    }
    q->count = count;
    q->session = session;
    q->next_ticket = 1;
    q->next_lease = 1;
    q->busy = q->has_frame_id = 0;
    q->last_frame_id = 0;
    q->accepted_frames = q->overflow_frames = q->rejected_frames = 0;
    for (i = 0; i < count; ++i) {
        q->slots[i].frame = buffers[i];
        q->slots[i].state = RAW14_FREE;
        q->slots[i].ticket = q->slots[i].frame_id = q->slots[i].timestamp_us = 0;
        q->slots[i].write_token = 0;
        q->slots[i].bytes = 0;
        q->slots[i].source_y = 0;
    }
    return RAW14_Q_OK;
}

static void copied(void *context, size_t bytes)
{
    struct raw14_slot *slot = context;
    slot->bytes = bytes;
    /* Publication happens in push AFTER raw14_copy_rows returns. */
}

enum raw14_queue_status raw14_queue_push(struct raw14_queue *q,
    struct raw14_engine *engine, const struct raw14_frame *source, uint32_t source_y,
    uint64_t frame_id, uint64_t timestamp_us, enum raw14_status *copy_status)
{
    unsigned i;
    enum raw14_status result;
    struct raw14_slot *slot;
    if (copy_status) *copy_status = RAW14_NOT_READY;
    if (!q || !q->session || q->count < 2 || q->count > RAW14_QUEUE_MAX_SLOTS)
        return RAW14_Q_INVALID;
    if (q->busy) return RAW14_Q_BUSY;
    if (q->has_frame_id && frame_id <= q->last_frame_id)
        return RAW14_Q_INVALID;
    if (q->next_ticket == UINT64_MAX) return RAW14_Q_EXHAUSTED;
    for (i = 0; i < q->count; ++i)
        if (q->slots[i].state == RAW14_FREE) break;
    if (i == q->count) {
        increment(&q->overflow_frames);
        return RAW14_Q_FULL;
    }
    q->busy = 1;
    slot = &q->slots[i];
    slot->state = RAW14_FILLING;
    slot->ticket = q->next_ticket++;
    slot->bytes = 0;
    result = raw14_copy_rows(engine, &slot->frame, 0, source, source_y,
                            slot->frame.height_rows, copied, slot);
    if (copy_status) *copy_status = result;
    if (result != RAW14_OK) {
        slot->state = RAW14_FREE;
        slot->bytes = 0;
        increment(&q->rejected_frames);
        q->busy = 0;
        return RAW14_Q_COPY_FAILED;
    }
    slot->frame_id = frame_id;
    slot->timestamp_us = timestamp_us;
    slot->source_y = source_y;
    slot->state = RAW14_READY;
    q->last_frame_id = frame_id;
    q->has_frame_id = 1;
    increment(&q->accepted_frames);
    q->busy = 0;
    return RAW14_Q_OK;
}

enum raw14_queue_status raw14_queue_take(struct raw14_queue *q,
    struct raw14_write_view *view)
{
    unsigned i, oldest = RAW14_QUEUE_MAX_SLOTS;
    struct raw14_slot *slot;
    if (!q || !view || !q->session || q->count < 2 || q->count > RAW14_QUEUE_MAX_SLOTS)
        return RAW14_Q_INVALID;
    if (q->busy) return RAW14_Q_BUSY;
    for (i = 0; i < q->count; ++i) {
        if (q->slots[i].state == RAW14_WRITING) return RAW14_Q_BUSY;
        if (q->slots[i].state == RAW14_READY &&
            (oldest == RAW14_QUEUE_MAX_SLOTS || q->slots[i].ticket < q->slots[oldest].ticket))
            oldest = i;
    }
    if (oldest == RAW14_QUEUE_MAX_SLOTS) return RAW14_Q_EMPTY;
    if (q->next_lease == UINT64_MAX) return RAW14_Q_EXHAUSTED;
    slot = &q->slots[oldest];
    slot->state = RAW14_WRITING;
    slot->write_token = q->next_lease++;
    view->lease = (struct raw14_lease){q->session, slot->write_token, oldest};
    view->frame = slot->frame;
    view->frame_id = slot->frame_id;
    view->timestamp_us = slot->timestamp_us;
    view->bytes = slot->bytes;
    view->source_y = slot->source_y;
    return RAW14_Q_OK;
}

static enum raw14_queue_status finish(struct raw14_queue *q,
    struct raw14_lease lease, enum raw14_slot_state next)
{
    struct raw14_slot *slot;
    if (!q || !q->session || q->count < 2 || q->count > RAW14_QUEUE_MAX_SLOTS)
        return RAW14_Q_INVALID;
    if (q->busy) return RAW14_Q_BUSY;
    if (lease.session != q->session || lease.slot >= q->count)
        return RAW14_Q_STALE;
    slot = &q->slots[lease.slot];
    if (slot->state != RAW14_WRITING || slot->write_token != lease.ticket)
        return RAW14_Q_STALE;
    slot->state = next;
    if (next == RAW14_FREE) slot->bytes = 0;
    return RAW14_Q_OK;
}

enum raw14_queue_status raw14_queue_release_written(struct raw14_queue *q,
    struct raw14_lease lease)
{
    return finish(q, lease, RAW14_FREE);
}

enum raw14_queue_status raw14_queue_abort_write(struct raw14_queue *q,
    struct raw14_lease lease)
{
    return finish(q, lease, RAW14_READY);
}
