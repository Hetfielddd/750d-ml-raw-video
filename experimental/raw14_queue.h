/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RAW14_QUEUE_H
#define RAW14_QUEUE_H
#include "raw14_copy.h"
#define RAW14_QUEUE_MAX_SLOTS 8

enum raw14_slot_state { RAW14_FREE, RAW14_FILLING, RAW14_READY, RAW14_WRITING };
enum raw14_queue_status {
    RAW14_Q_OK, RAW14_Q_INVALID, RAW14_Q_FULL, RAW14_Q_EMPTY,
    RAW14_Q_BUSY, RAW14_Q_COPY_FAILED, RAW14_Q_STALE, RAW14_Q_EXHAUSTED
};
struct raw14_lease { uint64_t session, ticket; unsigned slot; };
struct raw14_slot {
    struct raw14_frame frame;
    enum raw14_slot_state state;
    uint64_t ticket, write_token, frame_id, timestamp_us;
    size_t bytes;
};
struct raw14_queue {
    struct raw14_slot slots[RAW14_QUEUE_MAX_SLOTS];
    unsigned count, busy, has_frame_id;
    uint64_t session, next_ticket, next_lease, last_frame_id;
    uint32_t accepted_frames, overflow_frames, rejected_frames;
};
struct raw14_write_view {
    struct raw14_lease lease;
    struct raw14_frame frame;
    uint64_t frame_id, timestamp_us;
    size_t bytes;
};

/* Serialized callers only: no atomics, locks, DMA, or filesystem access.
 * Initialize only a new/quiescent queue. Supply a different nonzero session ID
 * for every reinitialization; all prior leases then become invalid.
 * Buffers remain caller-owned, distinct, and alive until queue use ends.
 */
enum raw14_queue_status raw14_queue_init(struct raw14_queue *queue,
    const struct raw14_frame *buffers, unsigned count, uint64_t session);

/* Copies synchronously; publishes only a successful complete frame.
 * Frame IDs must increase within a session. Full queue drops the NEW frame,
 * without touching queued/in-use frames. copy_status explains rejected copies.
 */
enum raw14_queue_status raw14_queue_push(struct raw14_queue *queue,
    struct raw14_engine *engine, const struct raw14_frame *source, uint32_t source_y,
    uint64_t frame_id, uint64_t timestamp_us, enum raw14_status *copy_status);

/* Single writer: obtain oldest ready frame; all other take calls return BUSY
 * until that lease is released. View is a value copy; frame data is borrowed.
 */
enum raw14_queue_status raw14_queue_take(struct raw14_queue *queue,
    struct raw14_write_view *view);
enum raw14_queue_status raw14_queue_release_written(struct raw14_queue *queue,
    struct raw14_lease lease);
/* Preserve data for retry. Caller must repair/seek the output after partial I/O;
 * aborting this lease does not roll back a filesystem write.
 */
enum raw14_queue_status raw14_queue_abort_write(struct raw14_queue *queue,
    struct raw14_lease lease);
#endif
