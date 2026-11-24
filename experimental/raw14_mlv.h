/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RAW14_MLV_H
#define RAW14_MLV_H
#include "raw14_queue.h"
#define RAW14_MLV_RAW_INFO_SIZE 160

enum raw14_mlv_status { RAW14_MLV_OK, RAW14_MLV_EMPTY, RAW14_MLV_BUSY,
    RAW14_MLV_INVALID, RAW14_MLV_IO_ERROR, RAW14_MLV_QUEUE_ERROR };
enum raw14_mlv_state { RAW14_MLV_OPEN = 1, RAW14_MLV_FAILED, RAW14_MLV_CLOSED };
struct raw14_mlv_io {
    void *ctx;
    /* Synchronous consumption. Positive short writes are retried.
     * Zero, SIZE_MAX, or a count larger than requested means failure. */
    size_t (*write)(void *, const void *, size_t);
    int (*seek)(void *, uint64_t);
    int (*truncate)(void *, uint64_t);
    int (*flush)(void *);
};
struct raw14_mlv_config {
    uint16_t width, height;
    uint32_t fps_num, fps_den;
    uint64_t guid, start_us;
    /* Upstream raw_info_t wire layout. Caller supplies real calibration later. */
    const uint8_t *raw_info;
};
struct raw14_mlv_writer {
    struct raw14_mlv_io io;
    struct raw14_queue *queue;
    uint64_t session, guid, start_us, first_id, last_us, offset, good_end;
    uint32_t fps_num, fps_den, frames, flags, frame_bytes;
    uint16_t width, height;
    unsigned state, busy, tail_valid, initialized;
};
/* Serialized callers only. The queue must remain in the same session.
 * The IO callbacks target an EXCLUSIVE NEW/EMPTY file positioned at zero.
 * No file is opened/closed by this layer. Metadata is serialized immediately.
 */
enum raw14_mlv_status raw14_mlv_begin(struct raw14_mlv_writer *,
    struct raw14_queue *, const struct raw14_mlv_io *, const struct raw14_mlv_config *);
enum raw14_mlv_status raw14_mlv_write_next(struct raw14_mlv_writer *);
/* On success, updates MLVI count/flags and flushes. Refuses pending frames in
 * a normal recording. A failed recording may finalize its repaired good prefix.
 */
enum raw14_mlv_status raw14_mlv_finish(struct raw14_mlv_writer *);
#endif
