/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RAW14_CAPTURE_H
#define RAW14_CAPTURE_H
#include "raw14_queue.h"

enum raw14_source_kind { RAW14_SOURCE_PC_SYNTHETIC=1, RAW14_SOURCE_CANON_750D=2 };
enum raw14_capture_status { RAW14_CAPTURE_OK, RAW14_CAPTURE_NO_FRAME,
    RAW14_CAPTURE_DROPPED, RAW14_CAPTURE_BUSY, RAW14_CAPTURE_INVALID,
    RAW14_CAPTURE_UNVERIFIED, RAW14_CAPTURE_SOURCE_ERROR,
    RAW14_CAPTURE_COPY_ERROR, RAW14_CAPTURE_SESSION_ERROR };
enum raw14_capture_state { RAW14_CAPTURE_IDLE=1, RAW14_CAPTURE_ACTIVE, RAW14_CAPTURE_FAILED };
struct raw14_source_view {
    struct raw14_frame frame;
    uint64_t frame_id, timestamp_us, cookie;
};
struct raw14_source_ops {
    void *ctx;
    /* begin/end own exactly one source request, not global source shutdown.
     * end must clean up even a partially failed begin. Zero means success;
     * nonzero end means this request is still owned and cleanup may retry. */
    int (*begin)(void *);
    int (*end)(void *);
    /* 0: complete stable frame borrowed until release; 1: none; -1: error.
     * Nonzero return must leave NO outstanding lease. Nonblocking acquisition.
     * Never expose a frame that DMA is still writing or may reuse meanwhile. */
    int (*acquire)(void *, struct raw14_source_view *);
    /* Nonzero release retains this same lease and must be retryable. */
    int (*release)(void *, uint64_t cookie);
};
struct raw14_capture_config {
    enum raw14_source_kind kind;
    uint32_t width, source_height, source_y;
    size_t pitch;
};
struct raw14_capture {
    struct raw14_source_ops source;
    struct raw14_capture_config config;
    struct raw14_queue *queue;
    struct raw14_engine *engine;
    uint64_t session, cookie, last_id, last_us;
    unsigned state, busy, requested, leased, seen;
};
/* PC source only in this version; CANON_750D is always UNVERIFIED, with no
 * callbacks invoked. This is an API policy, not hardware detection/security.
 * Initialize only a new/quiescent object. All calls externally serialized with
 * queue/writer access. Not ISR-safe; busy detects reentrancy, not parallelism.
 * No MMIO, DMA redirection, firmware calls, waiting, allocation, or file IO here.
 */
enum raw14_capture_status raw14_capture_init(struct raw14_capture *,
    struct raw14_queue *, struct raw14_engine *, const struct raw14_source_ops *,
    const struct raw14_capture_config *);
enum raw14_capture_status raw14_capture_start(struct raw14_capture *);
enum raw14_capture_status raw14_capture_poll(struct raw14_capture *);
/* Releases pending lease, then ends own request. Failed cleanup remains
 * retryable; no new capture allowed. Does not discard queued output frames. */
enum raw14_capture_status raw14_capture_stop(struct raw14_capture *);
#endif
