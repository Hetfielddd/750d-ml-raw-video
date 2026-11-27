/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RAW14_PC_SOURCE_H
#define RAW14_PC_SOURCE_H

#include "raw14_capture.h"

#define RAW14_PC_BUFFERS 2

struct raw14_pc_slot {
    struct raw14_frame frame;
    uint64_t ready_id, timestamp_us;
};

struct raw14_pc_source {
    struct raw14_pc_slot slots[RAW14_PC_BUFFERS];
    uint64_t last_id, last_us, pending_id, leased_id;
    size_t frame_bytes;
    unsigned pending_slot, requested;
};

/* Serialized PC model for one capture consumer per source. Initialize a
 * new/quiescent source and use RAW14_SOURCE_PC_SYNTHETIC for that capture.
 * Producer writes are confined to the most recently armed slot. */
enum raw14_status raw14_pc_source_init(struct raw14_pc_source *,
    const struct raw14_frame frames[RAW14_PC_BUFFERS], struct raw14_source_ops *);

/* A successful arm supersedes any incomplete write. Ready/borrowed slots
 * stay reserved. The returned ID is unique for the source's lifetime. */
enum raw14_status raw14_pc_source_arm(struct raw14_pc_source *, unsigned slot,
    uint64_t timestamp_us, uint64_t *id);

/* PC caller supplies the completed transfer's identity and exact bytes.
 * An unrecognized ID leaves the current write alone. A recognized but
 * short/oversize completion discards that transfer. */
enum raw14_status raw14_pc_source_complete(struct raw14_pc_source *, uint64_t id, size_t bytes);

#endif
