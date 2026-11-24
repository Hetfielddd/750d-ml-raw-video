/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_queue.h"
static uint8_t capture[56], storage[3][56];
static struct raw14_queue queue;
static struct raw14_frame buffers[3], source;
static struct raw14_engine engine;
static unsigned mode, copies;
static enum raw14_queue_status nested_take, nested_push;

static int copy_backend(void *ctx, void *dst, const void *src, size_t bytes)
{
    uint8_t *to = dst;
    const uint8_t *from = src;
    size_t i;
    struct raw14_write_view view;
    (void)ctx;
    ++copies;
    if (mode == 2) {
        nested_take = raw14_queue_take(&queue, &view);
        nested_push = raw14_queue_push(&queue, &engine, &source, 0, 999, 0, 0);
    }
    if (mode == 1) { to[0] = from[0]; return -1; }
    for (i = 0; i < bytes; ++i) to[i] = from[i];
    return 0;
}

static void setup(void)
{
    unsigned i, j;
    for (i = 0; i < 3; ++i) {
        buffers[i] = (struct raw14_frame){storage[i], 56, 8, 4, 14, 14};
        for (j = 0; j < 56; ++j) storage[i][j] = 0xa5;
    }
    for (j = 0; j < 56; ++j) capture[j] = (uint8_t)j;
    source = (struct raw14_frame){capture, 56, 8, 4, 14, 14};
    engine = (struct raw14_engine){copy_backend, 0, 0};
    mode = copies = 0;
    (void)raw14_queue_init(&queue, buffers, 2, 10);
}

#define CHECK(cond) do { if (!(cond)) return __LINE__; } while (0)
int test_run(void)
{
    struct raw14_write_view a, b;
    struct raw14_lease old;
    enum raw14_status detail;
    unsigned i, j, step, used = 0, head = 0;
    uint64_t expected[3], next_id = 1;

    setup();
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_EMPTY);
    capture[0] = 11;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 101, UINT64_C(0x123456789), &detail) == RAW14_Q_OK);
    CHECK(detail == RAW14_OK);
    capture[0] = 22;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 102, 200, 0) == RAW14_Q_OK);
    capture[0] = 33;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 103, 300, 0) == RAW14_Q_FULL);
    CHECK(copies == 2 && queue.overflow_frames == 1);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK);
    CHECK(a.frame_id == 101 && a.timestamp_us == UINT64_C(0x123456789) && a.bytes == 56);
    CHECK(((uint8_t *)a.frame.data)[0] == 11);
    CHECK(raw14_queue_take(&queue, &b) == RAW14_Q_BUSY);
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 103, 300, 0) == RAW14_Q_FULL);
    CHECK(((uint8_t *)a.frame.data)[0] == 11);
    old = a.lease;
    CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);
    CHECK(raw14_queue_release_written(&queue, old) == RAW14_Q_STALE);
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 103, 300, 0) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &b) == RAW14_Q_OK);
    CHECK(b.frame_id == 102 && ((uint8_t *)b.frame.data)[0] == 22);
    CHECK(raw14_queue_release_written(&queue, old) == RAW14_Q_STALE);
    CHECK(raw14_queue_abort_write(&queue, b.lease) == RAW14_Q_OK);
    old = b.lease;
    CHECK(raw14_queue_take(&queue, &b) == RAW14_Q_OK && b.frame_id == 102);
    CHECK(raw14_queue_release_written(&queue, old) == RAW14_Q_STALE);
    CHECK(raw14_queue_release_written(&queue, b.lease) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &b) == RAW14_Q_OK && b.frame_id == 103);
    CHECK(raw14_queue_release_written(&queue, b.lease) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &b) == RAW14_Q_EMPTY);
    CHECK(queue.accepted_frames == 3);
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 102, 0, 0) == RAW14_Q_INVALID);

    setup(); mode = 1;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, &detail) == RAW14_Q_COPY_FAILED);
    CHECK(detail == RAW14_BACKEND_FAILED && queue.rejected_frames == 1);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_EMPTY && !queue.busy);
    mode = 0;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK);
    for (i = 0; i < 56; ++i) CHECK(((uint8_t *)a.frame.data)[i] == capture[i]);
    CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);

    setup(); mode = 2;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_OK);
    CHECK(nested_take == RAW14_Q_BUSY && nested_push == RAW14_Q_BUSY);
    CHECK(copies == 1 && queue.accepted_frames == 1);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK);
    old = a.lease;
    CHECK(raw14_queue_release_written(&queue, old) == RAW14_Q_OK);
    CHECK(raw14_queue_init(&queue, buffers, 2, 11) == RAW14_Q_OK);
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK);
    CHECK(raw14_queue_release_written(&queue, old) == RAW14_Q_STALE);
    CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);

    setup(); engine.copy = 0;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, &detail) == RAW14_Q_COPY_FAILED);
    CHECK(detail == RAW14_NOT_READY && queue.slots[0].state == RAW14_FREE);
    setup();
    CHECK(raw14_queue_init(&queue, buffers, 1, 12) == RAW14_Q_INVALID);
    CHECK(raw14_queue_init(&queue, buffers, 3, 0) == RAW14_Q_INVALID);
    buffers[1].data = buffers[0].data;
    CHECK(raw14_queue_init(&queue, buffers, 2, 12) == RAW14_Q_INVALID);
    CHECK(queue.session == 10);
    setup(); buffers[1].height_rows = 3;
    CHECK(raw14_queue_init(&queue, buffers, 2, 12) == RAW14_Q_INVALID);
    setup(); queue.next_ticket = UINT64_MAX;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_EXHAUSTED);
    setup();
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_OK);
    queue.next_lease = UINT64_MAX;
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_EXHAUSTED);
    CHECK(queue.slots[0].state == RAW14_READY);

    setup(); queue.next_ticket = UINT64_C(0xffffffff); queue.next_lease = UINT64_C(0xffffffff);
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_OK);
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 2, 0, 0) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK && a.frame_id == 1);
    CHECK(a.lease.ticket == UINT64_C(0xffffffff));
    CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK && a.frame_id == 2);
    CHECK(a.lease.ticket == UINT64_C(0x100000000));
    CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);

    setup();
    CHECK(raw14_queue_push(&queue, &engine, &source, 1, 1, 0, &detail) == RAW14_Q_COPY_FAILED);
    CHECK(detail == RAW14_UNSUPPORTED && copies == 0 && queue.accepted_frames == 0);
    CHECK(raw14_queue_push(&queue, &engine, 0, 0, 1, 0, &detail) == RAW14_Q_COPY_FAILED);
    CHECK(detail == RAW14_INVALID && copies == 0);
    queue.accepted_frames = UINT32_MAX;
    CHECK(raw14_queue_push(&queue, &engine, &source, 0, 1, 0, 0) == RAW14_Q_OK);
    CHECK(queue.accepted_frames == UINT32_MAX);

    /* Different producer/writer schedules, checked against a separate FIFO. */
    setup();
    CHECK(raw14_queue_init(&queue, buffers, 3, 20) == RAW14_Q_OK);
    for (step = 0; step < 1000; ++step) {
        if (step % 5 != 4) {
            enum raw14_queue_status result;
            capture[0] = (uint8_t)next_id;
            result = raw14_queue_push(&queue, &engine, &source, 0, next_id, next_id * 100, 0);
            if (used == 3) CHECK(result == RAW14_Q_FULL);
            else {
                CHECK(result == RAW14_Q_OK);
                expected[(head + used) % 3] = next_id;
                ++used;
            }
            ++next_id;
        }
        if (step % 3 == 0 && used) {
            CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK);
            CHECK(a.frame_id == expected[head]);
            CHECK(((uint8_t *)a.frame.data)[0] == (uint8_t)expected[head]);
            for (j = 1; j < 56; ++j) CHECK(((uint8_t *)a.frame.data)[j] == j);
            CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);
            head = (head + 1) % 3;
            --used;
        }
    }
    while (used) {
        CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_OK && a.frame_id == expected[head]);
        CHECK(raw14_queue_release_written(&queue, a.lease) == RAW14_Q_OK);
        head = (head + 1) % 3;
        --used;
    }
    CHECK(raw14_queue_take(&queue, &a) == RAW14_Q_EMPTY);
    return 0;
}
