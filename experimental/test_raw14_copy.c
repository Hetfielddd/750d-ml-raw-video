/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_copy.h"

static uint8_t input[112], output[112];
static unsigned copied, completed;
static size_t completed_bytes;
static int fail_backend;
static struct raw14_engine engine;
static struct raw14_frame src, dst;
static int nested_status;
static unsigned nested_mode;
static uint8_t observed_first, observed_last;
static void done(void *ctx, size_t bytes);

static int copy(void *ctx, void *to, const void *from, size_t bytes)
{
    uint8_t *d = to;
    const uint8_t *s = from;
    size_t i;
    (void)ctx;
    copied++;
    if (nested_mode == 1)
        nested_status = raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0);
    if (fail_backend) return -1;
    for (i = 0; i < bytes; ++i) d[i] = s[i];
    return 0;
}

static void done(void *ctx, size_t bytes)
{
    unsigned *counter = ctx;
    completed++;
    completed_bytes = bytes;
    observed_first = output[28];
    observed_last = output[55];
    if (counter) (*counter)++;
    if (nested_mode == 2)
        nested_status = raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0);
}

static void reset(void)
{
    unsigned i;
    for (i = 0; i < sizeof(input); i++) { input[i] = (uint8_t)(i + 1); output[i] = 0xa5; }
    src = (struct raw14_frame){input, sizeof(input), 8, 8, 14, 14};
    dst = (struct raw14_frame){output, sizeof(output), 8, 8, 14, 14};
    engine = (struct raw14_engine){copy, 0, 0};
    copied = completed = fail_backend = nested_mode = 0;
    completed_bytes = 0;
    observed_first = observed_last = 0;
    nested_status = -1;
}

#define CHECK(cond) do { if (!(cond)) return __LINE__; } while (0)

/* Return zero on pass, otherwise the failed source line. Runs as ARM code. */
int test_run(void)
{
    unsigned i, counter = 0;
    reset();
    CHECK(raw14_copy_rows(&engine, &dst, 2, &src, 4, 2, done, &counter) == RAW14_OK);
    CHECK(copied == 1 && completed == 1 && counter == 1 && completed_bytes == 28);
    CHECK(observed_first == input[56] && observed_last == input[83]);
    for (i = 0; i < sizeof(output); i++)
        CHECK(output[i] == ((i >= 28 && i < 56) ? input[i + 28] : 0xa5));

    reset();
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 8, done, 0) == RAW14_OK);
    for (i = 0; i < sizeof(output); i++) CHECK(output[i] == input[i]);

    reset();
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 8, 2, done, 0) == RAW14_BOUNDS);
    CHECK(raw14_copy_rows(&engine, &dst, 8, &src, 0, 2, done, 0) == RAW14_BOUNDS);
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, UINT32_MAX - 1, done, 0) == RAW14_BOUNDS);
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 1, 2, done, 0) == RAW14_UNSUPPORTED);
    CHECK(raw14_copy_rows(&engine, &dst, 1, &src, 0, 2, done, 0) == RAW14_UNSUPPORTED);
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 3, done, 0) == RAW14_UNSUPPORTED);
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 0, done, 0) == RAW14_INVALID);
    CHECK(copied == 0 && completed == 0);
    CHECK(raw14_copy_rows(0, &dst, 0, &src, 0, 2, done, 0) == RAW14_INVALID);
    CHECK(raw14_copy_rows(&engine, 0, 0, &src, 0, 2, done, 0) == RAW14_INVALID);
    CHECK(raw14_copy_rows(&engine, &dst, 0, 0, 0, 2, done, 0) == RAW14_INVALID);
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, 0, 0) == RAW14_INVALID);

    reset(); src.bits_per_pixel = 12;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_UNSUPPORTED);
    reset(); src.width_pixels = 7;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_UNSUPPORTED);
    reset(); src.pitch_bytes = 16;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_UNSUPPORTED);
    reset(); dst.width_pixels = 4; dst.pitch_bytes = 7;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_UNSUPPORTED);
    reset(); dst.capacity--;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_BOUNDS);
    reset(); src.height_rows = UINT32_MAX;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_BOUNDS);
    reset(); src.width_pixels = UINT32_MAX - 3;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_BOUNDS);
    reset(); src.data = (void *)(UINTPTR_MAX - 5);
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_BOUNDS);
    reset(); dst.data = input + 14;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_OVERLAP);
    reset(); src.data = 0;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_INVALID);
    reset(); engine.copy = 0;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_NOT_READY);
    CHECK(copied == 0 && completed == 0);

    reset(); fail_backend = 1;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_BACKEND_FAILED);
    CHECK(!engine.busy && copied == 1 && completed == 0);
    for (i = 0; i < sizeof(output); i++) CHECK(output[i] == 0xa5);
    fail_backend = 0;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_OK);

    reset(); nested_mode = 1;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_OK);
    CHECK(nested_status == RAW14_BUSY && copied == 1 && completed == 1 && !engine.busy);
    reset(); nested_mode = 2;
    CHECK(raw14_copy_rows(&engine, &dst, 0, &src, 0, 2, done, 0) == RAW14_OK);
    CHECK(nested_status == RAW14_BUSY && copied == 1 && completed == 1 && !engine.busy);
    return 0;
}
