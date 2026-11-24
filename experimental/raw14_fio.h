/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RAW14_FIO_H
#define RAW14_FIO_H
#include "raw14_mlv.h"

/* Contract shaped by pinned ML src/fio-ml.h, not a binding to Canon addresses.
 * Use typed wrappers around ML FIO functions; do not cast function pointers.
 * flush is a required, separately verified operation with zero-success status.
 */
struct raw14_fio_ops {
    int (*write)(void *handle, const void *data, size_t bytes);
    int64_t (*seek)(void *handle, int64_t offset, int whence);
    int (*flush)(void *handle);
};
struct raw14_fio {
    void *handle;
    struct raw14_fio_ops ops;
};
/* Caller supplies an exclusively owned, already opened NEW/EMPTY file and
 * externally serializes access. Verifies EOF==0 before exposing writer IO.
 * Does not open/close files or validate opaque handles (including zero).
 * No truncate facility: shrinking fails; unchanged EOF succeeds only after
 * querying actual length and restoring the original position successfully.
 * Adapter and returned IO must outlive the writer and must not overlap.
 */
int raw14_fio_init(struct raw14_fio *, void *handle,
    const struct raw14_fio_ops *, struct raw14_mlv_io *);
#endif
