/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_fio.h"
#include <limits.h>

static size_t write_fio(void *ctx, const void *data, size_t bytes)
{
    struct raw14_fio *a=ctx;
    size_t request=bytes > INT_MAX ? INT_MAX : bytes;
    int written;
    if(!bytes) return 0;
    written=a->ops.write(a->handle,data,request);
    if(written<0 || (size_t)written>request) return SIZE_MAX;
    return (size_t)written;
}
static int seek_fio(void *ctx, uint64_t offset)
{
    struct raw14_fio *a=ctx;
    if(offset>INT64_MAX) return -1;
    return a->ops.seek(a->handle,(int64_t)offset,0)==(int64_t)offset ? 0 : -1;
}
static int unchanged_eof(void *ctx, uint64_t size)
{
    struct raw14_fio *a=ctx;
    int64_t position, end, restored;
    if(size>INT64_MAX) return -1;
    position=a->ops.seek(a->handle,0,1);
    if(position<0) return -1;
    end=a->ops.seek(a->handle,0,2);
    restored=a->ops.seek(a->handle,position,0);
    /* Neither a seek nor a successful header rewrite removes a partial tail. */
    return end==(int64_t)size && restored==position ? 0 : -1;
}
static int flush_fio(void *ctx)
{
    struct raw14_fio *a=ctx;
    return a->ops.flush(a->handle);
}
int raw14_fio_init(struct raw14_fio *a, void *handle,
    const struct raw14_fio_ops *ops, struct raw14_mlv_io *io)
{
    if(!a || !ops || !io || !ops->write || !ops->seek || !ops->flush) return -1;
    if(ops->seek(handle,0,2)!=0 || ops->seek(handle,0,0)!=0) return -1;
    a->handle=handle; a->ops=*ops;
    *io=(struct raw14_mlv_io){a,write_fio,seek_fio,unchanged_eof,flush_fio};
    return 0;
}
