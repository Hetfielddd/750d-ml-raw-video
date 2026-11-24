/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_fio.h"
#include <limits.h>
static uint8_t file[1024], source_data[56], storage[2][56], info[160];
static int64_t position, length;
static int write_mode, seek_mode, flush_error;
static size_t requested, fail_at;
static unsigned writes, seeks, flushes;
static void *last_handle;
static int mock_write(void *h,const void *data,size_t bytes)
{
    size_t i,n=bytes>7 ? 7 : bytes; const uint8_t *s=data;
    last_handle=h; requested=bytes; ++writes;
    if(write_mode==1) return -1;
    if(write_mode==2) return 0;
    if(write_mode==3) return (int)bytes+1;
    if(write_mode==4) return (int)bytes; /* Count-only limit test, no memory access. */
    if((uint64_t)position>=fail_at) return -1;
    if(n>fail_at-(size_t)position) n=fail_at-(size_t)position;
    if(position<0 || position+(int64_t)n>(int64_t)sizeof(file)) return -1;
    for(i=0;i<n;++i) file[(size_t)position+i]=s[i];
    position+=(int64_t)n; if(position>length) length=position;
    return (int)n;
}
static int64_t mock_seek(void *h,int64_t offset,int whence)
{
    int64_t target;
    last_handle=h; ++seeks;
    if(seek_mode==1 || (seek_mode==3 && whence==0)) return -1;
    target=offset+(whence==0 ? 0 : whence==1 ? position : length);
    if(target<0 || target>length) return -1; /* No seek beyond EOF. */
    position=target;
    return seek_mode==2 ? target+1 : target;
}
static int mock_flush(void *h) { last_handle=h; ++flushes; return flush_error; }
static int copy(void *ctx,void *dst,const void *src,size_t bytes)
{
    size_t i; uint8_t *d=dst; const uint8_t *s=src; (void)ctx;
    for(i=0;i<bytes;++i) d[i]=s[i];
    return 0;
}
static void put32(unsigned at,uint32_t value)
{ unsigned i; for(i=0;i<4;++i) info[at+i]=(uint8_t)(value>>(i*8)); }
static void reset(void)
{
    unsigned i;
    position=length=0; write_mode=seek_mode=flush_error=0;
    requested=writes=seeks=flushes=0; last_handle=(void *)1;
    fail_at=SIZE_MAX;
    for(i=0;i<sizeof(info);++i) info[i]=0;
    put32(0,1); put32(8,4); put32(12,8); put32(16,14); put32(20,56);
    put32(24,14); put32(32,16383);
}
#define CHECK(c) do { if(!(c)) return __LINE__; } while(0)
int test_run(void)
{
    struct raw14_fio adapter;
    struct raw14_fio_ops ops={mock_write,mock_seek,mock_flush};
    struct raw14_mlv_io io;
    struct raw14_queue queue;
    struct raw14_engine engine={copy,0,0};
    struct raw14_frame source={source_data,56,8,4,14,14}, buffers[2];
    struct raw14_mlv_writer writer;
    struct raw14_mlv_config config={8,4,24,1,123,0,info};
    unsigned i;
    reset(); CHECK(raw14_fio_init(&adapter,0,&ops,&io)==0 && last_handle==0);
    write_mode=1; CHECK(io.write(io.ctx,source_data,7)==SIZE_MAX);
    write_mode=2; CHECK(io.write(io.ctx,source_data,7)==0);
    write_mode=3; CHECK(io.write(io.ctx,source_data,7)==SIZE_MAX);
    write_mode=4; CHECK(io.write(io.ctx,source_data,SIZE_MAX)==INT_MAX && requested==INT_MAX);
    i=writes; CHECK(io.write(io.ctx,source_data,0)==0 && writes==i);
    length=100; position=13;
    CHECK(io.seek(io.ctx,27)==0 && position==27); /* Positive position is success. */
    CHECK(io.seek(io.ctx,101)!=0);
    i=seeks; CHECK(io.seek(io.ctx,UINT64_MAX)!=0 && seeks==i);
    seek_mode=2; CHECK(io.seek(io.ctx,27)!=0); seek_mode=0;
    CHECK(io.truncate(io.ctx,100)==0 && position==27 && length==100);
    CHECK(io.truncate(io.ctx,99)!=0 && position==27 && length==100);
    CHECK(io.truncate(io.ctx,101)!=0 && position==27 && length==100);
    length=INT64_C(0x200000011);
    CHECK(io.seek(io.ctx,UINT64_C(0x100000007))==0 && position==INT64_C(0x100000007));
    CHECK(io.truncate(io.ctx,UINT64_C(0x200000011))==0 && position==INT64_C(0x100000007));
    length=100; position=27;
    seek_mode=3; CHECK(io.truncate(io.ctx,100)!=0); seek_mode=0;
    flush_error=-1; CHECK(io.flush(io.ctx)!=0); flush_error=0;
    CHECK(io.flush(io.ctx)==0 && flushes==2);
    i=writes;
    CHECK(raw14_fio_init(&adapter,0,&ops,&io)!=0 && writes==i); /* Existing file refused. */

    for(i=0;i<2;++i) buffers[i]=(struct raw14_frame){storage[i],56,8,4,14,14};
    reset(); CHECK(raw14_fio_init(&adapter,0,&ops,&io)==0);
    CHECK(raw14_queue_init(&queue,buffers,2,1)==RAW14_Q_OK);
    CHECK(raw14_mlv_begin(&writer,&queue,&io,&config)==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,1,0,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK && length==320 && flushes==1);

    /* A failure before any new bytes preserves a finalizable prefix. */
    reset(); CHECK(raw14_fio_init(&adapter,0,&ops,&io)==0);
    CHECK(raw14_queue_init(&queue,buffers,2,2)==RAW14_Q_OK);
    CHECK(raw14_mlv_begin(&writer,&queue,&io,&config)==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,1,0,0)==RAW14_Q_OK);
    write_mode=1;
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_IO_ERROR && writer.tail_valid);
    write_mode=0;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK && length==232);

    /* Partial tail cannot be removed by seeking: finalization MUST fail. */
    reset(); CHECK(raw14_fio_init(&adapter,0,&ops,&io)==0);
    CHECK(raw14_queue_init(&queue,buffers,2,3)==RAW14_Q_OK);
    CHECK(raw14_mlv_begin(&writer,&queue,&io,&config)==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,1,0,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,2,41667,0)==RAW14_Q_OK);
    fail_at=writer.good_end+35;
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_IO_ERROR && !writer.tail_valid);
    CHECK(queue.slots[0].state==RAW14_READY && length==355 && writer.frames==1);
    fail_at=SIZE_MAX;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_IO_ERROR);
    return 0;
}
