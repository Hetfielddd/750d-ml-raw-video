/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_mlv.h"
uint8_t mlv_test_output[4096];
uint32_t mlv_test_size;
static uint8_t capture[112], storage[2][56], info[160];
static struct raw14_queue queue;
static struct raw14_engine engine;
static struct raw14_frame source, buffers[2];
static struct raw14_mlv_writer writer;
static struct raw14_mlv_config config;
static size_t pos, length, fail_after, chunk;
static unsigned bad_count, bad_seek, bad_truncate, bad_flush, observe;
static unsigned saw_writing, calls;
static enum raw14_mlv_status nested;

static void put32(uint8_t *p,uint32_t v) { unsigned i; for(i=0;i<4;i++) p[i]=(uint8_t)(v>>(i*8)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static size_t write_file(void *ctx,const void *data,size_t bytes)
{
    const uint8_t *from=data;
    size_t n=bytes,i;
    (void)ctx; ++calls;
    if(observe) {
        unsigned s;
        for(s=0;s<queue.count;s++) if(queue.slots[s].state==RAW14_WRITING) saw_writing=1;
        nested=raw14_mlv_write_next(&writer);
    }
    if(bad_count) return bytes+1;
    if(pos>=fail_after) return 0;
    if(n>chunk) n=chunk;
    if(n>fail_after-pos) n=fail_after-pos;
    if(n>sizeof(mlv_test_output)-pos) return SIZE_MAX;
    for(i=0;i<n;i++) mlv_test_output[pos+i]=from[i];
    pos+=n;
    if(pos>length) length=pos;
    return n;
}
static int seek_file(void *ctx,uint64_t offset)
{
    (void)ctx;
    if(bad_seek || offset>sizeof(mlv_test_output)) return -1;
    pos=(size_t)offset; return 0;
}
static int truncate_file(void *ctx,uint64_t size)
{
    (void)ctx;
    if(bad_truncate || size>sizeof(mlv_test_output)) return -1;
    length=(size_t)size; return 0;
}
static int flush_file(void *ctx) { (void)ctx; return bad_flush ? -1 : 0; }
static int copy(void *ctx,void *dst,const void *src,size_t bytes)
{
    uint8_t *d=dst; const uint8_t *s=src; size_t i;
    (void)ctx; for(i=0;i<bytes;i++) d[i]=s[i]; return 0;
}
static void setup(void)
{
    unsigned i;
    for(i=0;i<sizeof(mlv_test_output);i++) mlv_test_output[i]=0;
    for(i=0;i<sizeof(capture);i++) capture[i]=(uint8_t)(i+1);
    for(i=0;i<160;i++) info[i]=0;
    put32(info,1); put32(info+4,0xdeadbeef);
    put32(info+8,4); put32(info+12,8); put32(info+16,14);
    put32(info+20,56); put32(info+24,14); put32(info+32,16383);
    put32(info+44,8); put32(info+48,4); put32(info+60,4); put32(info+64,8);
    put32(info+72,1); put32(info+76,0x02010100); put32(info+80,1);
    for(i=0;i<9;i++) { put32(info+84+i*8,(i%4==0)?10000:0); put32(info+88+i*8,10000); }
    source=(struct raw14_frame){capture,112,8,8,14,14};
    for(i=0;i<2;i++) buffers[i]=(struct raw14_frame){storage[i],56,8,4,14,14};
    (void)raw14_queue_init(&queue,buffers,2,123);
    engine=(struct raw14_engine){copy,0,0};
    config=(struct raw14_mlv_config){8,4,24,1,UINT64_C(0x1122334455667788),1000000,info};
    pos=length=0; fail_after=SIZE_MAX; chunk=7;
    bad_count=bad_seek=bad_truncate=bad_flush=observe=saw_writing=calls=0;
    nested=RAW14_MLV_INVALID; mlv_test_size=0;
}
static enum raw14_mlv_status begin(void)
{
    struct raw14_mlv_io io={0,write_file,seek_file,truncate_file,flush_file};
    return raw14_mlv_begin(&writer,&queue,&io,&config);
}
#define CHECK(c) do { if(!(c)) return __LINE__; } while(0)
int test_run(void)
{
    struct raw14_write_view view;
    unsigned i;
    setup(); CHECK(begin()==RAW14_MLV_OK);
    CHECK(length==232 && get32(mlv_test_output+4)==52 && get32(mlv_test_output+56)==180);
    CHECK(get32(mlv_test_output+76)==0); /* Cleared raw_info buffer pointer. */
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_EMPTY);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,10,1000000,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_BUSY);
    observe=1;
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
    CHECK(saw_writing && nested==RAW14_MLV_BUSY && queue.slots[0].state==RAW14_FREE);
    observe=0;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK);
    CHECK(get32(mlv_test_output+36)==1 && length==320);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_INVALID);

    setup(); CHECK(begin()==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,10,1000000,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,11,1041667,0)==RAW14_Q_OK);
    fail_after=writer.good_end+35; /* Frame header, then three payload bytes. */
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_IO_ERROR);
    CHECK(length==320 && writer.frames==1 && writer.state==RAW14_MLV_FAILED);
    CHECK(raw14_queue_take(&queue,&view)==RAW14_Q_OK && view.frame_id==11);
    CHECK(raw14_queue_abort_write(&queue,view.lease)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_INVALID);
    fail_after=SIZE_MAX;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK);
    CHECK(get32(mlv_test_output+36)==1 && (get32(mlv_test_output+28)&8));

    setup(); CHECK(begin()==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,1,1000000,0)==RAW14_Q_OK);
    bad_count=1;
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_IO_ERROR);
    CHECK(length==232 && writer.frames==0);
    setup(); CHECK(begin()==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,1,1000000,0)==RAW14_Q_OK);
    fail_after=235; bad_truncate=1;
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_IO_ERROR);
    CHECK(!writer.tail_valid && raw14_mlv_finish(&writer)==RAW14_MLV_IO_ERROR);
    setup(); fail_after=3;
    CHECK(begin()==RAW14_MLV_IO_ERROR && length==0);
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_INVALID);
    setup(); put32(info+24,12);
    CHECK(begin()==RAW14_MLV_INVALID && calls==0);
    setup(); CHECK(begin()==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,1,999999,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_INVALID && length==232);
    setup(); CHECK(begin()==RAW14_MLV_OK); bad_flush=1;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_IO_ERROR);
    bad_flush=0;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK && (get32(mlv_test_output+28)&8));
    setup(); CHECK(begin()==RAW14_MLV_OK); bad_seek=1;
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_IO_ERROR);

    /* Leave a complete synthetic 2-frame MLV for independent Python parsing. */
    setup(); CHECK(begin()==RAW14_MLV_OK);
    CHECK(raw14_queue_push(&queue,&engine,&source,2,100,1000000,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
    for(i=0;i<sizeof(capture);i++) capture[i]=(uint8_t)(255-i);
    CHECK(raw14_queue_push(&queue,&engine,&source,0,102,1083333,0)==RAW14_Q_OK);
    CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK);
    CHECK(get32(mlv_test_output+36)==2 && get32(mlv_test_output+28)==2 && length==408);
    mlv_test_size=(uint32_t)length;
    return 0;
}
