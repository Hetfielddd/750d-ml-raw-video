/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_capture.h"
static uint8_t data[98], storage[2][56];
static struct raw14_queue queue;
static struct raw14_capture capture;
static struct raw14_engine engine;
static struct raw14_capture_config cfg;
static struct raw14_source_ops ops;
static struct raw14_frame buffers[2];
static uint64_t next_id, next_us, cookie;
static unsigned begins, ends, acquires, releases, held, copied_held, nested;
static int begin_error, end_error, release_error, acquire_result, malformed, copy_error;
static int begin(void *ctx) { (void)ctx; ++begins; return begin_error; }
static int end(void *ctx) { (void)ctx; ++ends; return held ? -1 : end_error; }
static int acquire(void *ctx,struct raw14_source_view *v)
{
    unsigned i; (void)ctx; ++acquires;
    if(acquire_result) return acquire_result;
    if(held) return -1;
    held=1; ++cookie;
    for(i=0;i<sizeof(data);++i) data[i]=(uint8_t)(next_id*17+i);
    *v=(struct raw14_source_view){{data,sizeof(data),8,7,14,14},next_id,next_us,cookie};
    if(malformed==1) v->frame.width_pixels=4;
    if(malformed==2) v->frame.bits_per_pixel=12;
    if(malformed==3) v->frame.capacity=5;
    if(malformed==4) v->frame.height_rows=6;
    if(malformed==5) v->cookie=0;
    return 0;
}
static int release(void *ctx,uint64_t token)
{
    unsigned i; (void)ctx; ++releases;
    nested=raw14_capture_poll(&capture)==RAW14_CAPTURE_BUSY &&
           raw14_capture_stop(&capture)==RAW14_CAPTURE_BUSY;
    if(release_error || !held || token!=cookie) return -1;
    held=0;
    for(i=0;i<sizeof(data);++i) data[i]=0xee; /* Source is immediately reusable. */
    return 0;
}
static int copy(void *ctx,void *dst,const void *src,size_t bytes)
{
    size_t i; uint8_t *d=dst; const uint8_t *s=src; (void)ctx;
    copied_held=held;
    if(copy_error) return -1;
    for(i=0;i<bytes;++i) d[i]=s[i];
    return 0;
}
static void setup(void)
{
    unsigned i;
    begins=ends=acquires=releases=held=copied_held=nested=0;
    begin_error=end_error=release_error=acquire_result=malformed=copy_error=0;
    next_id=next_us=cookie=0;
    for(i=0;i<2;++i) buffers[i]=(struct raw14_frame){storage[i],56,8,4,14,14};
    (void)raw14_queue_init(&queue,buffers,2,1);
    engine=(struct raw14_engine){copy,0,0};
    cfg=(struct raw14_capture_config){RAW14_SOURCE_PC_SYNTHETIC,8,7,2,14};
    ops=(struct raw14_source_ops){0,begin,end,acquire,release};
    (void)raw14_capture_init(&capture,&queue,&engine,&ops,&cfg);
}
#define CHECK(c) do { if(!(c)) return __LINE__; } while(0)
int test_run(void)
{
    struct raw14_write_view view;
    unsigned i;
    setup(); cfg.kind=RAW14_SOURCE_CANON_750D;
    CHECK(raw14_capture_init(&capture,&queue,&engine,&ops,&cfg)==RAW14_CAPTURE_UNVERIFIED);
    CHECK(!begins && !acquires && !ends && !releases);
    setup(); cfg.source_y=1;
    CHECK(raw14_capture_init(&capture,&queue,&engine,&ops,&cfg)==RAW14_CAPTURE_INVALID);
    setup(); cfg.width=UINT32_MAX-3;
    CHECK(raw14_capture_init(&capture,&queue,&engine,&ops,&cfg)==RAW14_CAPTURE_INVALID);
    setup(); CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_INVALID);
    CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK && begins==1);
    acquire_result=1;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_NO_FRAME && !releases);
    acquire_result=0;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_OK && copied_held && !held && nested);
    CHECK(data[28]==0xee && raw14_queue_take(&queue,&view)==RAW14_Q_OK);
    for(i=0;i<56;++i) CHECK(((uint8_t *)view.frame.data)[i]==(uint8_t)(28+i));
    CHECK(view.source_y==2 && view.frame_id==0);
    CHECK(raw14_queue_release_written(&queue,view.lease)==RAW14_Q_OK);
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK && ends==1);
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK && ends==1);
    CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_INVALID); /* Fresh session required. */

    setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK);
    for(i=0;i<3;++i) {
        next_id=i; next_us=i*41667;
        CHECK(raw14_capture_poll(&capture)==(i==2 ? RAW14_CAPTURE_DROPPED : RAW14_CAPTURE_OK));
    }
    CHECK(releases==3 && queue.accepted_frames==2 && queue.overflow_frames==1 && !held);
    CHECK(raw14_queue_take(&queue,&view)==RAW14_Q_OK);
    CHECK(raw14_queue_release_written(&queue,view.lease)==RAW14_Q_OK);
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_INVALID); /* Replayed dropped ID. */
    CHECK(capture.state==RAW14_CAPTURE_FAILED && releases==4);
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK);

    for(i=1;i<=4;++i) {
        setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK); malformed=(int)i;
        CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_INVALID && releases==1 && !held);
        CHECK(!queue.accepted_frames && raw14_capture_stop(&capture)==RAW14_CAPTURE_OK);
    }
    setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK); copy_error=1;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_COPY_ERROR && releases==1 && !held);
    CHECK(!queue.accepted_frames && raw14_capture_stop(&capture)==RAW14_CAPTURE_OK);
    setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK); acquire_result=-1;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_SOURCE_ERROR && !releases);
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK);
    setup(); begin_error=end_error=1;
    CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_SOURCE_ERROR && begins==1 && ends==1);
    CHECK(capture.state==RAW14_CAPTURE_FAILED && capture.requested);
    end_error=0;
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK && ends==2);
    setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK); release_error=1;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_SOURCE_ERROR && held && capture.leased);
    CHECK(queue.accepted_frames==1); /* Copy succeeded before release failed. */
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_SOURCE_ERROR && !ends);
    release_error=0;
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK && !held && ends==1);
    setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK);
    ++queue.session;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_SESSION_ERROR && !acquires);
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK);
    setup(); CHECK(raw14_capture_start(&capture)==RAW14_CAPTURE_OK); engine.busy=1;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_BUSY && !acquires);
    engine.busy=0; next_us=10;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_OK);
    next_id=1; next_us=9;
    CHECK(raw14_capture_poll(&capture)==RAW14_CAPTURE_INVALID && !held);
    CHECK(raw14_capture_stop(&capture)==RAW14_CAPTURE_OK);
    return 0;
}
