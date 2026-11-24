/* SPDX-License-Identifier: GPL-2.0-or-later
 * PC-only synthetic workload. Python intercepts the four bridge functions;
 * their fallback bodies fail if no host bridge is installed. Not camera code.
 */
#include "raw14_mlv.h"
#define WIDTH 64
#define HEIGHT 32
#define PITCH (WIDTH / 4 * 7)
#define BYTES (PITCH * HEIGHT)
static uint8_t capture[PITCH * (HEIGHT + 4)], storage[3][BYTES], info[160];
volatile uint32_t disk_demo_fault;
__attribute__((noipa)) size_t bridge_write(void *ctx, const void *data, size_t size)
{ (void)ctx; (void)data; (void)size; return SIZE_MAX; }
__attribute__((noipa)) int bridge_seek(void *ctx, uint64_t offset)
{ (void)ctx; (void)offset; return -1; }
__attribute__((noipa)) int bridge_truncate(void *ctx, uint64_t size)
{ (void)ctx; (void)size; return -1; }
__attribute__((noipa)) int bridge_flush(void *ctx)
{ (void)ctx; return -1; }
static int copy(void *ctx, void *dst, const void *src, size_t n)
{
    uint8_t *d=dst; const uint8_t *s=src; size_t i;
    (void)ctx; for(i=0;i<n;++i) d[i]=s[i]; return 0;
}
static void put32(unsigned offset, uint32_t value)
{ unsigned i; for(i=0;i<4;++i) info[offset+i]=(uint8_t)(value>>(8*i)); }
#define CHECK(c) do { if(!(c)) return __LINE__; } while(0)
int test_run(void)
{
    struct raw14_queue queue;
    struct raw14_engine engine={copy,0,0};
    struct raw14_frame source={capture,sizeof(capture),WIDTH,HEIGHT+4,PITCH,14}, buffers[3];
    struct raw14_mlv_writer writer;
    struct raw14_mlv_io io={0,bridge_write,bridge_seek,bridge_truncate,bridge_flush};
    struct raw14_mlv_config config={WIDTH,HEIGHT,24,1,12345,1000000,info};
    unsigned id,i;
    for(i=0;i<3;++i) buffers[i]=(struct raw14_frame){storage[i],BYTES,WIDTH,HEIGHT,PITCH,14};
    put32(0,1); put32(8,HEIGHT); put32(12,WIDTH); put32(16,PITCH);
    put32(20,BYTES); put32(24,14); put32(32,16383);
    put32(44,WIDTH); put32(48,HEIGHT); put32(60,HEIGHT); put32(64,WIDTH);
    put32(72,1); put32(76,0x02010100); put32(80,1);
    for(i=0;i<9;++i) { put32(84+i*8,i%4==0 ? 10000 : 0); put32(88+i*8,10000); }
    CHECK(raw14_queue_init(&queue,buffers,3,1)==RAW14_Q_OK);
    CHECK(raw14_mlv_begin(&writer,&queue,&io,&config)==RAW14_MLV_OK);
    if(disk_demo_fault) {
        for(id=0;id<2;++id) {
            for(i=0;i<sizeof(capture);++i) capture[i]=(uint8_t)(id*17+i);
            CHECK(raw14_queue_push(&queue,&engine,&source,2*(id%3),id,
                1000000+(uint64_t)id*1000000/24,0)==RAW14_Q_OK);
        }
        CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
        CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_IO_ERROR);
        CHECK(writer.frames==1 && queue.slots[1].state==RAW14_READY);
        CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK);
        return 0;
    }
    for(id=0;id<48;++id) {
        for(i=0;i<sizeof(capture);++i) capture[i]=(uint8_t)(id*17+i);
        CHECK(raw14_queue_push(&queue,&engine,&source,2*(id%3),id,
            1000000+(uint64_t)id*1000000/24,0)==(id%4==3 ? RAW14_Q_FULL : RAW14_Q_OK));
        if(id%4==3) {
            for(i=0;i<3;++i) CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_OK);
            CHECK(raw14_mlv_write_next(&writer)==RAW14_MLV_EMPTY);
        }
    }
    CHECK(queue.accepted_frames==36 && queue.overflow_frames==12);
    CHECK(raw14_mlv_finish(&writer)==RAW14_MLV_OK && writer.frames==36);
    return 0;
}
