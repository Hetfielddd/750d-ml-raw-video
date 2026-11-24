/* SPDX-License-Identifier: GPL-2.0-or-later
 * Wire layouts: upstream modules/raw_video/mlv_rec/mlv.h and src/raw.h,
 * Magic Lantern commit 142472e95054d73640f50789ac0fd66325499d82.
 * Explicit little-endian serialization; no native struct/pointer serialization.
 */
#include "raw14_mlv.h"
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { unsigned i; for (i=0;i<4;++i) p[i]=(uint8_t)(v>>(8*i)); }
static void put64(uint8_t *p, uint64_t v) { put32(p,(uint32_t)v); put32(p+4,(uint32_t)(v>>32)); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24; }
static void zero(uint8_t *p, unsigned n) { unsigned i; for(i=0;i<n;++i) p[i]=0; }
static void type(uint8_t *p, const char *s) { unsigned i; for(i=0;i<4;++i) p[i]=(uint8_t)s[i]; }

static int seek_to(struct raw14_mlv_writer *w, uint64_t offset)
{
    if (w->io.seek(w->io.ctx, offset)) return 0;
    w->offset = offset;
    return 1;
}
static int write_all(struct raw14_mlv_writer *w, const void *data, size_t bytes)
{
    const uint8_t *p = data;
    while (bytes) {
        size_t n = w->io.write(w->io.ctx, p, bytes);
        if (!n || n > bytes || n > UINT64_MAX - w->offset) return 0;
        w->offset += n;
        p += n;
        bytes -= n;
    }
    return 1;
}
static void file_header(struct raw14_mlv_writer *w, uint8_t *h)
{
    zero(h,52); type(h,"MLVI"); put32(h+4,52); type(h+8,"v2.0");
    put64(h+16,w->guid); put16(h+26,1); put32(h+28,w->flags);
    put16(h+32,1); put32(h+36,w->frames);
    put32(h+44,w->fps_num); put32(h+48,w->fps_den);
}
/* MLVI wire size is 52 bytes, not a generic timestamped block. */
static int write_file_header(struct raw14_mlv_writer *w)
{
    uint8_t header[52];
    file_header(w,header);
    return write_all(w,header,52);
}
static void fail_frame(struct raw14_mlv_writer *w, struct raw14_lease lease)
{
    int truncated = w->io.truncate(w->io.ctx,w->good_end) == 0;
    int positioned = seek_to(w,w->good_end);
    w->tail_valid = (unsigned)(truncated && positioned);
    w->flags |= 8;
    w->state = RAW14_MLV_FAILED;
    (void)raw14_queue_abort_write(w->queue,lease);
    w->busy = 0;
}

enum raw14_mlv_status raw14_mlv_begin(struct raw14_mlv_writer *w,
    struct raw14_queue *q, const struct raw14_mlv_io *io, const struct raw14_mlv_config *c)
{
    uint8_t rawi[180];
    uint32_t pitch, bytes;
    unsigned i;
    if (!w || !q || !q->session || q->count<2 || q->count>RAW14_QUEUE_MAX_SLOTS ||
        !io || !io->write || !io->seek || !io->truncate || !io->flush ||
        !c || !c->raw_info || !c->width || !c->height || c->width%4 || c->height%2 ||
        !c->fps_num || !c->fps_den || !c->guid) return RAW14_MLV_INVALID;
    if (q->busy) return RAW14_MLV_BUSY;
    for(i=0;i<q->count;++i) if(q->slots[i].state!=RAW14_FREE) return RAW14_MLV_BUSY;
    pitch = (uint32_t)c->width/4*7;
    if (c->height > INT32_MAX/pitch) return RAW14_MLV_INVALID;
    bytes = pitch*c->height;
    if (get32(c->raw_info)!=1 || get32(c->raw_info+8)!=c->height ||
        get32(c->raw_info+12)!=c->width || get32(c->raw_info+16)!=pitch ||
        get32(c->raw_info+20)!=bytes || get32(c->raw_info+24)!=14 ||
        get32(c->raw_info+28)>=get32(c->raw_info+32) || get32(c->raw_info+32)>16383 ||
        q->slots[0].frame.width_pixels!=c->width || q->slots[0].frame.height_rows!=c->height)
        return RAW14_MLV_INVALID;
    w->io=*io; w->queue=q; w->session=q->session; w->guid=c->guid; w->start_us=c->start_us;
    w->first_id=w->last_us=w->offset=w->good_end=0;
    w->fps_num=c->fps_num; w->fps_den=c->fps_den; w->frames=w->flags=0;
    w->frame_bytes=bytes; w->width=c->width; w->height=c->height;
    w->state=RAW14_MLV_FAILED; w->busy=1; w->tail_valid=w->initialized=0;
    zero(rawi,180); type(rawi,"RAWI"); put32(rawi+4,180);
    put16(rawi+16,c->width); put16(rawi+18,c->height);
    for(i=0;i<160;++i) rawi[20+i]=c->raw_info[i];
    put32(rawi+24,0); /* Never store a process/camera buffer pointer. */
    if (!seek_to(w,0) || !write_file_header(w) || !write_all(w,rawi,180)) {
        (void)w->io.truncate(w->io.ctx,0); w->busy=0;
        return RAW14_MLV_IO_ERROR;
    }
    w->good_end=w->offset; w->initialized=w->tail_valid=1;
    w->state=RAW14_MLV_OPEN; w->busy=0;
    return RAW14_MLV_OK;
}

enum raw14_mlv_status raw14_mlv_write_next(struct raw14_mlv_writer *w)
{
    struct raw14_write_view view;
    enum raw14_queue_status status;
    uint8_t header[32], pad[4]={0,0,0,0};
    uint32_t number, space;
    uint64_t relative;
    if (!w || !w->initialized || w->state!=RAW14_MLV_OPEN) return RAW14_MLV_INVALID;
    if (w->busy || w->queue->busy) return RAW14_MLV_BUSY;
    if (w->queue->session!=w->session) return RAW14_MLV_QUEUE_ERROR;
    w->busy=1;
    status=raw14_queue_take(w->queue,&view);
    if (status!=RAW14_Q_OK) {
        w->busy=0;
        return status==RAW14_Q_EMPTY ? RAW14_MLV_EMPTY :
               status==RAW14_Q_BUSY ? RAW14_MLV_BUSY : RAW14_MLV_QUEUE_ERROR;
    }
    if (w->frames==UINT32_MAX || view.bytes!=w->frame_bytes ||
        view.frame.width_pixels!=w->width || view.frame.height_rows!=w->height || view.source_y>UINT16_MAX ||
        view.timestamp_us<w->start_us || (w->frames && view.timestamp_us<w->last_us) ||
        (w->frames && (view.frame_id<w->first_id || view.frame_id-w->first_id>UINT32_MAX))) {
        fail_frame(w,view.lease); return RAW14_MLV_INVALID;
    }
    number=w->frames ? (uint32_t)(view.frame_id-w->first_id) : 0;
    relative=view.timestamp_us-w->start_us;
    space=(4-view.bytes%4)%4;
    zero(header,32); type(header,"VIDF"); put32(header+4,32+space+w->frame_bytes);
    put64(header+8,relative); put32(header+16,number); put32(header+28,space);
    put16(header+22,(uint16_t)view.source_y); put16(header+26,(uint16_t)view.source_y);
    if (!write_all(w,header,32) || !write_all(w,pad,space) ||
        !write_all(w,view.frame.data,view.bytes)) {
        fail_frame(w,view.lease); return RAW14_MLV_IO_ERROR;
    }
    if (raw14_queue_release_written(w->queue,view.lease)!=RAW14_Q_OK) {
        fail_frame(w,view.lease); return RAW14_MLV_QUEUE_ERROR;
    }
    if (!w->frames) w->first_id=view.frame_id;
    if (number!=w->frames) w->flags|=2;
    w->last_us=view.timestamp_us; ++w->frames;
    w->good_end=w->offset; w->busy=0;
    return RAW14_MLV_OK;
}

enum raw14_mlv_status raw14_mlv_finish(struct raw14_mlv_writer *w)
{
    unsigned i;
    if (!w || !w->initialized || w->state==RAW14_MLV_CLOSED) return RAW14_MLV_INVALID;
    if (w->busy || w->queue->busy) return RAW14_MLV_BUSY;
    if (w->queue->session!=w->session) return RAW14_MLV_QUEUE_ERROR;
    if (!w->tail_valid) return RAW14_MLV_IO_ERROR;
    if(w->state==RAW14_MLV_OPEN)
        for(i=0;i<w->queue->count;++i)
            if(w->queue->slots[i].state!=RAW14_FREE) return RAW14_MLV_BUSY;
    if(w->queue->overflow_frames) w->flags|=2;
    w->busy=1;
    if (!seek_to(w,0) || !write_file_header(w) || !seek_to(w,w->good_end) ||
        w->io.truncate(w->io.ctx,w->good_end) || w->io.flush(w->io.ctx)) {
        w->flags|=8; w->state=RAW14_MLV_FAILED; w->busy=0;
        return RAW14_MLV_IO_ERROR;
    }
    w->state=RAW14_MLV_CLOSED; w->busy=0;
    return RAW14_MLV_OK;
}
