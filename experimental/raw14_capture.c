/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "raw14_capture.h"

enum raw14_capture_status raw14_capture_init(struct raw14_capture *c,
    struct raw14_queue *q, struct raw14_engine *e, const struct raw14_source_ops *s,
    const struct raw14_capture_config *cfg)
{
    unsigned i;
    if(!c || !q || !e || !s || !cfg) return RAW14_CAPTURE_INVALID;
    if(cfg->kind!=RAW14_SOURCE_PC_SYNTHETIC) return RAW14_CAPTURE_UNVERIFIED;
    if(!s->begin || !s->end || !s->acquire || !s->release || !e->copy || !q->session ||
        q->count<2 || q->count>RAW14_QUEUE_MAX_SLOTS || !cfg->width || cfg->width%4 ||
        !cfg->source_height || cfg->source_y%2 || cfg->width/4>SIZE_MAX/7 ||
        cfg->pitch!=(size_t)(cfg->width/4)*7 || cfg->source_y>cfg->source_height ||
        cfg->source_height>SIZE_MAX/cfg->pitch) return RAW14_CAPTURE_INVALID;
    for(i=0;i<q->count;++i)
        if(q->slots[i].frame.width_pixels!=cfg->width ||
            q->slots[i].frame.height_rows>cfg->source_height-cfg->source_y)
            return RAW14_CAPTURE_INVALID;
    c->source=*s; c->config=*cfg; c->queue=q; c->engine=e; c->session=q->session;
    c->cookie=c->last_id=c->last_us=0;
    c->state=RAW14_CAPTURE_IDLE; c->busy=c->requested=c->leased=c->seen=0;
    return RAW14_CAPTURE_OK;
}

enum raw14_capture_status raw14_capture_start(struct raw14_capture *c)
{
    unsigned i;
    if(!c) return RAW14_CAPTURE_INVALID;
    if(c->busy) return RAW14_CAPTURE_BUSY;
    if(c->state!=RAW14_CAPTURE_IDLE) return RAW14_CAPTURE_INVALID;
    if(c->queue->busy || c->engine->busy) return RAW14_CAPTURE_BUSY;
    if(c->queue->session!=c->session) return RAW14_CAPTURE_SESSION_ERROR;
    /* One capture run per fresh queue session: source IDs must not restart
     * inside a recording, even when the queue currently happens to be empty. */
    if(c->seen || c->queue->has_frame_id || c->queue->accepted_frames ||
        c->queue->overflow_frames || c->queue->rejected_frames) return RAW14_CAPTURE_INVALID;
    for(i=0;i<c->queue->count;++i)
        if(c->queue->slots[i].state!=RAW14_FREE) return RAW14_CAPTURE_BUSY;
    c->busy=c->requested=1;
    if(c->source.begin(c->source.ctx)) {
        c->state=RAW14_CAPTURE_FAILED;
        if(!c->source.end(c->source.ctx)) { c->requested=0; c->state=RAW14_CAPTURE_IDLE; }
        c->busy=0;
        return RAW14_CAPTURE_SOURCE_ERROR;
    }
    c->state=RAW14_CAPTURE_ACTIVE; c->busy=0;
    return RAW14_CAPTURE_OK;
}

enum raw14_capture_status raw14_capture_poll(struct raw14_capture *c)
{
    struct raw14_source_view v;
    volatile uint8_t *clear=(volatile uint8_t *)&v;
    size_t i;
    enum raw14_capture_status result;
    enum raw14_queue_status queued;
    int acquired;
    if(!c) return RAW14_CAPTURE_INVALID;
    if(c->busy) return RAW14_CAPTURE_BUSY;
    if(c->state!=RAW14_CAPTURE_ACTIVE) return RAW14_CAPTURE_INVALID;
    if(c->queue->busy || c->engine->busy) return RAW14_CAPTURE_BUSY;
    if(c->queue->session!=c->session) {
        c->state=RAW14_CAPTURE_FAILED; return RAW14_CAPTURE_SESSION_ERROR;
    }
    c->busy=1;
    /* Explicit volatile stores keep this freestanding (no implicit memset). */
    for(i=0;i<sizeof(v);++i) clear[i]=0;
    acquired=c->source.acquire(c->source.ctx,&v);
    if(acquired) {
        c->busy=0;
        if(acquired==1) return RAW14_CAPTURE_NO_FRAME;
        c->state=RAW14_CAPTURE_FAILED;
        return RAW14_CAPTURE_SOURCE_ERROR;
    }
    c->leased=1; c->cookie=v.cookie;
    result=RAW14_CAPTURE_INVALID;
    if(v.cookie && raw14_validate_frame(&v.frame)==RAW14_OK &&
        v.frame.width_pixels==c->config.width && v.frame.height_rows==c->config.source_height &&
        v.frame.pitch_bytes==c->config.pitch &&
        (!c->seen || (v.frame_id>c->last_id && v.timestamp_us>=c->last_us))) {
        /* Track every valid source frame, including drops due to full queue. */
        c->seen=1; c->last_id=v.frame_id; c->last_us=v.timestamp_us;
        queued=raw14_queue_push(c->queue,c->engine,&v.frame,c->config.source_y,
                               v.frame_id,v.timestamp_us,0);
        result=queued==RAW14_Q_OK ? RAW14_CAPTURE_OK :
               queued==RAW14_Q_FULL ? RAW14_CAPTURE_DROPPED : RAW14_CAPTURE_COPY_ERROR;
    }
    if(c->source.release(c->source.ctx,c->cookie)) result=RAW14_CAPTURE_SOURCE_ERROR;
    else { c->leased=0; c->cookie=0; }
    if(result!=RAW14_CAPTURE_OK && result!=RAW14_CAPTURE_DROPPED) c->state=RAW14_CAPTURE_FAILED;
    c->busy=0;
    return result;
}

enum raw14_capture_status raw14_capture_stop(struct raw14_capture *c)
{
    if(!c) return RAW14_CAPTURE_INVALID;
    if(c->busy) return RAW14_CAPTURE_BUSY;
    if(c->state!=RAW14_CAPTURE_IDLE && c->state!=RAW14_CAPTURE_ACTIVE &&
        c->state!=RAW14_CAPTURE_FAILED) return RAW14_CAPTURE_INVALID;
    c->busy=1;
    if(c->leased) {
        if(c->source.release(c->source.ctx,c->cookie)) goto failed;
        c->leased=0; c->cookie=0;
    }
    if(c->requested) {
        if(c->source.end(c->source.ctx)) goto failed;
        c->requested=0;
    }
    c->state=RAW14_CAPTURE_IDLE; c->busy=0;
    return RAW14_CAPTURE_OK;
failed:
    c->state=RAW14_CAPTURE_FAILED; c->busy=0;
    return RAW14_CAPTURE_SOURCE_ERROR;
}
