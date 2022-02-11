/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_modsecurity_common.h"


static ngx_int_t ngx_http_modsecurity_request_body_filter(
   ngx_http_request_t *r, ngx_chain_t *in);


static ngx_http_request_body_filter_pt   ngx_http_next_request_body_filter;


void
ngx_http_modsecurity_request_body_filter_init(void)
{
    ngx_http_next_request_body_filter = ngx_http_top_request_body_filter;
    ngx_http_top_request_body_filter = ngx_http_modsecurity_request_body_filter;
}


static ngx_int_t
ngx_http_modsecurity_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                    rc, rcms;
    ngx_pool_t                  *old_pool;
    ngx_uint_t                   last;
    ngx_http_modsecurity_ctx_t  *ctx;

    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (ctx == NULL) {
        // module is off
        return ngx_http_next_request_body_filter(r, in);
    }

    rc = ngx_http_next_request_body_filter(r, in);

    last = 0;

    while (in) {
        if (in->buf->last_buf) {
            last = 1;
        }

        msc_append_request_body(ctx->modsec_transaction,
                                in->buf->pos,
                                in->buf->last - in->buf->pos);

        /**
         * ModSecurity may perform stream inspection on this buffer,
         * it may ask for a intervention in consequence of that.
         *
         */
        rcms = ngx_http_modsecurity_process_intervention(
                                                 ctx->modsec_transaction, r, 0);
        if (rcms > 0) {
            return rcms;
        }

        in = in->next;
    }

    if (last) {
        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_request_body(ctx->modsec_transaction);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);

        rcms = ngx_http_modsecurity_process_intervention(
                                                 ctx->modsec_transaction, r, 0);
        if (rcms > 0) {
            return rcms;
        }
    }

    return rc;
}

