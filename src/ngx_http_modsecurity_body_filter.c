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

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

/* XXX: check behaviour on few body filters installed */
void
ngx_http_modsecurity_body_filter_init(void)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;
}

ngx_int_t
ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *chain = in;

    ngx_http_modsecurity_ctx_t  *ctx;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->intervention_triggered) {
        return ngx_http_next_body_filter(r, in);
    }

    int is_request_processed = 0;
    for (; chain != NULL; chain = chain->next)
    {
        u_char *data = chain->buf->pos;
        int ret;

        msc_append_response_body(ctx->modsec_transaction, data, chain->buf->last - data);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
        if (ret > 0) {
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity_module, ret);
        }

/* XXX: chain->buf->last_buf || chain->buf->last_in_chain */
        is_request_processed = chain->buf->last_buf;

        if (is_request_processed) {
            ngx_pool_t *old_pool;

            old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
            msc_process_response_body(ctx->modsec_transaction);
            ngx_http_modsecurity_pcre_malloc_done(old_pool);

/* XXX: I don't get how body from modsec being transferred to nginx's buffer.  If so - after adjusting of nginx's
   XXX: body we can proceed to adjust body size (content-length).  see xslt_body_filter() for example */
            ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
            if (ret > 0) {
                return ret;
            }
            else if (ret < 0) {
                return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity_module, NGX_HTTP_INTERNAL_SERVER_ERROR);

            }
        }
    }
    if (!is_request_processed)
    {
        dd("buffer was not fully loaded! ctx: %p", ctx);
    }

/* XXX: xflt_filter() -- return NGX_OK here */
    return ngx_http_next_body_filter(r, in);
}
