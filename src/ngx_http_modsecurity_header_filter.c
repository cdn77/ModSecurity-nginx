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

#include "ngx_http_modsecurity.h"


static ngx_int_t ngx_http_modsecurity_header_filter(ngx_http_request_t *r);


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


void
ngx_http_modsecurity_header_filter_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;
}


static ngx_int_t
ngx_http_modsecurity_header_filter(ngx_http_request_t *r)
{
    int                          rc;
    char                        *http_protocol;
    ngx_uint_t                   i;
    ngx_pool_t                  *old_pool;
    ngx_list_part_t             *part;
    ngx_table_elt_t             *header;
    ngx_http_modsecurity_ctx_t  *ctx;


/* XXX: if NOT_MODIFIED, do we need to process it at all?  see xslt_header_filter() */

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    if (ctx == NULL || ctx->intervention_triggered) {
        // nothing to be done
        return ngx_http_next_header_filter(r);
    }

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        msc_add_n_response_header(ctx->modsec_transaction,
                                  header[i].key.data, header[i].key.len,
                                  header[i].value.data, header[i].value.len);
    }

    if (r->http_version < NGX_HTTP_VERSION_10) {
        http_protocol = "HTTP/0.9";
    } else if (r->http_version < NGX_HTTP_VERSION_20) {
        http_protocol = "HTTP/1.1";
    } else {
        http_protocol = (char *)r->http_protocol.data;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_response_headers(ctx->modsec_transaction, r->headers_out.status,
                                 http_protocol);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    rc = ngx_http_modsecurity_process_intervention(r, ctx, 0);
    if (r->error_page) {
        return ngx_http_next_header_filter(r);
    }
    if (rc > 0) {
        ctx->intervention_triggered = 1;
        return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module, rc);
    }

    return ngx_http_next_header_filter(r);
}
