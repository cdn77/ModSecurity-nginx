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


ngx_int_t ngx_http_modsecurity_process_connection(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx);
ngx_int_t ngx_http_modsecurity_process_url(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx);
ngx_int_t ngx_http_modsecurity_process_req_header(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx);
ngx_int_t ngx_http_modsecurity_process_empty_req_body(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx);


ngx_int_t
ngx_http_modsecurity_rewrite_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_modsecurity_ctx_t   *ctx;
    ngx_http_modsecurity_conf_t  *mcf;

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);

    if (!mcf->enable) {
        dd("ModSecurity not enabled... returning");
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx != NULL) {
        dd("already processed before");
        return NGX_DECLINED;
    }

    rc = ngx_http_modsecurity_create_ctx(r, &ctx);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_modsecurity_process_connection(r, ctx);
    if (rc > 0) {
        ctx->intervention_triggered = 1;
        return rc;
    }

    rc = ngx_http_modsecurity_process_url(r, ctx);
    if (rc > 0) {
        ctx->intervention_triggered = 1;
        return rc;
    }

    rc = ngx_http_modsecurity_process_req_header(r, ctx);

    if (r->error_page) {
        return NGX_DECLINED;
    }
    if (rc > 0) {
        ctx->intervention_triggered = 1;
        return rc;
    }

    rc = ngx_http_modsecurity_process_empty_req_body(r, ctx);
    if (rc > 0) {
        return rc;
    }

    return NGX_DECLINED;
}


ngx_int_t
ngx_http_modsecurity_process_connection(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx)
{
    in_port_t          client_port, server_port;
    ngx_int_t          rc;
    ngx_str_t          client_addr, server_addr;
    ngx_pool_t        *old_pool;
    ngx_connection_t  *c;
    u_char             addr[NGX_SOCKADDR_STRLEN + 1];

    c = r->connection;

    client_addr = c->addr_text;
    client_port = ngx_inet_get_port(c->sockaddr);

    if (client_addr.len < c->listening->addr_text_max_len) {
        client_addr.data[client_addr.len] = 0;
    } else {
        client_addr.data = (u_char *)ngx_str_to_char(client_addr, r->pool);
    }

    // fill c->local_sockaddr
    ngx_connection_local_sockaddr(c, NULL, 0);

    server_addr.data = addr;
    server_addr.len = NGX_SOCKADDR_STRLEN;

    server_addr.len = ngx_sock_ntop(c->local_sockaddr, c->local_socklen,
                                    server_addr.data, server_addr.len, 0);
    server_addr.data[server_addr.len] = 0;
    server_port = ngx_inet_get_port(c->local_sockaddr);

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    rc = msc_process_connection(ctx->modsec_transaction,
                                (char *)client_addr.data, client_port,
                                (char *)server_addr.data, server_port);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    if (rc != 1){
        dd("Was not able to extract connection information.");
    }
    /**
     *
     * FIXME: Check how we can finalize a request without crash nginx.
     *
     * I don't think nginx is expecting to finalize a request at that
     * point as it seems that it clean the ngx_http_request_t information
     * and try to use it later.
     *
     */
    dd("Processing intervention with the connection information filled in");
    return ngx_http_modsecurity_process_intervention(r, ctx, 1);
}


ngx_int_t
ngx_http_modsecurity_process_url(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_pool_t  *old_pool;
    const char  *http_version, *n_uri, *n_method;

    switch (r->http_version) {
        case NGX_HTTP_VERSION_9 :
            http_version = "0.9";
            break;
        case NGX_HTTP_VERSION_10 :
            http_version = "1.0";
            break;
        case NGX_HTTP_VERSION_11 :
            http_version = "1.1";
            break;
        case NGX_HTTP_VERSION_20 :
            http_version = "2.0";
            break;
        default :
            http_version = ngx_str_to_char(r->http_protocol, r->pool);
            if (http_version == (char*)-1) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if ((http_version != NULL) && (strlen(http_version) > 5) && (!strncmp("HTTP/", http_version, 5))) {
                http_version += 5;
            } else {
                http_version = "1.0";
            }
            break;
    }

    n_uri = ngx_str_to_char(r->unparsed_uri, r->pool);
    n_method = ngx_str_to_char(r->method_name, r->pool);
    if (n_uri == (char*)-1 || n_method == (char*)-1) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (n_uri == NULL) {
        dd("uri is of length zero");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_uri(ctx->modsec_transaction, n_uri, n_method, http_version);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    dd("Processing intervention with the transaction information filled in (uri, method and version)");
    return ngx_http_modsecurity_process_intervention(r, ctx, 1);
}


ngx_int_t
ngx_http_modsecurity_process_req_header(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_uint_t        i;
    ngx_pool_t       *old_pool;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    part = &r->headers_in.headers.part;
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

        msc_add_n_request_header(ctx->modsec_transaction,
                                 header[i].key.data, header[i].key.len,
                                 header[i].value.data, header[i].value.len);
    }

    /**
     * Since ModSecurity already knew about all headers, i guess it is safe
     * to process this information.
     */

    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_request_headers(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    dd("Processing intervention with the request headers information filled in");

    return ngx_http_modsecurity_process_intervention(r, ctx, 1);
}


ngx_int_t
ngx_http_modsecurity_process_empty_req_body(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx)
{
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked) {
        msc_process_request_body(ctx->modsec_transaction);
        return ngx_http_modsecurity_process_intervention(r, ctx, 1);
    }

    return NGX_OK;
}
