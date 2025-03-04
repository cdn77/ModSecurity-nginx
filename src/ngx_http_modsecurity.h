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


#ifndef _NGX_HTTP_MODSECURITY_COMMON_H_INCLUDED_
#define _NGX_HTTP_MODSECURITY_COMMON_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules_set.h>


#define MODSECURITY_NGINX_WHOAMI "ModSecurity-nginx v" NGINX_VERSION


typedef struct {
    Transaction                    *modsec_transaction;

    unsigned                        logged:1;
    unsigned                        intervention_triggered:1;
    unsigned                        log_intervention:1;
} ngx_http_modsecurity_ctx_t;


typedef struct {
    ModSecurity                     *modsec;
    ngx_str_t                       *server_name;
} ngx_http_modsecurity_server_t;


typedef struct {
    ngx_http_modsecurity_server_t    server;
    /* RulesSet or Rules */
    void                            *rules_set;
    ngx_flag_t                       enable;
    ngx_http_complex_value_t        *transaction_id;
} ngx_http_modsecurity_conf_t;


extern ngx_module_t ngx_http_modsecurity_module;

/* ngx_http_modsecurity_module.c */
ngx_int_t ngx_http_modsecurity_process_intervention(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t *ctx, ngx_int_t early_log);
ngx_int_t ngx_http_modsecurity_create_ctx(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t **ctx);
char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p);
#if (NGX_PCRE2)
#define ngx_http_modsecurity_pcre_malloc_init(x) NULL
#define ngx_http_modsecurity_pcre_malloc_done(x) (void)x
#else
ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool);
void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *old_pool);
#endif

/* ngx_http_modsecurity_header_filter.c */
void ngx_http_modsecurity_header_filter_init(void);

/* ngx_http_modsecurity_log.c */
void ngx_http_modsecurity_log(void *log, const void* data);
ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r);

void ngx_http_modsecurity_request_body_filter_init(void);

/* ngx_http_modsecurity_rewrite.c */
ngx_int_t ngx_http_modsecurity_rewrite_handler(ngx_http_request_t *r);


#endif /* _NGX_HTTP_MODSECURITY_COMMON_H_INCLUDED_ */
