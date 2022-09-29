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
#include "stdio.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define WITH_SAFE_PCRE_FREE(h)  {                                              \
    void  (*old_free)(void *ptr);                                              \
                                                                               \
    old_free = pcre_free;                                                      \
    pcre_free = ngx_http_modsec_pcre_noop;                                     \
    h                                                                          \
    pcre_free = old_free;                                                      \
}


static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf);
static void *ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_modsecurity_create_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_modsecurity_cleanup_instance(void *data);
static void ngx_http_modsecurity_cleanup_rules(void *data);


/*
 * PCRE malloc/free workaround, based on
 * https://github.com/openresty/lua-nginx-module/blob/master/src/ngx_http_lua_pcrefix.c
 */

#if !(NGX_PCRE2)
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
static ngx_pool_t *ngx_http_modsec_pcre_pool = NULL;


static void
ngx_http_modsec_pcre_noop(void *ptr)
{
}


static void *
ngx_http_modsec_pcre_malloc(size_t size)
{
    if (ngx_http_modsec_pcre_pool) {
        return ngx_palloc(ngx_http_modsec_pcre_pool, size);
    }

    fprintf(stderr, "error: modsec pcre malloc failed due to empty pcre pool");

    return NULL;
}

static void
ngx_http_modsec_pcre_free(void *ptr)
{
    if (ngx_http_modsec_pcre_pool) {
        ngx_pfree(ngx_http_modsec_pcre_pool, ptr);
        return;
    }

#if 0
    /* this may happen when called from cleanup handlers */
    fprintf(stderr, "error: modsec pcre free failed due to empty pcre pool");
#endif

    return;
}

ngx_pool_t *
ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    ngx_pool_t  *old_pool;

    if (pcre_malloc != ngx_http_modsec_pcre_malloc) {
        ngx_http_modsec_pcre_pool = pool;

        old_pcre_malloc = pcre_malloc;
        old_pcre_free = pcre_free;

        pcre_malloc = ngx_http_modsec_pcre_malloc;
        pcre_free = ngx_http_modsec_pcre_free;

        return NULL;
    }

    old_pool = ngx_http_modsec_pcre_pool;
    ngx_http_modsec_pcre_pool = pool;

    return old_pool;
}

void
ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *old_pool)
{
    ngx_http_modsec_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}
#endif

/*
 * ngx_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones before passing to ModSecurity
 */
char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    char *str = NULL;

    str = ngx_pnalloc(p, a.len+1);
    if (str == NULL) {
        return NULL;
    }

    if (a.len > 0) {
        ngx_memcpy(str, a.data, a.len);
    }
    str[a.len] = '\0';

    return str;
}


ngx_int_t
ngx_http_modsecurity_process_intervention(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_int_t early_log)
{
    ModSecurityIntervention intervention = {
        .status = 200,
        .url = NULL,
        .log = NULL,
        .disruptive = 0,
    };

    dd("processing intervention");

    if (msc_intervention(ctx->modsec_transaction, &intervention) == 0) {
        dd("nothing to do");
        return NGX_OK;
    }

    if (intervention.log != NULL && ctx->log_intervention) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%s", intervention.log);
        free(intervention.log);
    }

    if (intervention.url != NULL)
    {
        dd("intervention -- redirecting to: %s with status code: %d", intervention.url, intervention.status);

        if (r->header_sent)
        {
            dd("Headers are already sent. Cannot perform the redirection at this point.");
            return NGX_ERROR;
        }

        /**
         * Not sure if it sane to do this indepent of the phase
         * but, here we go...
         *
         * This code cames from: http/ngx_http_special_response.c
         * function: ngx_http_send_error_page
         * src/http/ngx_http_core_module.c
         * From src/http/ngx_http_core_module.c (line 1910) i learnt
         * that location->hash should be set to 1.
         *
         */
        ngx_http_clear_location(r);
        ngx_str_t a = ngx_string("");

        a.data = (unsigned char *)intervention.url;
        a.len = strlen(intervention.url);

        ngx_table_elt_t *location = NULL;
        location = ngx_list_push(&r->headers_out.headers);
        ngx_str_set(&location->key, "Location");
        location->value = a;
        r->headers_out.location = location;
        r->headers_out.location->hash = 1;

        return intervention.status;
    }

    if (intervention.status != 200)
    {
        /**
         * FIXME: this will bring proper response code to audit log in case
         * when e.g. error_page redirect was triggered, but there still won't be another
         * required pieces like response headers etc.
         *
         */
        msc_update_status_code(ctx->modsec_transaction, intervention.status);

        if (early_log) {
            dd("intervention -- calling log handler manually with code: %d", intervention.status);
            ngx_http_modsecurity_log_handler(r);
            ctx->logged = 1;
	}

        if (r->header_sent)
        {
            dd("Headers are already sent. Cannot perform the redirection at this point.");
            return NGX_ERROR;
        }
        dd("intervention -- returning code: %d", intervention.status);
        return intervention.status;
    }

    return NGX_OK;
}


static void
ngx_http_modsecurity_cleanup(void *data)
{
    ngx_http_modsecurity_ctx_t *ctx = data;

    msc_transaction_cleanup(ctx->modsec_transaction);
}


ngx_int_t
ngx_http_modsecurity_create_ctx(ngx_http_request_t *r,
        ngx_http_modsecurity_ctx_t **ctx)
{
    ngx_str_t                          tid;
    ngx_pool_cleanup_t                *cln;
    ngx_http_modsecurity_conf_t       *mcf;
    ngx_http_modsecurity_main_conf_t  *mmcf;

    if (r != r->main || r->internal) {
        return NGX_DECLINED;
    }

    /*
    if (r->method != NGX_HTTP_GET &&
        r->method != NGX_HTTP_POST && r->method != NGX_HTTP_HEAD) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NGX_DECLINED;
    }
    */

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_modsecurity_module);
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);

    if (mcf->rules_set == NULL) {
        // no rules, nothing to do
        return NGX_DECLINED;
    }

    ngx_str_null(&tid);
    if (mcf->transaction_id) {
        if (ngx_http_complex_value(r, mcf->transaction_id, &tid) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    if (*ctx == NULL) {
        return NGX_ERROR;
    }

    (*ctx)->log_intervention = 0;

    if (tid.len > 0) {
        (*ctx)->modsec_transaction =
            msc_new_transaction_with_id(mmcf->modsec, mcf->rules_set,
                                        (char *) tid.data, r);
    } else {
        (*ctx)->modsec_transaction =
            msc_new_transaction(mmcf->modsec, mcf->rules_set, r);
    }

    dd("transaction created");

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    if (cln == NULL) {
        return NGX_ERROR;
    }
    cln->handler = ngx_http_modsecurity_cleanup;
    cln->data = *ctx;

    ngx_http_set_ctx(r, *ctx, ngx_http_modsecurity_module);

    return NGX_OK;
}


static char *
ngx_http_modsecurity_set_rules(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_modsecurity_conf_t *mcf = conf;

    int                  rc;
    ngx_str_t           *value;
    const char          *error;
    ngx_pool_t          *old_pool;
    ngx_pool_cleanup_t  *cln;

    value = cf->args->elts;

    if (mcf->rules_set == NULL) {
        mcf->rules_set = msc_create_rules_set();

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_http_modsecurity_cleanup_rules;
        cln->data = mcf;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    rc = msc_rules_add(mcf->rules_set, (char *)value[1].data, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (rc < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Failed to load the rules: \"%V\": %s",
                           &value[1], error);
        free((char *)error);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_modsecurity_set_rules_file(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    ngx_http_modsecurity_conf_t *mcf = conf;

    int                  rc;
    ngx_str_t           *value;
    const char          *error;
    ngx_pool_t          *old_pool;
    ngx_pool_cleanup_t  *cln;

    value = cf->args->elts;

    if (mcf->rules_set == NULL) {
        mcf->rules_set = msc_create_rules_set();

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_http_modsecurity_cleanup_rules;
        cln->data = mcf;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    rc = msc_rules_add_file(mcf->rules_set, (char *)value[1].data, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (rc < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Failed to load the rules from file %V: %s",
                           &value[1], error);
        free((char *)error);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_modsecurity_set_rules_remote(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf)
{
    ngx_http_modsecurity_conf_t *mcf = conf;

    int                  rc;
    ngx_str_t           *value;
    const char          *error;
    ngx_pool_t          *old_pool;
    ngx_pool_cleanup_t  *cln;

    value = cf->args->elts;

    if (mcf->rules_set == NULL) {
        mcf->rules_set = msc_create_rules_set();

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL) {
            return NGX_CONF_ERROR;
        }

        cln->handler = ngx_http_modsecurity_cleanup_rules;
        cln->data = mcf;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    rc = msc_rules_add_remote(mcf->rules_set,
                              (char *)value[1].data, (char *)value[2].data,
                              &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (rc < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Failed to load the remote rules %V %V: %s",
                           &value[1], &value[2], error);
        free((char *)error);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_modsecurity_set_transaction_id(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf) {
    ngx_str_t                         *value;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_modsecurity_conf_t *mcf = conf;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;
    ccv.zero = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    mcf->transaction_id = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (mcf->transaction_id == NULL) {
        return NGX_CONF_ERROR;
    }

    *mcf->transaction_id = cv;

    return NGX_CONF_OK;
}


static ngx_command_t ngx_http_modsecurity_commands[] =  {
  {
    ngx_string("modsecurity"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_rules"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_http_modsecurity_set_rules,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_rules_file"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_http_modsecurity_set_rules_file,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_rules_remote"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
    ngx_http_modsecurity_set_rules_remote,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_transaction_id"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
    ngx_http_modsecurity_set_transaction_id,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  ngx_null_command
};


static ngx_http_module_t ngx_http_modsecurity_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_modsecurity_init,             /* postconfiguration */

    ngx_http_modsecurity_create_main_conf, /* create main configuration */
    ngx_http_modsecurity_init_main_conf,   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_modsecurity_create_conf,      /* create location configuration */
    ngx_http_modsecurity_merge_conf        /* merge location configuration */
};


ngx_module_t ngx_http_modsecurity_module = {
    NGX_MODULE_V1,
    &ngx_http_modsecurity_ctx,             /* module context */
    ngx_http_modsecurity_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_modsecurity_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_modsecurity_rewrite_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_modsecurity_log_handler;

    ngx_http_modsecurity_request_body_filter_init();
    ngx_http_modsecurity_header_filter_init();

    return NGX_OK;
}


static void *
ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_modsecurity_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->modsec = NULL;
     */

    return conf;
}

static char *
ngx_http_modsecurity_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_modsecurity_main_conf_t *mmcf = conf;

    ngx_pool_cleanup_t  *cln;

    /* Create our ModSecurity instance */
    mmcf->modsec = msc_init();
    if (mmcf->modsec == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "failed to create the ModSecurity instance");
        return NGX_CONF_ERROR;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_modsecurity_cleanup_instance;
    cln->data = mmcf;

    /* Provide our connector information to LibModSecurity */
    msc_set_connector_info(mmcf->modsec, MODSECURITY_NGINX_WHOAMI);
    msc_set_log_cb(mmcf->modsec, ngx_http_modsecurity_log);

    return NGX_CONF_OK;
}

static void *
ngx_http_modsecurity_create_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_modsecurity_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->enable = 0;
     *     conf->rules_set = NULL;
     *     conf->transaction_id = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->transaction_id = NGX_CONF_UNSET_PTR;

    return conf;
}


static char *
ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_modsecurity_conf_t *prev = parent;
    ngx_http_modsecurity_conf_t *conf = child;

    int          rc;
    const char  *error;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->transaction_id, prev->transaction_id, NULL);

    if (prev->rules_set != NULL) {
        if (conf->rules_set != NULL) {
            rc = msc_rules_merge(conf->rules_set, prev->rules_set, &error);

            if (rc < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, error);
                free((char *)error);
                return NGX_CONF_ERROR;
            }

        } else {
            conf->rules_set = prev->rules_set;
        }
    }

    return NGX_CONF_OK;
}


static void
ngx_http_modsecurity_cleanup_instance(void *data)
{
    ngx_http_modsecurity_main_conf_t *mmcf = data;

    WITH_SAFE_PCRE_FREE(
        msc_cleanup(mmcf->modsec);
    )
}


static void
ngx_http_modsecurity_cleanup_rules(void *data)
{
    ngx_http_modsecurity_conf_t *mcf = data;

    WITH_SAFE_PCRE_FREE(
        msc_rules_cleanup(mcf->rules_set);
    )
}

