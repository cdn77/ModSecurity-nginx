

// From: https://raw.githubusercontent.com/openresty/lua-nginx-module/master/src/ddebug.h

/*
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _DDEBUG_H_INCLUDED_
#define _DDEBUG_H_INCLUDED_

#include <ngx_core.h>

/*
 * #undef MODSECURITY_DDEBUG
 * #define MODSECURITY_DDEBUG 1
 */

#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...) fprintf(stderr, "modsec *** %s: ", __func__); \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, " at %s line %d.\n", __FILE__, __LINE__)

#   else

#include <stdarg.h>
#include <stdio.h>

#include <stdarg.h>

static void dd(const char *fmt, ...) {
}

#    endif

#else

#   if (NGX_HAVE_VARIADIC_MACROS)

#       define dd(...)

#   else

#include <stdarg.h>

static void dd(const char *fmt, ...) {
}

#   endif

#endif

#endif /* _DDEBUG_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
