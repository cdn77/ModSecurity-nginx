

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

/*
 * Setting MODSECURITY_SANITY_CHECKS will help you in the debug process. By
 * defining MODSECURITY_SANITY_CHECKS a set of functions will be executed in
 * order to make sure the well behavior of ModSecurity, letting you know (via
 * debug_logs) if something unexpected happens.
 *
 * If performance is not a concern, it is safe to keep it set.
 *
 */
#ifndef MODSECURITY_SANITY_CHECKS
#define MODSECURITY_SANITY_CHECKS 0
#endif

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
