/* -*- mode: c; c-file-style: "gnu" -*- */
#ifndef YACL_GUILE_EXT_H_
#define YACL_GUILE_EXT_H_


#include <libguile.h>

SCM
yacl_scm_sha256 (SCM bv);

void
yacl_init_guile (void);

#endif
