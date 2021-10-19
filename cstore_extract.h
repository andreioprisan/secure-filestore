/**
 * @file cstore_extract.h
 * @brief Extracts files from cstore archive
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#ifndef CSTORE_EXTRACT
#define CSTORE_EXTRACT
#include "cstore_utils.h"

int cstore_extract(int, const char *const *, const char *, std::string, int, int);

#endif
