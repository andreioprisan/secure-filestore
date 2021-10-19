/**
 * @file cstore_list.cpp
 * @brief Lists files in cstore archive
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#include <string>
#include "cstore_list.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

typedef unsigned char BYTE;

// Change argument as needed
int cstore_list(const char *archive_file_name)
{
	// 1. Make sure archive_file_ptr is readable
	checkArchiveExistsReadable(archive_file_name);

	// 2. You could check to see if it at least has an HMAC?
	FILE *archive_file_ptr = fopen(archive_file_name, "rb");
	int archive_files_total_count = files_count_archived(archive_file_ptr);
	header *file_header = new header[archive_files_total_count];

	checkArchiveHasHMACAndList(archive_file_ptr, archive_files_total_count, file_header);

	// 3. Cleanup
	fclose(archive_file_ptr);
	return 0;
}
