/**
 * @file cstore_list.cpp
 * @brief Lists files in cstore archive
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#ifndef CSTORE_LIST
#define CSTORE_LIST

#ifndef HEADER
#define HEADER
#define FILE_NAME_LENGTH_MAX 20
typedef struct header
{
	unsigned int file_length;
	char file_name[FILE_NAME_LENGTH_MAX];
} header;

#define HEADER_SIZE(x) (sizeof(unsigned int) + x * sizeof(header))
#endif

int cstore_list(const char *archive_file_name);

#endif
