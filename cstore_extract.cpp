/**
 * @file cstore_extract.cpp
 * @brief Extracts files from cstore archive
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#include <string>
#include <cstring>
#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include <vector>
#include <iostream>
#include <fstream>
#include <unistd.h>

typedef unsigned char BYTE;

int cstore_extract(int arg_num, const char *const *args, const char *archive_file_name, std::string passwd, int archive_files_start_index, int archive_files_total_count)
{
	// Do Argument Checking
	// 1. Make sure archive_file_ptr is readable
	checkArchiveExistsReadable(archive_file_name);

	// Build Key
	BYTE *key = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	iterate_sha256(passwd, key);

	// Compare HMAC
	FILE *archive_file_ptr = fopen(archive_file_name, "rb");
	if (!verify_archive_hmac(archive_file_ptr, key))
	{
		die("Error: HMAC verification failed.\n");
	}

	int total_file_count = files_count_archived(archive_file_ptr);
	header *file_header = new header[total_file_count];
	for (int i = 0; i < total_file_count; i++)
	{
		printf("\nReading archive file index %d\n", i);
		fseek(archive_file_ptr, sizeof(unsigned) + i * sizeof(header), SEEK_SET);
		fread(file_header + i, sizeof(header), 1, archive_file_ptr);
		print_hex((BYTE *)(file_header + i), sizeof(header));
	}

	// Loop over archive_file_ptr for files to extract and write to CWD
	for (int i = 0; i < archive_files_total_count; i++)
	{
		fseek(archive_file_ptr, sizeof(unsigned) + total_file_count * sizeof(header),
			  SEEK_SET);
		for (int j = 0; j < total_file_count; j++)
		{
			printf("\nLooking for file %s. Current archive_file_ptr index at %s:",
				   args[archive_files_start_index + i],
				   file_header[j].file_name);
			// Read archive_file_ptr blocks
			int aes_file_index_offset;
			if (file_header[j].file_length % AES_BLOCK_SIZE == 0)
			{
				aes_file_index_offset = file_header[j].file_length / AES_BLOCK_SIZE;
			}
			else
			{
				aes_file_index_offset = file_header[j].file_length / AES_BLOCK_SIZE + 1;
			}
			if (strcmp(args[archive_files_start_index + i], file_header[j].file_name) != 0)
			{
				fseek(archive_file_ptr, aes_file_index_offset * 2 * AES_BLOCK_SIZE, SEEK_CUR);
				continue;
			}
			// Read content from archive_file_ptr
			BYTE *cipher = new BYTE[aes_file_index_offset * 2 * AES_BLOCK_SIZE];
			BYTE *plain = new BYTE[file_header[j].file_length];
			fread(cipher, aes_file_index_offset * 2 * AES_BLOCK_SIZE, 1, archive_file_ptr);
			decrypt_cbc(cipher, plain, key, SHA256_BLOCK_SIZE,
						aes_file_index_offset * 2 * AES_BLOCK_SIZE);
			printf("\n%sFile contents:\n", file_header[j].file_name);
			print_hex(plain, file_header[j].file_length);
			printf("\n");

			// Extract file
			FILE *t = fopen(args[archive_files_start_index + i], "w");
			fwrite(plain, file_header[j].file_length, 1, t);
			fclose(t);
		}
	}

	return 0;
}
