/**
 * @file cstore_delete.cpp
 * @brief Removes files from cstore archive
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"

typedef unsigned char BYTE;

// Update Argument as you see fit.
int cstore_delete(int arg_num, const char *const *args, const char *archive_file_name, std::string passwd, int archive_files_start_index, int archive_files_total_count)
{
	// Check arguments if you haven't already, see cstore_add
	checkArchiveExistsReadable(archive_file_name);

	// Crate Key
	BYTE *key = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	iterate_sha256(passwd, key);

	// Compute HMAC
	FILE *archive_file_ptr = fopen(archive_file_name, "rb");
	if (!verify_archive_hmac(archive_file_ptr, key))
	{
		die("Error: HMAC verification failed.\n");
	}

	// Iterate through archive_file_ptr and see which files to delete
	int total_file_count = files_count_archived(archive_file_ptr);
	header *file_header = new header[total_file_count];
	memset(file_header, 0, total_file_count * sizeof(header));
	for (int i = 0; i < total_file_count; i++)
	{
		printf("\nReading archive file index %d\n", i);
		fseek(archive_file_ptr, sizeof(unsigned) + i * sizeof(header), SEEK_SET);
		fread(file_header + i, sizeof(header), 1, archive_file_ptr);
		print_hex((BYTE *)(file_header + i), sizeof(header));
	}

	// Keep track of file matches
	bool *found_file_match_in_archive = new bool[total_file_count];
	for (int i = 0; i < total_file_count; i++)
	{
		found_file_match_in_archive[i] = false;
	}
	int looking_for_file_index = total_file_count;
	for (int i = 0; i < archive_files_total_count; i++)
	{
		fseek(archive_file_ptr, sizeof(unsigned) + total_file_count * sizeof(header),
			  SEEK_SET);
		for (int j = 0; j < total_file_count; j++)
		{
			printf("\nLooking for file %s. Current archive_file_ptr index at %s:",
				   args[archive_files_start_index + i],
				   file_header[j].file_name);
			// Check if we found a match for our file in archive index list
			if (strcmp(args[archive_files_start_index + i], file_header[j].file_name) != 0)
			{
				found_file_match_in_archive[j] = true;
			}
			else
			{
				looking_for_file_index--;
			}
		}
	}

	// Look at archive and recreate with all files except the one to delete.
	BYTE **prev_archive_contents = new BYTE *[looking_for_file_index];
	int prev_archive_contents_index = 0;
	fseek(archive_file_ptr, sizeof(unsigned) + total_file_count * sizeof(header),
		  SEEK_SET);
	for (int i = 0; i < total_file_count; i++)
	{
		int aes_file_index_offset;
		if (file_header[i].file_length % AES_BLOCK_SIZE == 0)
		{
			aes_file_index_offset = file_header[i].file_length / AES_BLOCK_SIZE;
		}
		else
		{
			aes_file_index_offset = file_header[i].file_length / AES_BLOCK_SIZE + 1;
		}
		// Keep seeking until we find a match
		if (!found_file_match_in_archive[i])
		{
			fseek(archive_file_ptr, aes_file_index_offset * 2 * AES_BLOCK_SIZE, SEEK_CUR);
			continue;
		}
		prev_archive_contents[prev_archive_contents_index] = new BYTE[aes_file_index_offset * 2 * AES_BLOCK_SIZE];
		fread(prev_archive_contents[prev_archive_contents_index], aes_file_index_offset * 2 * AES_BLOCK_SIZE, 1, archive_file_ptr);
		prev_archive_contents_index++;
	}

	// Build new archive
	fclose(archive_file_ptr);
	archive_file_ptr = fopen(archive_file_name, "wb+");
	fwrite(&looking_for_file_index, sizeof(int), 1, archive_file_ptr);
	prev_archive_contents_index = 0;
	for (int i = 0; i < total_file_count; i++)
	{
		if (!found_file_match_in_archive[i])
		{
			continue;
		}
		fwrite(&(file_header[i]), sizeof(header), 1, archive_file_ptr);
	}
	prev_archive_contents_index = 0;
	// Iterate through archive_file_ptr and see which files to delete
	for (int i = 0; i < total_file_count; i++)
	{
		if (!found_file_match_in_archive[i])
		{
			continue;
		}
		int aes_file_index_offset;
		if (file_header[i].file_length % AES_BLOCK_SIZE == 0)
		{
			aes_file_index_offset = file_header[i].file_length / AES_BLOCK_SIZE;
		}
		else
		{
			aes_file_index_offset = file_header[i].file_length / AES_BLOCK_SIZE + 1;
		}
		fwrite(prev_archive_contents[prev_archive_contents_index], aes_file_index_offset * 2 * AES_BLOCK_SIZE, 1, archive_file_ptr);
		prev_archive_contents_index++;
	}

	int artchiveSize = ftell(archive_file_ptr);
	BYTE *arthiveContents = new BYTE[artchiveSize];
	BYTE *updatedArchiveHMAC = new BYTE[HMAC_BLOCKSIZE];

	printf("\nUpdated archive size: %d\n", artchiveSize);
	fseek(archive_file_ptr, 0, SEEK_SET);
	fread(arthiveContents, artchiveSize, 1, archive_file_ptr);

	// Compute HMAC
	hmac(arthiveContents, key, updatedArchiveHMAC, artchiveSize, SHA256_BLOCK_SIZE);
	printf("\nUPDATED HMAC:\n");
	print_hex(updatedArchiveHMAC, HMAC_BLOCKSIZE);
	fwrite(updatedArchiveHMAC, HMAC_BLOCKSIZE, 1, archive_file_ptr);
	fclose(archive_file_ptr);

	return 0;
}
