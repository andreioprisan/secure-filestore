/**
 * @file cstore_add.cpp
 * @brief Adds file to cstore archive
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#include "cstore_add.h"
#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"

// NOTE, change arguments as you see fit
int cstore_add(int arg_num, const char *const *args, const char *archive_file_name, std::string passwd, int archive_files_start_index, int archive_files_total_count)
{
	// If you haven't checked in main()
	// 1- check for -p
	// 2- Check to make sure you can open all files to add, if not error out and file list not empty

	// You may want to have a helper function to check for above 2...
	// Check input files are readable
	checkInputFilesReadable(archive_files_start_index, archive_files_total_count, args);

	// Open all files for storage
	FILE **file_arr = new FILE *[archive_files_total_count];
	memset(file_arr, 0, sizeof(FILE *) * archive_files_total_count);
	for (int i = 0; i < archive_files_total_count; i++)
	{
		file_arr[i] = fopen(args[i + archive_files_start_index], "rb");
	}

	// Create Key
	BYTE *key = (BYTE *)malloc(SHA256_BLOCK_SIZE * sizeof(BYTE));
	iterate_sha256(passwd, key);

	// Check for existing archive_file_ptr
	FILE *archive_file_ptr;
	int v1_files_counter = 0;
	BYTE *v1_header;
	BYTE *v1_contents;
	int v1_length;
	BYTE *v1_hmac;
	bool existing = false;
	// Let's check for existing archive
	if (!checkFileExists(archive_file_name))
	{
		// Not existing, let's create the archive
		archive_file_ptr = fopen(archive_file_name, "wb+");
	}
	else
	{
		if (checkFileReadable(archive_file_name) && checkFileWriteable(archive_file_name))
		{
			existing = true;
			archive_file_ptr = fopen(archive_file_name, "rb");
			v1_files_counter = archive_files_count(archive_file_ptr);
			v1_header = new BYTE[sizeof(header) * v1_files_counter + 1];
			memset(v1_header, 0, sizeof(header) * v1_files_counter + 1);
			get_arch_header(archive_file_ptr, v1_header);
			print_hex(v1_header, sizeof(header) * v1_files_counter);

			// Read Archive contents
			v1_length = len_archive_contents(archive_file_ptr);
			v1_contents = new BYTE[v1_length];
			memset(v1_contents, 0, sizeof(BYTE) * v1_length);
			archive_contents(archive_file_ptr, v1_contents);
			print_hex(v1_contents, v1_length);

			// If existing archive_file_ptr exists you can use helper function
			// Read old HMAC, recompute HMAC and compare...
			if (!verify_archive_hmac(archive_file_ptr, key))
			{
				die("Error: HMAC verification failed.\n");
			}
		}
		else
		{
			die("Error: Acrhive not rw.\n");
		}
	}

	// If HMAC ok, do for loop, read each file, get new IV, encrypt, append
	// encrypt per file
	header *v2_header_arr = new header[archive_files_total_count];
	BYTE **v2_crypt = new BYTE *[archive_files_total_count];
	BYTE **v2_content = new BYTE *[archive_files_total_count];
	int *v2_crypt_length = new int[archive_files_total_count];
	int *v2_content_length = new int[archive_files_total_count];

	memset(v2_header_arr, 0, sizeof(header) * archive_files_total_count);
	memset(v2_crypt, 0, sizeof(BYTE *) * archive_files_total_count);
	memset(v2_crypt_length, 0, sizeof(int) * archive_files_total_count);
	memset(v2_content, 0, sizeof(BYTE *) * archive_files_total_count);
	memset(v2_content_length, 0, sizeof(int) * archive_files_total_count);

	for (int i = 0; i < archive_files_total_count; i++)
	{
		printf("Adding file index %d\n", i);
		v2_content_length[i] = len_file(file_arr[i]);
		v2_content[i] = new BYTE[v2_content_length[i]];
		v2_header_arr[i].file_length = len_file(file_arr[i]);
		strcpy(v2_header_arr[i].file_name, args[archive_files_start_index + i]);
		memset(v2_content[i], 0, sizeof(BYTE) * v2_content_length[i]);

		int input_length_offset_padded;
		unsigned v2_length = len_file(file_arr[i]);
		fseek(file_arr[i], 0, SEEK_SET);
		fread(v2_content[i], v2_length, 1, file_arr[i]);
		fseek(file_arr[i], 0, SEEK_SET);

		// Add file with padding
		if (v2_content_length[i] % 16 == 0)
		{
			v2_crypt[i] = new BYTE[(v2_content_length[i] / 16) * 2 *
								   AES_BLOCK_SIZE];
			memset(v2_crypt[i], 0,
				   sizeof(BYTE) * (v2_content_length[i] / 16) * 2 *
					   AES_BLOCK_SIZE);
			v2_crypt_length[i] =
				(v2_content_length[i] / 16) * 2 * AES_BLOCK_SIZE;
			input_length_offset_padded = 16;
		}
		else
		{
			v2_crypt[i] = new BYTE[(v2_content_length[i] / 16 + 1) *
								   2 * AES_BLOCK_SIZE];
			memset(v2_crypt[i], 0,
				   sizeof(BYTE) * (v2_content_length[i] / 16 + 1) * 2 *
					   AES_BLOCK_SIZE);
			v2_crypt_length[i] =
				(v2_content_length[i] / 16 + 1) * 2 * AES_BLOCK_SIZE;
			input_length_offset_padded = v2_content_length[i] % 16;
		}
		// Encrypt and store
		encrypt_cbc(v2_content[i], v2_content_length[i], NULL,
					v2_crypt[i], key, SHA256_BLOCK_SIZE, input_length_offset_padded);
	}
	if (existing)
	{
		fclose(archive_file_ptr);
		archive_file_ptr = fopen(archive_file_name, "wb+");
	}

	// Encrypt each file with new HMAC of new archive and store it
	int files_count = v1_files_counter + archive_files_total_count;
	fwrite(&files_count, sizeof(int), 1, archive_file_ptr);
	if (existing)
	{
		fwrite(v1_header, v1_files_counter * sizeof(header), 1,
			   archive_file_ptr);
	}
	for (int i = 0; i < archive_files_total_count; i++)
	{
		fwrite(&(v2_header_arr[i]), sizeof(header), 1, archive_file_ptr);
	}
	if (existing)
	{
		fwrite(v1_contents, v1_length, 1, archive_file_ptr);
	}
	for (int i = 0; i < archive_files_total_count; i++)
	{
		fwrite(v2_crypt[i], v2_crypt_length[i], 1, archive_file_ptr);
	}
	int all_size = ftell(archive_file_ptr);
	fseek(archive_file_ptr, 0, SEEK_SET);
	BYTE *arthiveContents = new BYTE[all_size + 1];
	memset(arthiveContents, 0, sizeof(BYTE) * (all_size + 1));
	BYTE *updatedArchiveHMAC = new BYTE[HMAC_BLOCKSIZE];
	memset(updatedArchiveHMAC, 0, sizeof(BYTE) * HMAC_BLOCKSIZE);
	fread(arthiveContents, sizeof(BYTE), all_size, archive_file_ptr);

	fseek(archive_file_ptr, 0, SEEK_END);
	hmac(arthiveContents, key, updatedArchiveHMAC, all_size, SHA256_BLOCK_SIZE);

	printf("\nUPDATED HMAC\n");
	print_hex(updatedArchiveHMAC, HMAC_BLOCKSIZE);
	fwrite(updatedArchiveHMAC, HMAC_BLOCKSIZE, 1, archive_file_ptr);
	fclose(archive_file_ptr);
	for (int i = 0; i < archive_files_total_count; i++)
	{
		fclose(file_arr[i]);
	}

	// todo: should probably functionalize some of this repeat logic between add, extract, and delete

	return 1;
}
