/**
 * @file cstore_utils.cpp
 * @brief Utils functions for cstore
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#include "cstore_utils.h"
#include "crypto_lib/sha256.h"
#include "crypto_lib/aes.h"
#include <unistd.h>
#include <iostream>
#include <cstring>
#include <fstream>
using namespace std;

// Create error.txt, place your error message, and this will exit the program.
void die(const std::string error)
{
	std::ofstream new_error_file("error.txt", std::ios::out | std::ios::binary | std::ios::app);
	if (!new_error_file.is_open())
	{
		std::cerr << "Could not write to error.txt" << std::endl;
	}
	new_error_file << error << std::endl;
	new_error_file.close();
	exit(1);
}

int read_mac_archive(const std::string archivename, BYTE *file_mac, std::vector<BYTE> &file_content, int mac_len)
{
	// I/O: Open old archivename

	// Authenticate with HMAC if existing archive_file_ptr.

	// Read data as a block:

	// Copy over the file as two parts: (1) MAC (2) Content
	return 0;
}

int hmac(const BYTE *message, const BYTE *key, BYTE *out_tag, int message_len, int key_len)
{
	// Pad key with 32 bytes to make it 64 bytes long
	BYTE pad_key[HMAC_BLOCKSIZE] = {0};
	memcpy(pad_key, key, key_len * sizeof(BYTE));
	for (int i = key_len; i < 64; i++)
	{
		pad_key[i] = 0;
	}
	// Inner padding, 64 Bytes
	BYTE inner_pad[HMAC_BLOCKSIZE] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
		0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
		0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad, 0xba,
		0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
		0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a,
		0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
	// Outer Padding, 64 Bytes
	BYTE outer_pad[HMAC_BLOCKSIZE] = {
		0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
		0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff,
		0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1, 0x24,
		0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93,
		0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21,
		0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};
	// Concatenate ipad and opad section: (o_key_pad || H(i_key_pad || m))
	BYTE i_key_pad[HMAC_BLOCKSIZE];
	BYTE o_key_pad[HMAC_BLOCKSIZE];
	for (int i = 0; i < HMAC_BLOCKSIZE; i++)
	{
		i_key_pad[i] = pad_key[i] ^ inner_pad[i];
		o_key_pad[i] = pad_key[i] ^ outer_pad[i];
	}
	// First, concatenate i_key_pad and message, then hash
	BYTE *i_key_pad_m =
		(BYTE *)malloc((HMAC_BLOCKSIZE + message_len) * sizeof(BYTE) + 1);

	memset(i_key_pad_m, 0, (HMAC_BLOCKSIZE + message_len) * sizeof(BYTE) + 1);
	memcpy(i_key_pad_m, i_key_pad, HMAC_BLOCKSIZE);
	memcpy(i_key_pad_m + HMAC_BLOCKSIZE, message, message_len);
	BYTE h_i_key_pad_m[SHA256_BLOCK_SIZE];
	hash_sha256(i_key_pad_m, h_i_key_pad_m, HMAC_BLOCKSIZE + message_len);

	// Second, concatenate the o_key_pad and H(i_key_pad || m)
	BYTE o_h_i_key_pad_m[HMAC_BLOCKSIZE + SHA256_BLOCK_SIZE];
	memcpy(o_h_i_key_pad_m, o_key_pad, HMAC_BLOCKSIZE * sizeof(BYTE));
	memcpy(o_h_i_key_pad_m + HMAC_BLOCKSIZE, o_h_i_key_pad_m,
		   SHA256_BLOCK_SIZE * sizeof(BYTE));
	// Finally, hash the entire thing
	BYTE finally[SHA256_BLOCK_SIZE];
	hash_sha256(o_h_i_key_pad_m, finally, HMAC_BLOCKSIZE + SHA256_BLOCK_SIZE);
	memcpy(out_tag, finally, HMAC_BLOCKSIZE);
	free(i_key_pad_m);
	return 1;
}

void encrypt_cbc(BYTE *plain_text, int plain_text_length, const BYTE *IV,
				 BYTE ciphertext[], BYTE *key, int keysize, int input_length_offset_padded)
{
	// Pad the plaintext first
	BYTE *aes_data_padding = pad_cbc(plain_text, plain_text_length, input_length_offset_padded);
	int plaintext_padded_text_length = 0;
	if (input_length_offset_padded == AES_BLOCK_SIZE)
	{
		plaintext_padded_text_length = plain_text_length / AES_BLOCK_SIZE * 2 * AES_BLOCK_SIZE;
	}
	else
	{
		plaintext_padded_text_length =
			(plain_text_length / AES_BLOCK_SIZE + 1) * 2 * AES_BLOCK_SIZE;
	}
	// Key setup
	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, 256);
	// Encryption starts here:, AES_BLOCKSIZE is from aes.h
	BYTE iv_buf[AES_BLOCK_SIZE] = {0x0D, 0x04, 0x62, 0x4B, 0xEB, 0x32,
								   0x13, 0x21, 0x15, 0x40, 0x15, 0x10,
								   0x35, 0x49, 0x24, 0x18};
	// Main Loop
	// Transfer over IV to buffer
	// Append the IV to the beginning of final ciphertext
	BYTE t[AES_BLOCK_SIZE + plaintext_padded_text_length + 1];
	memset(t, 0, AES_BLOCK_SIZE + plaintext_padded_text_length + 1);
	memcpy(t, iv_buf, AES_BLOCK_SIZE);
	memcpy(t + AES_BLOCK_SIZE, aes_data_padding, plaintext_padded_text_length);
	for (int i = 1; i < (AES_BLOCK_SIZE + plaintext_padded_text_length) / AES_BLOCK_SIZE;
		 i++)
	{
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			t[i * AES_BLOCK_SIZE + j] ^= ((BYTE *)key_schedule)[j];
			t[i * AES_BLOCK_SIZE + j] ^= t[(i - 1) * AES_BLOCK_SIZE + j];
		}
	}
	// Sanity check with padded data block
	if ((plaintext_padded_text_length) % AES_BLOCK_SIZE != 0)
	{
		die("Incorrect block padding offset");
	}
	memcpy(ciphertext, t + AES_BLOCK_SIZE, plaintext_padded_text_length);
}

void decrypt_cbc(const BYTE *ciphertext, BYTE *decrypted_plaintext, BYTE *key,
				 int keysize, int input_len)
{
	BYTE iv_buf[AES_BLOCK_SIZE] = {0x0D, 0x04, 0x62, 0x4B, 0xEB, 0x32,
								   0x13, 0x21, 0x15, 0x40, 0x15, 0x10,
								   0x35, 0x49, 0x24, 0x18};
	BYTE t[AES_BLOCK_SIZE + input_len + 1];
	WORD key_schedule[60];

	aes_key_setup(key, key_schedule, 256);
	memcpy(t, iv_buf, AES_BLOCK_SIZE);
	memcpy(t + AES_BLOCK_SIZE, ciphertext, input_len);

	for (int i = (AES_BLOCK_SIZE + input_len) / AES_BLOCK_SIZE - 1; i > 0;
		 i--)
	{
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			t[i * AES_BLOCK_SIZE + j] ^= t[(i - 1) * AES_BLOCK_SIZE + j];
			t[i * AES_BLOCK_SIZE + j] ^= ((BYTE *)key_schedule)[j];
		}
	};

	int aes_offset_group = (input_len / AES_BLOCK_SIZE) / 2 - 1;
	int input_length_offset_padded = int(t[AES_BLOCK_SIZE + input_len - 2]);
	int aes_offset_group_size = (aes_offset_group)*AES_BLOCK_SIZE + input_length_offset_padded;

	// Remove padding from the plaintext
	BYTE *plaintext_unpadded_data = unpad_cbc(t + AES_BLOCK_SIZE, input_len);
	// Write unpadded plaintext
	memcpy(decrypted_plaintext, plaintext_unpadded_data, aes_offset_group_size);
}

// Use this function to read sample_len to get cryptographically secure random stuff into sampled_bits
int sample_urandom(BYTE sampled_bits[], int sample_len)
{
	std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary); //Open stream
	if (urandom.is_open())
	{
		for (int i = 0; i < sample_len; i++)
		{
			BYTE random_value;					//Declare value to store data into
			size_t size = sizeof(random_value); //Declare size of data

			if (urandom) //Check if stream is open
			{
				urandom.read(reinterpret_cast<char *>(&random_value), size); //Read from urandom
				if (urandom)												 //Check if stream is ok, read succeeded
				{
					sampled_bits[i] = random_value;
				}
				else //Read failed
				{
					std::cerr << "Failed to read from /dev/urandom" << std::endl;
					return 1;
				}
			}
		}
	}
	else
	{
		std::cerr << "Failed to open /dev/urandom" << std::endl;
		return 1;
	}

	urandom.close(); //close stream
	return 0;
}

void hash_sha256(const BYTE *input, BYTE *output, int in_len)
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, input, in_len);
	sha256_final(&ctx, output);
}

// Iterate Hashing your password 10,000+ times. Store output in final_hash
void iterate_sha256(std::string password, BYTE *final_hash, int rounds)
{
	// Convert password into BYTE array of chars
	BYTE password_bytes[password.length() + 1];
	for (int i = 0; i < password.length(); i++)
	{
		password_bytes[i] = password[i];
	}
	password_bytes[password.length()] = '\0';

	// Iteratively hash 10k times
	// First time needs to hash variable length password_bytes
	BYTE *buf = (BYTE *)malloc(SHA256_BLOCK_SIZE);
	hash_sha256(password_bytes, buf, password.length());
	// Other 10,000 times hashes buffer (32 bytes)
	for (int i = 0; i < rounds; i++)
	{
		hash_sha256(buf, buf, SHA256_BLOCK_SIZE);
	}
	// Update the final hash
	for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
	{
		final_hash[i] = buf[i];
	}
	free(buf);
	return;
}

/**
 * @description: It will return the num of the file in the archive_file_ptr
 * @param {fstream*} f
 * @return {*}
 */
FNUM files_count_archived(FILE *f)
{
	FNUM i = 0;
	fseek(f, 0, SEEK_SET);
	fread(&i, sizeof(FNUM), 1, f);
	fseek(f, 0, SEEK_SET);
	return i;
}

void show_usage(std::string name)
{
	std::cerr << "Usage: " << name << " <function> [-p password] archivename <files>\n"
			  << "<function> can be: list, add, extract, delete.\n"
			  << "Options:\n"
			  << "\t-h, --help\t\t Show this help message.\n"
			  << "\t-p <PASSWORD>\t\t Specify password (plaintext) in console. If not supplied, user will be prompted."
			  << std::endl;
}

void print_hex(const BYTE *byte_arr, int len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%.2X", byte_arr[i]);
	}
}

void print_hex(const std::vector<BYTE> byte_arr)
{
	for (int i = 0; i < byte_arr.size(); i++)
	{
		printf("%.2X", byte_arr[i]);
	}
}

/**
 * @description: Checks whether or not a password argument is present
 * @param {int} argc
 * @param {char*} argv
 * @return {*} status code 1 or 0 for error status
 */
int checkPasswordParameterSet(int argc, const char *const *argv)
{
	if (argc == 2)
	{
		throwIncorrectInputError(argv[1]);
		return 0;
	}
	if (strcmp(argv[2], "-p") == 0)
	{
		if (argc == 3 || argc == 4 || argc == 5)
		{
			throwIncorrectInputError(argv[1]);
			return 0;
		}
		if (strlen(argv[3]) > 12)
		{
			throwPasswordTooLong();
			return 0;
		}
		return 1;
	}
	else
	{
		return 0;
	}
	if (argc < 4)
	{
		throwIncorrectInputError(argv[1]);
		return 0;
	}

	return 1;
}

/**
 * @description: Checks that all provided to be archived files are readable and non-zero.
 * @param {int*} file start offset
 * @param {int*} file end at index
 * @param {char*} file name
 * @return {void} status code 1 or 0 for error status
 */
void checkInputFilesReadable(int archive_files_start_index, int archive_files_total_count, const char *const *argv)
{
	FILE **file_arr = new FILE *[archive_files_total_count];
	memset(file_arr, 0, sizeof(FILE *) * archive_files_total_count);

	for (int i = 0; i < archive_files_total_count; i++)
	{
		// Check that file is readable
		checkFileCanReadOrDie(argv[i + archive_files_start_index]);
		// Check that file is non-empty or exit
		file_arr[i] = fopen(argv[i + archive_files_start_index], "rb");
		if (len_file(file_arr[i]) == 0)
		{
			die("Error: Encountered empty input file.");
		}
	}
}

/**
 * @description: Checks if file is readable or exit.
 * @param {char*} file name
 * @return {void} status code 1 or 0 for error status
 */
void checkFileCanReadOrDie(const char *file_name)
{
	if (!checkFileReadable(file_name))
	{
		char error[100];
		sprintf(error, "Error: Can't read %s", file_name);
		die(error);
	}
}

/**
 * @description: Checks if file exists
 * @param {char*} path
 * @return {*}
 */
int checkFileExists(const char *path)
{
	if (access(path, F_OK) != -1)
	{
		return true;
	}
	return false;
}

/**
 * @description: Checks if file is readable
 * @param {char*} path
 * @return {*}
 */
int checkFileReadable(const char *path)
{
	if (access(path, R_OK) != -1)
	{
		return true;
	}
	return false;
}

/**
 * @description: It will return the num of the file in the archive_file_ptr
 * @param {fstream*} f
 * @return {*}
 */
int checkFileWriteable(const char *path)
{
	if (access(path, W_OK) != -1)
	{
		return true;
	}
	return false;
}

/**
 * @description: Throws input error and exists program.
 * @param {char*} param of command throwing error
 * @return {void} status code 1 or 0 for error status
 */
void throwIncorrectInputError(const char *param)
{
	printf("Error: incorrect input, expecting cstore %s [-p password] archivename file", param);
	exit(1);
}

/**
 * @description: Throws password input error and exists program.
 * @return {void} status code 1 or 0 for error status
 */
void throwPasswordTooLong()
{
	printf("Error: the password is longer than 12 characters");
	exit(1);
}

/**
 * @description: Reads input password from user
 * @return {std::string} password
 */
std::string promptUserForPassword()
{
	std::string user_prompt;

	for (;;)
	{
		std::cout << "Password (up to 12 chars): ";
		std::cin >> user_prompt;
		if (user_prompt.length() <= 12)
		{
			break;
		}
		else
		{
			throwPasswordTooLong();
		}
	}

	return user_prompt;
}

/**
 * @description: get file length
 * @param {fstream*} f
 * @return {*} unsigned length
 */
unsigned len_file(FILE *f)
{
	fseek(f, 0, SEEK_END);
	unsigned l = ftell(f);
	fseek(f, 0, SEEK_SET);
	return l;
}

/**
 * @description: Verify HMAC value from archive_file_ptr with key input
 * @return {*} bool archive_file_ptr HMAC found_file_match_in_archive
 */
bool verify_archive_hmac(FILE *f, const BYTE *key)
{
	// Read archive_file_ptr minus padding
	fseek(f, 0, SEEK_END);
	int length = ftell(f);
	length -= HMAC_BLOCKSIZE;
	fseek(f, 0, SEEK_SET);
	BYTE *inArchiveValidHMAC = new BYTE[HMAC_BLOCKSIZE];
	BYTE content[length];
	BYTE *recomputedHMACFromArchiveKey = new BYTE[HMAC_BLOCKSIZE];

	memset(content, 0, length);
	archive_hmac(f, inArchiveValidHMAC);
	fread(content, length, 1, f);
	// Compute hmac based on key value
	hmac(content, key, recomputedHMACFromArchiveKey, length, SHA256_BLOCK_SIZE);
	print_hex(recomputedHMACFromArchiveKey, HMAC_BLOCKSIZE);
	fseek(f, 0, SEEK_SET);
	// Compare archive_file_ptr stored hmac with newly recomputed based on key
	return memcmp(recomputedHMACFromArchiveKey, inArchiveValidHMAC, HMAC_BLOCKSIZE * sizeof(BYTE)) == 0;
}

// Implement Padding if the message can't be cut into 32 size blocks
// You can use PKCS#7 Padding, but if you have another method that works, thats OK too.
BYTE *pad_cbc(BYTE *data, int data_len, int input_length_offset_padded)
{
	// Compute ASE offset aes_file_index_offset and size based on data length
	int aes_offset_group = (input_length_offset_padded == 16) ? (data_len / AES_BLOCK_SIZE - 1) : (data_len / AES_BLOCK_SIZE);
	int aes_offset_group_size = (aes_offset_group + 1) * 2 * AES_BLOCK_SIZE;

	// Pad data
	BYTE *aes_data_padding = new BYTE[aes_offset_group_size + 1];
	memset(aes_data_padding, 0, aes_offset_group_size * sizeof(BYTE) + 1);
	for (int i = 0; i < aes_offset_group; i++)
	{
		memcpy(aes_data_padding + i * 2 * AES_BLOCK_SIZE, data + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			aes_data_padding[(i * 2 + 1) * AES_BLOCK_SIZE + j] = 0x10;
		}
	}
	for (int i = 0; i < input_length_offset_padded; i++)
	{
		aes_data_padding[(aes_offset_group * 2) * AES_BLOCK_SIZE + i] = data[aes_offset_group * AES_BLOCK_SIZE + i];
	}
	for (int i = 0; i < AES_BLOCK_SIZE - input_length_offset_padded; i++)
	{
		aes_data_padding[(aes_offset_group * 2) * AES_BLOCK_SIZE + input_length_offset_padded + i] = AES_BLOCK_SIZE - input_length_offset_padded;
	}
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
	{
		aes_data_padding[(aes_offset_group * 2 + 1) * AES_BLOCK_SIZE + i] = input_length_offset_padded;
	}
	return aes_data_padding;
}

// Remove the padding from the data after it is decrypted.
BYTE *unpad_cbc(const BYTE *padded_data, int len)
{
	int aes_offset_group = (len / AES_BLOCK_SIZE) / 2 - 1;
	int input_length_offset_padded = int(padded_data[len - 1]);
	int aes_offset_group_size = (aes_offset_group)*AES_BLOCK_SIZE + input_length_offset_padded;

	BYTE *plaintext_unpadded_data = new BYTE[aes_offset_group_size + 1];
	memset(plaintext_unpadded_data, 0, aes_offset_group_size * sizeof(BYTE) + 1);
	for (int i = 0; i < aes_offset_group; i++)
	{
		memcpy(plaintext_unpadded_data + i * AES_BLOCK_SIZE, padded_data + i * 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
	}
	// now with the offset
	memcpy(plaintext_unpadded_data + aes_offset_group * AES_BLOCK_SIZE,
		   padded_data + 2 * aes_offset_group * AES_BLOCK_SIZE, input_length_offset_padded);

	return plaintext_unpadded_data;
}

/**
 * @description: Get archive header for x number of files
 * @param {file*} f
 * @param {byte*} out
 * @return {*}
 */
void get_arch_header(FILE *f, BYTE *out)
{
	unsigned total_file_count = files_count_archived(f);
	fseek(f, sizeof(unsigned), SEEK_SET);
	unsigned int size = fread(out, total_file_count * sizeof(header), 1, f);
	fseek(f, 0, SEEK_SET);
}

/**
 * @description: Get archive contents
 * @param {file*} f
 * @param {byte*} out
 * @return {*}
 */
void archive_contents(FILE *f, BYTE *out)
{
	unsigned l = len_archive_contents(f);
	BYTE *buffer = new BYTE[l + 1];
	memset(buffer, 0, l * sizeof(BYTE) + 1);
	fseek(f, sizeof(unsigned) + files_count_archived(f) * sizeof(header), SEEK_SET);
	fread(out, l, 1, f);
	fseek(f, 0, SEEK_SET);
}

/**
 * @description: Get length of archive contents
 * @param {file*} f
 * @return {*}
 */
unsigned len_archive_contents(FILE *f)
{
	unsigned c = files_count_archived(f);
	fseek(f, 0, SEEK_END);
	unsigned l = ftell(f);
	fseek(f, 0, SEEK_SET);
	return l - HMAC_BLOCKSIZE - HEADER_SIZE(c);
}

/**
 * @description: It will return the content of the archive_file_ptr;
 * @param {fstream*} f
 * @return {*}
 */
int archive_files_count(FILE *f)
{
	int i = 0;
	fseek(f, 0, SEEK_SET);
	fread(&i, sizeof(int), 1, f);
	fseek(f, 0, SEEK_SET);
	return i;
}

/**
 * @description: It will return the HMAC of the archive_file_ptr
 * @param {file*} f
 * @param {byte*} out
 * @return {*}
 */
void archive_hmac(FILE *f, BYTE *out)
{
	fseek(f, -HMAC_BLOCKSIZE, SEEK_END);
	fread(out, HMAC_BLOCKSIZE, 1, f);
	fseek(f, 0, SEEK_SET);
	printf("\nHMAC:\n");
	print_hex(out, HMAC_BLOCKSIZE);
	return;
}

/**
 * @description: checkArchiveExistsReadable checks if the archive_file_ptr is readable and a file.
 * @param {char*} archive_file_name is the archive_file_ptr file name
 * @return void
 */
void checkArchiveExistsReadable(const char *archive_file_name)
{
	if (!checkFileExists(archive_file_name) || !checkFileReadable(archive_file_name))
	{
		die("Error: Could not read archive_file_ptr file.");
	}
}

void checkArchiveHasHMACAndList(FILE *archive_file_ptr, int archive_files_total_count, header *file_header)
{
	if (!archive_files_total_count)
	{
		die("Error: Archive empty.");
	}
	else
	{
		// you design how the archive_file_ptr is formatted but loop and write all file names to
		// a "list.txt" file as shown in class
		FILE *list = fopen("list.txt", "w");
		for (int i = 0; i < archive_files_total_count; i++)
		{
			// Save file header offset and file name values
			fseek(archive_file_ptr, sizeof(unsigned) + i * sizeof(header), SEEK_SET);
			fread(file_header + i, sizeof(header), 1, archive_file_ptr);

			// Save each file name to list file on new lines
			fprintf(list, "%s\n", file_header[i].file_name);
		}
		fclose(list);
	}
}
