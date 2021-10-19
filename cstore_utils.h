/**
 * @file cstore_utils.h
 * @brief Utils functions for cstore
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#ifndef CSTORE_UTILS
#define CSTORE_UTILS
#include <vector>
#include <string>
#include "crypto_lib/aes.h"

#define SHA256_ITERS 10000
#define HMAC_BLOCKSIZE 64

typedef unsigned FNUM;
#ifndef HEADER
#define HEADER
#define FILE_NAME_LENGTH_MAX 20
typedef struct header
{
	unsigned int file_length;
	char file_name[FILE_NAME_LENGTH_MAX + 1];
} header;

#define HEADER_SIZE(x) (sizeof(unsigned int) + x * sizeof(header))
#endif

void die(std::string error);

void show_usage(std::string name);

int hmac(const BYTE *message, const BYTE *key, BYTE *out_tag, int message_len, int key_len);

int read_mac_archive(const std::string archivename, BYTE *file_mac, std::vector<BYTE> &file_content, int mac_len);

void encrypt_cbc(BYTE *plain_text, int plain_text_length, const BYTE *IV, BYTE ciphertext[], BYTE *key, int keysize, int input_length_offset_padded);
void decrypt_cbc(const BYTE *ciphertext, BYTE *decrypted_plaintext, BYTE *key, int keysize, int input_len);

BYTE *pad_cbc(BYTE *data, int data_len, int input_length_offset_padded);

BYTE *unpad_cbc(const BYTE *padded_data, int len);

int sample_urandom(BYTE sampled_bits[], int sample_len);

void sample_random(char *buf, int sample_bytes);

void hash_sha256(const BYTE *input, BYTE *output, int in_len);

void iterate_sha256(std::string password, BYTE *final_hash, int rounds = SHA256_ITERS);

void print_hex(const BYTE *byte_arr, int len);

void print_hex(const std::vector<BYTE> byte_arr);

int checkFileExists(const char *path);
int checkFileReadable(const char *path);
int checkFileWriteable(const char *path);
void checkFileCanReadOrDie(const char *file_name);
void checkInputFilesReadable(int archive_files_start_index, int archive_files_total_count, const char *const *argv);

FNUM files_count_archived(FILE *f);

int checkPasswordParameterSet(int argc, const char *const *argv);
void throwIncorrectInputError(const char *param);
void throwPasswordTooLong();

std::string promptUserForPassword();

unsigned len_file(FILE *f);

bool verify_archive_hmac(FILE *f, const BYTE *key);

void get_arch_header(FILE *f, BYTE *out);
unsigned len_archive_contents(FILE *f);
void archive_contents(FILE *f, BYTE *out);

int archive_files_count(FILE *f);

void archive_hmac(FILE *f, BYTE *out);

void checkArchiveExistsReadable(const char *archive_file_name);
void checkArchiveHasHMACAndList(FILE *archive_file_ptr, int archive_files_total_count, header *file_header);

#endif
