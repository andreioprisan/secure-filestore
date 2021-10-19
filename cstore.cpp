/**
 * @file cstore.cpp
 * @brief Main program invocation file
 * @ingroup cstore
 * @author Andrei Oprisan <ao2775@columbia.edu>
 */

#include <iostream>
#include "crypto_lib/aes.c"
#include "crypto_lib/sha256.c"
#include "cstore_list.h"
#include "cstore_add.h"
#include "cstore_extract.h"
#include "cstore_delete.h"
#include "cstore_utils.h"
#include <cstring>
#include <fstream>
#include <iostream>

int main(int argc, char *argv[])
{
	// Check correct number of arguments (minimum 3)
	if (argc < 3)
	{
		show_usage(argv[0]);
		return 1;
	}
	// Check the function that the user wants to perform on the archive_file_ptr
	std::string function = argv[1];
	if (function == "list")
	{
		const char *archive_file_name = argv[2];
		return cstore_list(archive_file_name);
	}
	else if (function == "add" || function == "extract" || function == "delete")
	{
		// You will need to Parse Args/Check your arguments.
		// Might not be a bad idea to check here if you can successfully open the files,
		// Check the correct order, etc.

		// Parsing password, archive_file_ptr name, and files to add/extract/delete list from archive_file_ptr
		std::string passwd;
		const char *archive_file_name;
		int archive_files_start_index, archive_files_total_count;
		int passwordSet = checkPasswordParameterSet(argc, argv);
		if (passwordSet)
		{
			archive_file_name = argv[4];
			passwd = argv[3];
			archive_files_start_index = 5;
			archive_files_total_count = argc - 5;
		}
		else
		{
			archive_file_name = argv[2];
			passwd = promptUserForPassword();
			archive_files_start_index = 3;
			archive_files_total_count = argc - 3;
		}

		if (function == "add")
		{
			return cstore_add(argc, argv, archive_file_name, passwd, archive_files_start_index, archive_files_total_count);
		}

		if (function == "extract")
		{
			return cstore_extract(argc, argv, archive_file_name, passwd, archive_files_start_index, archive_files_total_count);
		}

		if (function == "delete")
		{
			return cstore_delete(argc, argv, archive_file_name, passwd, archive_files_start_index, archive_files_total_count);
		}
	}
	else
	{
		std::cerr << "ERROR: cstore <function> must have <function> in: {list, add, extract, delete}.\n";
		return 1;
	}
}
