#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "certcheck.h"

#define BUF_SIZE 1024
#define OUT_FNAME "output.csv"

int main(int argc, char **argv)
{
	FILE *in_file, *out_file;
	char buf[BUF_SIZE];
	char *cert_fname, *url;

	// Check arg count is correct
	if (argc != 2) {
		fprintf(stderr, "Usage is:\n./certcheck pathToTestFile\n");
		return EXIT_FAILURE;
	}
	// Open supplied file
	in_file = fopen(argv[1], "r");
	if (in_file == NULL) {
		fprintf(stderr, "Error opening \"%s\"\n", argv[1]);
		return EXIT_FAILURE;
	}
	// Open out file
	out_file = fopen(OUT_FNAME, "w");
	if (out_file == NULL) {
		fprintf(stderr, "Error opening \"%s\"\n", OUT_FNAME);
		return EXIT_FAILURE;
	}

	// Parse input csv into arguments for the check function
	// Assumes input file is correctly formatting
	// Checks cert and writes results to out_file
	while (fgets(buf, BUF_SIZE, in_file)) {
		cert_fname = strtok(buf, ",");
		url = strtok(NULL, "\n");
		cert_check(cert_fname, url, out_file);
	}

	// Close file streams and exit
	fclose(in_file);
	fclose(out_file);

	return EXIT_SUCCESS;

}
