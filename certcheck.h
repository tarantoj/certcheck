#ifndef CERTCHECK_H
#define CERTCHECK_H

/*
 * Checks cert at cert_fname against cert_url, printing results to out_file
 */
void cert_check(const char *cert_fname, const char *cert_url, FILE * out_file);

#endif				/* CERTCHECK_H */
