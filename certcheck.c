#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>

/*
 * Helper function to check a url against a common name, with or without a
 * wildcard
 */
static bool name_check(const char *url, const char *cn)
{
	char *wc, *cndot, *urldot;
	// Get the location of the wildcard in the common name and domain name
	// in the provided url and common name
	wc = strchr(cn, '*');
	cndot = strchr(cn, '.');
	urldot = strchr(url, '.');

	// If there is no wildcard, simply return strcasecmp == 0
	if (!wc)
		return (strcasecmp(url, cn) == 0);

	// Check if wildcard is in the left most label before proceding
	if (wc > cndot)
		return false;

	// If wildcard is not first char, check preceding chars first
	if (wc != cn && strncasecmp(url, cn, wc - cn) != 0)
		return false;

	// If wildcard is not last char in label, check following chars first
	if (wc != cndot - 1 &&
	    strncasecmp(urldot - (cndot - wc) + 1, wc + 1, cndot - wc) != 0)
		return false;

	// return strcasecmp == 0 of the domain names
	return (strcasecmp(urldot, cndot) == 0);
}

/*
 * Checks if supplied url matches certificate Common Name
 */
static bool cn_check(const char *url, X509 * cert)
{
	// Get Common Name from cert
	X509_NAME *cert_subject = X509_get_subject_name(cert);
	char subject_cn[256] = "Issuer CN NOT FOUND";
	X509_NAME_get_text_by_NID(cert_subject, NID_commonName, subject_cn,
				  256);

	// Check url against Common name
	return name_check(url, subject_cn);
}

/*
 * Checks if the given url matches a Subject Alternative Name. Checks if the
 * given url matches the Common Name, if and only if there are no DNS type names
 * in the Subject Alternative Names
 *
 * This function was adapted from code found in the ssl-conservatory repository
 * and can be found at:
 * https://github.com/iSECPartners/ssl-conservatory/blob/master/openssl/openssl_hostname_validation.c
 */
static bool domain_check(const char *url, X509 * cert)
{
	int i;
	int san_names_nb = -1;
	bool result = false;
	bool dns_flag = false;
	STACK_OF(GENERAL_NAME) * san_names = NULL;

	san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	// Return CommonName check if there are no Subject Alternative Names
	// to check against
	if (san_names == NULL)
		return cn_check(url, cert);

	// Get name count
	san_names_nb = sk_GENERAL_NAME_num(san_names);

	// Check each name within extension
	for (i = 0; i < san_names_nb; i++) {
		const GENERAL_NAME *current_name =
		    sk_GENERAL_NAME_value(san_names, i);

		// Only check names marked DNS
		if (current_name->type == GEN_DNS) {
			dns_flag = true;
			char *dns_name =
			    (char *)ASN1_STRING_data(current_name->d.dNSName);

			// Ensure name is properly formed
			if ((size_t) ASN1_STRING_length(current_name->d.dNSName)
			    != strlen(dns_name)) {
				fprintf(stderr, "Malformed Certificate\n");
				break;
			// Do the actual check using helper function
			} else if (name_check(url, dns_name)) {
				result = true;
				break;
			}
		}
	}

	// Free the GENERAL_NAME stack
	sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

	// Return CommonName check if there were no DNS type Subject Alternative
	// Names, else return the result, ie strictly check certificate
	return dns_flag ? result : cn_check(url, cert);
}

/*
 * Checks if Extended Key Usage includes 'TLS Web Server Authentication'
 */
static bool sa_check(X509 * cert)
{
	// Fill cert extension flags
	X509_check_purpose(cert, -1, 0);
	// Return TLS: Web Server Authentication flag
	return cert->ex_xkusage & XKU_SSL_SERVER;
}

/*
 * Checks if BasicConstraints includes CA:FALSE
 */
static bool bc_check(X509 * cert)
{
	bool result = false;
	BASIC_CONSTRAINTS *bc = NULL;

	// Get basic constraints
	bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
	if (bc != NULL) {
		// Set result to true if CA:FALSE
		result = !(bc->ca);
		// Free BASIC_CONSTRAINTS
		BASIC_CONSTRAINTS_free(bc);
	}

	return result;
}

/*
 * Checks if given cert has a valid key length (>= 2048 bits)
 */
static bool size_check(X509 * cert)
{
	EVP_PKEY *pubkey = X509_get_pubkey(cert);

	// Make sure key exists first
	if (pubkey == NULL)
		return false;

	RSA *rsa = EVP_PKEY_get1_RSA(pubkey);
	EVP_PKEY_free(pubkey);

	// Make sure key is RSA
	if (rsa == NULL)
		return false;

	// OpenSSL < 1.1.0 only has a function to return byte-size of RSA key
	// Multiply by 8 to get bit-size
	unsigned int len = 8 * RSA_size(rsa);

	RSA_free(rsa);
	return len >= 2048;

}

/*
 * Checks if given cert has a valid date
 */
static bool date_check(X509 * cert)
{
	int pday, psec;

	// Return false if not before invalid
	const ASN1_TIME *nb = X509_get_notBefore(cert);
	ASN1_TIME_diff(&pday, &psec, NULL, nb);
	if (pday > 0 || psec > 0)
		return false;

	// Return false if not after invalid
	const ASN1_TIME *na = X509_get_notAfter(cert);
	ASN1_TIME_diff(&pday, &psec, NULL, na);
	if (pday < 0 || psec < 0)
		return false;

	// Return true otherwise
	return true;
}

/*
 * Checks given cert against given url, outputs result to given file
 */
void cert_check(const char *cert_fname, const char *url, FILE * out_file)
{
	bool valid = true;
	BIO *certificate_bio = NULL;
	X509 *cert = NULL;

	// Read cert using OpenSSL API
	// NOTE: What an awful library to work with.
	certificate_bio = BIO_new(BIO_s_file());

	if (!(BIO_read_filename(certificate_bio, cert_fname))) {
		fprintf(stderr, "Error in reading cert BIO filename");
		exit(EXIT_FAILURE);
	}

	if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
		fprintf(stderr, "Error in loading certificate");
		exit(EXIT_FAILURE);
	}
	// Check the certificate using helper functions
	valid = size_check(cert) && date_check(cert) && bc_check(cert)
	    && sa_check(cert) && domain_check(url, cert);

	// Free certificate and bio
	X509_free(cert);
	BIO_free_all(certificate_bio);

	// Write results to output file
	fprintf(out_file, "%s,%s,%d\n", cert_fname, url, valid);
}
