# Certcheck
A simple application which checks a given list of certificates against a given
list of urls for the following:
- Valid dates
- Domain name validation (Subject Alternative Name or Common Name)
- Minimum RSA key length of 2048 bits
- Not a root certificate
- Is a server certificate

*NOTE:* Implements strict domain name checking
## Build
```bash
make clean
make
```
*NOTE:* Requires the OpenSSL 1.0 libraries to be installed
## Use
```bash
./certcheck input.csv
```
## Input
A csv file with the format `$cert_file,$url`
## Output
A csv file called `output.csv` with the format `$cert_file,$url,$valid`
