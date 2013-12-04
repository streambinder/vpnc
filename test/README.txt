2013-12-04: Antonio Borneo <borneo.antonio@gmail.com>

VPNC includes a wrapper around openssl and gnutls to
offer single set of crypto-API.
The program test-crypto.c is used to verify the API.

This folder "test" provides a chain of certificates
and an encrypted binary.
test-crypto.c verifies the certificate chain, decrypts
the binary and compare it against expected result.
See below for more details on how to use test-crypto.

openSSL is required to rebuild the test files.
To avoid the dependence from openSSL during SW compile,
all required files are distribuited together with the
VPNC source code.

The Makefile in this folder is able to rebuild all the
certificates and the binary.
	make clean_all
to cleanup the folder and
	make rebuild
to re-build everything from scratch.
Since both cryptographic keys and binary are generated
through random functions, results are not replicable
across executions. Use
	make clean_build
if you want to cleanup the folder but keep either keys
and binary file.

Files in the folder:
- readme.txt:
	This file.
- Makefile:
	To rebuild all following file.
- ca1.key ca2.key ca3.key:
	Pairs of private and public keys, used for
	certificate authorities.
- ca1.pem ca2.pem ca3.pem:
	Self signed certificate of the certificate
	authorities.
- ca_list.pem:
	Single file containing all the certificates
	of the three CA above.
- cert0.key cert1.key cert2.key cert3.key:
	Pairs of private and public keys, used for
	certificates.
- cert0.pem cert1.pem cert2.pem cert3.pem:
	Certificates derived from ".key" files above.
	Certificates are signed in chain:
		ca3.pem -> cert0.pem -> cert1.pem ->
		 -> cert2.pem -> cert3.pem
	Self signed certificate "ca3.pem" signs the
	certificate "cert0.pem", that in turn signs
	"cert1.pem", and so on.
- dec_data.bin:
	Binary random data. File size equal to private
	key size "cert0.key" (256 byte = 2048 bit).
- sig_data.bin:
	Data from "dec_data.bin" RSA encrypted through
	private key in "cert0.pem".
- openssl.cnf:
	Temporarily config file for openSSL flags that
	cannot be passed through command line.

The program test-crypto.c requires at least 5 arguments:
	test-crypto <sig> <dec> <ca> <cert1> <server>
- <sig> is the encrypted binary;
- <dec> is the reference binary before encryption;
- <ca>  is a list of CA certificates, one of them
	signs <server>;
- <cert1> ... <server> is the chain of certificates.
