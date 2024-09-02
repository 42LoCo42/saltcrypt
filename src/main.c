#include <err.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define die(...) err(1, __VA_ARGS__)
#define diex(...) errx(1, __VA_ARGS__)

#define shift()                                                                \
	({                                                                         \
		if(argc <= 1) usage(name);                                             \
		argv++;                                                                \
		argc--;                                                                \
		argv[0];                                                               \
	})

#define B64 sodium_base64_VARIANT_URLSAFE_NO_PADDING

void usage(const char* name) {
	const char* format = "Usage: %s options... > out.file\n"
						 "Options:\n"
						 "    genkey\n"
						 "    encrypt raw.file pubkey.b64\n"
						 "    decrypt enc.file seckey.file\n";

	diex(format, name);
}

char* cat(const char* name, size_t* size) {
	FILE* file = fopen(name, "r");
	if(file == NULL) die("fopen %s", name);

	struct stat statbuf = {0};
	if(fstat(fileno(file), &statbuf) < 0) die("fstat %s", name);

	*size      = statbuf.st_size;
	char* data = malloc(*size);
	if(data == NULL) die("malloc %zu", *size);

	if(fread(data, 1, *size, file) != *size)
		die("fread %zu from %s", *size, name);

	fclose(file);
	return data;
}

int main(int argc, char** argv) {
	const char* name = argv[0];
	const char* mode = shift();

	if(sodium_init() < 0) diex("sodium_init");

	if(strcmp(mode, "genkey") == 0) {
		unsigned char seed[crypto_box_SEEDBYTES] = {0};
		randombytes_buf(seed, sizeof(seed));

		unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
		unsigned char seckey[crypto_box_SECRETKEYBYTES] = {0};
		if(crypto_box_seed_keypair(pubkey, seckey, seed) < 0)
			diex("generate keypair from seed failed");

		fwrite(seed, 1, sizeof(seed), stdout);

		char pubkey_b64[sodium_base64_ENCODED_LEN(sizeof(pubkey), B64)] = {0};
		if(sodium_bin2base64(
			   pubkey_b64, sizeof(pubkey_b64), pubkey, sizeof(pubkey), B64
		   ) == NULL)
			diex("encode pubkey failed");

		fprintf(stderr, "%s\n", pubkey_b64);
	} else if(strcmp(mode, "encrypt") == 0) {
		const char* raw_file   = shift();
		const char* pubkey_b64 = shift();

		unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
		if(sodium_base642bin(
			   pubkey, sizeof(pubkey), pubkey_b64, strlen(pubkey_b64), NULL,
			   NULL, NULL, B64
		   ) < 0)
			diex("decode pubkey.b64 failed");

		size_t raw_size = 0;
		char*  raw      = cat(raw_file, &raw_size);

		size_t         enc_size = raw_size + crypto_box_SEALBYTES;
		unsigned char* enc      = malloc(enc_size);
		if(enc == NULL) die("malloc %zu for enc", enc_size);

		if(crypto_box_seal(enc, (unsigned char*) raw, raw_size, pubkey) < 0)
			diex("encryption failed");

		fwrite(enc, 1, enc_size, stdout);
	} else if(strcmp(mode, "decrypt") == 0) {
		const char* enc_file  = shift();
		const char* seed_file = shift();

		size_t seed_size = 0;
		char*  seed      = cat(seed_file, &seed_size);
		if(seed_size != crypto_box_SEEDBYTES)
			diex(
				"invalid secret key length: %zu != %u", seed_size,
				crypto_box_SEEDBYTES
			);

		unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
		unsigned char seckey[crypto_box_SECRETKEYBYTES] = {0};
		if(crypto_box_seed_keypair(pubkey, seckey, (unsigned char*) seed) < 0)
			diex("generate keypair from seed failed");

		size_t enc_size = 0;
		char*  enc      = cat(enc_file, &enc_size);

		size_t raw_size = enc_size - crypto_box_SEALBYTES;
		char*  raw      = malloc(raw_size);
		if(raw == NULL) die("malloc %zu for raw", raw_size);

		if(crypto_box_seal_open(
			   (unsigned char*) raw, (unsigned char*) enc, enc_size, pubkey,
			   seckey
		   ) < 0)
			diex("decryption failed");

		fwrite(raw, 1, raw_size, stdout);
	} else {
		usage(name);
	}

	return 0;
}
