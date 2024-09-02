#include <err.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

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
						 "    encrypt raw.file pubkey.b64...\n"
						 "    decrypt enc.file seckey.file\n";

	diex(format, name);
}

char* cat(FILE* file, size_t* size) {
	long curr = ftell(file);
	fseek(file, 0, SEEK_END);
	*size = ftell(file) - curr;
	fseek(file, curr, SEEK_SET);

	char* data = malloc(*size);
	if(data == NULL) die("malloc %zu", *size);

	if(fread(data, 1, *size, file) != *size) die("fread %zu", *size);

	fclose(file);
	return data;
}

int main(int argc, char** argv) {
	const char* name = argv[0];
	const char* mode = shift();

	if(sodium_init() < 0) diex("sodium_init");

	if(strcmp(mode, "genkey") == 0) {
		///// generate seed /////
		unsigned char seed[crypto_box_SEEDBYTES] = {0};
		randombytes_buf(seed, sizeof(seed));

		///// generate keypair from seed /////
		unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
		unsigned char seckey[crypto_box_SECRETKEYBYTES] = {0};
		if(crypto_box_seed_keypair(pubkey, seckey, seed) < 0)
			diex("generate keypair from seed failed");

		///// write seed to keyfile for later keypair reconstruction /////
		fwrite(seed, 1, sizeof(seed), stdout);

		///// write base64-encoded pubkey to stderr /////
		char pubkey_b64[sodium_base64_ENCODED_LEN(sizeof(pubkey), B64)] = {0};
		if(sodium_bin2base64(
			   pubkey_b64, sizeof(pubkey_b64), pubkey, sizeof(pubkey), B64
		   ) == NULL)
			diex("encode pubkey failed");

		fprintf(stderr, "%s\n", pubkey_b64);
	} else if(strcmp(mode, "encrypt") == 0) {
		const char* raw_file = shift();

		///// generate symmetric master key for data encryption /////
		unsigned char sym_key[crypto_secretbox_KEYBYTES] = {0};
		unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
		crypto_secretbox_keygen(sym_key);
		randombytes_buf(nonce, sizeof(nonce));

		///// write its nonce to output (it can be public) /////
		fwrite(nonce, 1, sizeof(nonce), stdout);

		///// calculate & write the amount of public keys       /////
		///// due to shift(), argc still contains raw_file at 0 /////
		uint8_t count = argc - 1;
		fwrite((char*) &count, sizeof(count), 1, stdout);

		///// for each public key: /////
		for(uint8_t i = 0; i < count; i++) {
			const char* pubkey_b64 = argv[i + 1];

			///// decode it from base64 /////
			unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
			if(sodium_base642bin(
				   pubkey, sizeof(pubkey), pubkey_b64, strlen(pubkey_b64), NULL,
				   NULL, NULL, B64
			   ) < 0)
				diex("decode pubkey.b64 failed");

			///// encrypt the master to the current public key & output /////
			unsigned char sym_key_enc[sizeof(sym_key) + crypto_box_SEALBYTES] =
				{0};
			if(crypto_box_seal(sym_key_enc, sym_key, sizeof(sym_key), pubkey) <
			   0)
				diex("encrypt sym_key for %s failed", pubkey_b64);

			fwrite(sym_key_enc, 1, sizeof(sym_key_enc), stdout);
		}

		///// read input file /////
		size_t raw_size = 0;
		char*  raw      = cat(fopen(raw_file, "rb"), &raw_size);

		///// prepare storage for encrypted data /////
		size_t         enc_size = raw_size + crypto_secretbox_MACBYTES;
		unsigned char* enc      = malloc(enc_size);
		if(enc == NULL) die("malloc %zu for enc", enc_size);

		///// encrypt data & output /////
		if(crypto_secretbox_easy(
			   enc, (unsigned char*) raw, raw_size, nonce, sym_key
		   ) < 0)
			diex("master encryption failed");

		fwrite(enc, 1, enc_size, stdout);
	} else if(strcmp(mode, "decrypt") == 0) {
		const char* enc_file_name = shift();
		const char* seed_file     = shift();

		///// read keypair seed from keyfile /////
		size_t seed_size = 0;
		char*  seed      = cat(fopen(seed_file, "rb"), &seed_size);
		if(seed_size != crypto_box_SEEDBYTES)
			diex(
				"invalid secret key length: %zu != %u", seed_size,
				crypto_box_SEEDBYTES
			);

		///// generate keypair from seed /////
		unsigned char pubkey[crypto_box_PUBLICKEYBYTES] = {0};
		unsigned char seckey[crypto_box_SECRETKEYBYTES] = {0};
		if(crypto_box_seed_keypair(pubkey, seckey, (unsigned char*) seed) < 0)
			diex("generate keypair from seed failed");

		///// open encrypted file /////
		FILE* enc_file = fopen(enc_file_name, "rb");
		if(enc_file == NULL) die("fopen %s", enc_file_name);

		///// read the nonce /////
		unsigned char nonce[crypto_secretbox_NONCEBYTES] = {0};
		if(fread(nonce, sizeof(nonce), 1, enc_file) != 1) die("fread nonce");

		///// read the count /////
		uint8_t count = 0;
		if(fread(&count, sizeof(count), 1, enc_file) != 1) die("fread count");

		///// for each encrypted master key entry: /////
		int           valid_entry                        = 0;
		unsigned char sym_key[crypto_secretbox_KEYBYTES] = {0};

		for(uint8_t i = 0; i < count; i++) {
			///// read it /////
			unsigned char
				sym_key_enc[crypto_secretbox_KEYBYTES + crypto_box_SEALBYTES] =
					{0};
			if(fread(sym_key_enc, sizeof(sym_key_enc), 1, enc_file) != 1)
				die("fread sym_key_enc %d", i);

			if(valid_entry) continue;

			///// try decrypting it with our keypair /////
			if(crypto_box_seal_open(
				   sym_key, sym_key_enc, sizeof(sym_key_enc), pubkey, seckey
			   ) < 0)
				continue;

			valid_entry = 1;
			fprintf(stderr, "valid key entry %d\n", i);
		}

		if(!valid_entry) diex("no valid key entry found");

		///// read rest of file /////
		size_t enc_size = 0;
		char*  enc      = cat(enc_file, &enc_size);

		size_t raw_size = enc_size - crypto_secretbox_MACBYTES;
		char*  raw      = malloc(raw_size);
		if(raw == NULL) die("malloc %zu for raw", raw_size);

		///// decrypt & output /////
		if(crypto_secretbox_open_easy(
			   (unsigned char*) raw, (unsigned char*) enc, enc_size, nonce,
			   sym_key
		   ) < 0)
			diex("master decryption failed");

		fwrite(raw, 1, raw_size, stdout);
	} else {
		usage(name);
	}

	return 0;
}
