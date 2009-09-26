
#include <stdio.h>
#include <string.h>
#include <base64.h>
#include <oxdigest.h>
#include <openssl/evp.h>
#include <time.h>


#define key "53ehjUrT"
#define iv "y0Q0mySl"

#define STRUCT_SIZE 20
#define ALIGNED_STRUCT_SIZE 20+8

typedef struct {
	int r1;
	int r2;
	time_t timestamp;
	int r3;
	int r4;
} oxdigest;


void get_digest(char* data) {
	oxdigest d;
	char buf[ALIGNED_STRUCT_SIZE] = {0};
	int size1;
	int size;
	FILE* rand = fopen("/dev/urandom", "rb");
	fread(&d.r1, sizeof(int), 1, rand);
	fread(&d.r2, sizeof(int), 1, rand);
	fread(&d.r3, sizeof(int), 1, rand);
	fread(&d.r4, sizeof(int), 1, rand);
	fclose(rand);
	d.timestamp = time(NULL);
	EVP_CIPHER_CTX ctx;
	EVP_EncryptInit(&ctx, EVP_bf_cbc(), (unsigned char*)key, (unsigned char*)iv);
	EVP_EncryptUpdate(&ctx, (unsigned char*)buf, &size1, (unsigned char*)&d, sizeof(d));
	EVP_EncryptFinal(&ctx, (unsigned char*)buf+size1, &size);
	EVP_CIPHER_CTX_cleanup(&ctx);
	size1 += size;
	b64_encode(buf, size1, data);
}

int digest_offset(const char* data) {
	oxdigest d;
	char buf[ALIGNED_STRUCT_SIZE] = {0};
	int size;
	b64_decode(data, strlen(data), buf, &size);
	int size1;
	EVP_CIPHER_CTX ctx;
	EVP_DecryptInit(&ctx, EVP_bf_cbc(), (unsigned char*)key, (unsigned char*)iv);
	EVP_DecryptUpdate(&ctx, (unsigned char*)&d, &size1, (unsigned char*)buf, size);
	EVP_DecryptFinal(&ctx, (unsigned char*)&d+size1, &size);
	EVP_CIPHER_CTX_cleanup(&ctx);
	size1 += size;
	return time(NULL) - d.timestamp;
}

