#ifndef __RSA_LABO_
#define __RSA_LABO_
#include "rsa_conf.h"

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>


typedef unsigned int UINT;
typedef unsigned char UCHAR;
typedef const char CCHAR;



struct RSA_KEY_GEN 
{
	RSA *rsa_keypair;
	UINT key_length;
};

struct RSA_PUB_PRIV
{
	BUF_MEM *public_bufmem;
	BUF_MEM *private_bufmem;

	EVP_PKEY *public_keys;
	EVP_PKEY *private_keys;
	
	BIO *public_bio;
	BIO *private_bio;
};

struct RSA_KEYPAIR_BYTES
{
	BIO *public_bio;
	BIO *private_bio;
	EVP_PKEY *public_keys;
	EVP_PKEY *private_keys;
};

struct RSA_ENCRYPT
{
	UCHAR encrypted[RESOLVE_LENGHT];
};

struct RSA_DECRYPT
{
	UCHAR decrypted[RESOLVE_LENGHT];
};

typedef struct RSA_KEYPAIR_BYTES RSA_KEYPAIR_BYTES;
typedef struct RSA_KEY_GEN RSA_KEY_GEN;
typedef struct RSA_PUB_PRIV RSA_PUB_PRIV;

typedef struct RSA_ENCRYPT RSA_ENCRYPT;
typedef struct RSA_DECRYPT RSA_DECRYPT;

int rsa_keypair_generate(RSA_KEY_GEN *rkg);
int rsa_keypair_bytes(RSA_KEY_GEN *rkg, RSA_KEYPAIR_BYTES *rkb, RSA_PUB_PRIV *rpp);
int bytes_to_rsakey_pair(RSA_PUB_PRIV *rpp);
int rsa_encrypt(RSA_PUB_PRIV *rpp, CCHAR *text, RSA_ENCRYPT *r);
int rsa_decrypt(RSA_PUB_PRIV *rpp, UCHAR *src, RSA_DECRYPT *rd, size_t rsakey_bytes_length, size_t decrypt_l);

int bytes_to_rsakey_public(RSA_PUB_PRIV *rpp);
int bytes_to_rsa_private(RSA_PUB_PRIV *rpp);



void RSA_KEY_GEN_free(RSA_KEY_GEN *rkg);
void RSA_PUB_PRIV_free(RSA_PUB_PRIV *rpp);
void RSA_KEYPAIR_BYTES_free(RSA_KEYPAIR_BYTES *rkb);




#endif 
