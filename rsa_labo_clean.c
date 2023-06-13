#include "rsa_labo_clean.h"
#include "rsa_utils.h"

static RSA* generateRSAKey(int key_length) {
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    unsigned long e = RSA_F4;

    bne = BN_new();
    BN_set_word(bne, e);

    rsa = RSA_new();
    RSA_generate_key_ex(rsa, key_length, bne, NULL);

    BN_free(bne);
    return rsa;
}

int rsa_keypair_generate(RSA_KEY_GEN *rkg)
{
	if(rkg->key_length < 1024)
	{
		return 1;
	}

	rkg->rsa_keypair = generateRSAKey(rkg->key_length);
	if(rkg->rsa_keypair == NULL)
	{
		return 2;
	}
	
	return 0;
}


int rsa_keypair_bytes(RSA_KEY_GEN *rkg, RSA_KEYPAIR_BYTES *rkb, RSA_PUB_PRIV *rpp)
{
	rkb->public_keys = EVP_PKEY_new();
	rkb->private_keys = EVP_PKEY_new();

	EVP_PKEY_set1_RSA(rkb->public_keys, rkg->rsa_keypair);
	EVP_PKEY_set1_RSA(rkb->private_keys, rkg->rsa_keypair);
	
	rkb->public_bio = BIO_new(BIO_s_mem());
	rkb->private_bio = BIO_new(BIO_s_mem());

	PEM_write_bio_PUBKEY(rkb->public_bio, rkb->public_keys);
	PEM_write_bio_PrivateKey(rkb->private_bio, rkb->private_keys, NULL, NULL, 0, NULL, NULL);
	
	BIO_get_mem_ptr(rkb->public_bio, &rpp->public_bufmem);
	BIO_get_mem_ptr(rkb->private_bio, &rpp->private_bufmem);
	
	return 0;
}


int bytes_to_rsakey_pair(RSA_PUB_PRIV *rpp)
{
	
	int public_keys = bytes_to_rsakey_public(rpp);
	int private_keys = bytes_to_rsa_private(rpp);
	
	if(public_keys || private_keys)
	{	
		return 1;
	}
	return 0;
}


int bytes_to_rsakey_public(RSA_PUB_PRIV *rpp)
{
	rpp->public_bio = BIO_new(BIO_s_mem());
	BIO_write(rpp->public_bio, rpp->public_bufmem->data, rpp->public_bufmem->length);
	rpp->public_keys = PEM_read_bio_PUBKEY(rpp->public_bio, NULL, NULL, NULL);
	
	if(rpp->public_keys == NULL)
	{
		puts("e");
		return 1;
	}
	return 0;
}


int bytes_to_rsa_private(RSA_PUB_PRIV *rpp)
{
	rpp->private_bio = BIO_new(BIO_s_mem());
	BIO_write(rpp->private_bio, rpp->private_bufmem->data, rpp->private_bufmem->length);
	rpp->private_keys = PEM_read_bio_PrivateKey(rpp->private_bio, NULL, NULL, NULL);
	if(rpp->private_keys == NULL)
	{
		return 1;
	}
	return 0;
}


int rsa_encrypt(RSA_PUB_PRIV *rpp, CCHAR *text, RSA_ENCRYPT *re)
{
	size_t text_length = strlen(text) + 1;

	EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(rpp->public_keys, NULL);
	if(EVP_PKEY_encrypt_init(encrypt_ctx) <= 0)
	{
		return 1;
	}
	
	if(EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_PKCS1_PADDING) <= 0)
	{
		EVP_PKEY_CTX_free(encrypt_ctx);
		return 2;
	}
	
	if(EVP_PKEY_encrypt(encrypt_ctx, re->encrypted, &text_length, 
				(UCHAR*)text, text_length) <= 0)
	{
		EVP_PKEY_CTX_free(encrypt_ctx);		
		return 3;	
	}
		
	EVP_PKEY_CTX_free(encrypt_ctx);
	return 0;
}



int rsa_decrypt(RSA_PUB_PRIV *rpp, UCHAR *src, RSA_DECRYPT *rd, size_t rsakey_bytes_length, size_t decrypt_l)
{
	if(decrypt_l < 4096 && decrypt_l % 2 != 0)
	{	
		return 1;
	}

	EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(rpp->private_keys, NULL);
	if(EVP_PKEY_decrypt_init(decrypt_ctx) <= 0)
	{
		return 1;
	}
	
	if(EVP_PKEY_CTX_set_rsa_padding(decrypt_ctx, RSA_PKCS1_PADDING) <= 0)
	{
		EVP_PKEY_CTX_free(decrypt_ctx);
		return 2;
	}
	
	if(EVP_PKEY_decrypt(decrypt_ctx, rd->decrypted, &decrypt_l, src, rsakey_bytes_length) <= 0)
	{	
		EVP_PKEY_CTX_free(decrypt_ctx);
		return 3;
	}
	
	EVP_PKEY_CTX_free(decrypt_ctx);
	return 0;
}


void RSA_KEY_GEN_free(RSA_KEY_GEN *rkg)
{
	RSA_free(rkg->rsa_keypair);
}

void RSA_PUB_PRIV_free(RSA_PUB_PRIV *rpp)
{	
	BUF_MEM_free(rpp->public_bufmem);
	BUF_MEM_free(rpp->private_bufmem);
	
	EVP_PKEY_free(rpp->public_keys);
	EVP_PKEY_free(rpp->private_keys);
	
//	BIO_free_all(rpp->public_bio);
//	BIO_free_all(rpp->private_bio);

}

void RSA_KEYPAIR_BYTES_free(RSA_KEYPAIR_BYTES *rkb)
{
	EVP_PKEY_free(rkb->public_keys);
	EVP_PKEY_free(rkb->private_keys);
	
//	BIO_free_all(rkb->public_bio);
//	BIO_free_all(rkb->private_bio);
}
