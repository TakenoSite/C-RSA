#include "rsa_labo_clean.h"
#include "rsa_utils.h"


int main()
{
	RSA_KEY_GEN *rkg, rkgn;
	RSA_PUB_PRIV *rpp, rppn;
	RSA_KEYPAIR_BYTES *rkb, rkbn;
	RSA_ENCRYPT *re, ren;
	RSA_DECRYPT *rd, rdn;
	
	rkg = &rkgn;
	rpp = &rppn;
	rkb = &rkbn;
	
	re = &ren;
	rd = &rdn;

	CCHAR *text = "ilove rsa!!";
	
	memset(&ren, 0, sizeof(ren));
	memset(&rdn, 0, sizeof(rdn));

	rkg->key_length = RSA_KEY_LENGTH;
	// generate key pair	
	if(rsa_keypair_generate(rkg))
	{
		fprintf(stderr, "keypairの生成に失敗しました");
		return 0;
	};
	
	// rsa keypair to bytes
	if(rsa_keypair_bytes(rkg, rkb, rpp))
	{
		fprintf(stderr, "byte変換に失敗しました");
		return 1;
	}
	
	puts("PUBLIC");
	printf_rsa_keys(rpp->public_bufmem);
	puts("PRAIVATE");
	printf_rsa_keys(rpp->private_bufmem);

	// rsa bytes to keypair
	if(bytes_to_rsakey_pair(rpp))
	{
		fprintf(stderr, "rsakeyへの変換に失敗しました");
		return 1;
	}

	// rsa encrypted
	int encrypt = rsa_encrypt(rpp, text, re);
	if(encrypt)
	{
		fprintf(stderr, "encryptが失敗しました e: %d\n", encrypt);
		return 1;
	}
	
	rsa_cliphertext_print(re, RSA_KEY_LENGTH);


	// rsa decrypt 
	UCHAR *encrypted_body = re->encrypted;
	size_t decrypt_length = sizeof(rd->decrypted);
	size_t rsa_keys_bytes_l = RSA_KEY_LENGTH / 8;
	

	int decrypt = rsa_decrypt(rpp, 
			encrypted_body, rd, 
			rsa_keys_bytes_l, decrypt_length);
		
	if(decrypt)
	{
		fprintf(stderr, "decryptが失敗しました e: %d\n", decrypt);
		return 1;
	}
		
	printf("decrypted :  \n%s\n", rd->decrypted);
	
	// memory free 
	RSA_KEY_GEN_free(rkg);
	RSA_PUB_PRIV_free(rpp);
	RSA_KEYPAIR_BYTES_free(rkb);	
	return 0;
}
