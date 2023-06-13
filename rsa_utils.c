#include <stdio.h>
#include "rsa_labo_clean.h"


void printf_rsa_keys(BUF_MEM *bm)
{	
	puts("RSA KEYS : ");
	for(size_t i=0; i<bm->length; i++){
		if((i+1) % 16 == 0)
		{
			printf("%02X\n", bm->data[i]);
			continue;		
		};
		printf("%02X:", bm->data[i]);
	}
	puts("\n");
}

void rsa_cliphertext_print(RSA_ENCRYPT *re, size_t rsa_key_length)
{
	if(rsa_key_length % 2 != 0)
	{
		puts("e : rsakey_bytes_length =  rsa_key_length % 2 != 0");
	}
	
	size_t cliphertext_l = rsa_key_length / 8;
	
	puts("CLIPHERTEXT : ");
	for(size_t i=0; i<cliphertext_l; i++)
	{
		if((i+1) % 16 ==0)	
		{
			printf("%02X\n", re->encrypted[i]);
			continue;
		}
		printf("%02X:", re->encrypted[i]);
	}
	puts("\n");
}
