// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec.h"
#include "f_xy.h"
#include "dsi.h"
#include "sha1.h"
#include "tad.h"
#include "cert.h"

int get_encrypted_size(int normal_size)
{
	int extra = normal_size % 0x20000;
	int normal_blocks = normal_size / 0x20000;

	int rv =  normal_blocks*0x20020;
	if(extra > 0)
	{
		rv += extra + 0x20;
	}

	return rv;
}

int load_file_to_buffer(char *filename, uint8_t *buffer, int32_t expected_length, int32_t mandatory)
{
	int readbytes=0;
	int size=0;
	
	FILE *f=fopen(filename,"rb");
	if(!f){
		if(mandatory){
			printf("Error: %s missing\n", filename);
			exit(-1);
		}
		return -1;
	}
	
	fseek(f, 0, SEEK_END); 
	size = ftell(f); 
	fseek(f, 0, SEEK_SET);
	
	if(size > 20*0x100000){
		printf("Input file is outrageously large ( > 20MBs)\n");
		fclose(f);
		exit(-3);
	}
	
	if(expected_length < 0) expected_length = size;
	if(expected_length != size){
		printf("Error: file unexpected size\n");
		fclose(f);
		exit(-2);
	}

	readbytes=fread(buffer, 1, expected_length, f);
	fclose(f);
	
	printf("reading %s\t\t(0x%08X)\n", filename, readbytes);

	return readbytes;
}

int dump_to_file(char *filename, uint8_t *buffer, int32_t expected_length){
	printf("Dumping %s\t\t(0x%08X bytes)\n", filename, expected_length);
	int32_t len=0;
	FILE *f=fopen(filename,"wb");
	len=fwrite(buffer, 1, expected_length, f);
	fclose(f);
	if(len < expected_length){
		printf("Warning: File write size less than expected value\n");
		return 1;
	}
	
	return 0;
}

int encrypt_to_file(uint8_t *key, FILE *output, uint8_t *src, int32_t length, char *filename)
{
	int32_t bytes_to_enc = 0;
	int32_t total_enc_bytes = 0;
	dsi_es_context dec;
	dsi_es_init(&dec, key);
	while(length > 0)
	{
		bytes_to_enc = 0x20000;
		if(bytes_to_enc > length)
		{
			bytes_to_enc = length;
		}

		memcpy(buffer, src, bytes_to_enc);

		dsi_es_encrypt(&dec, buffer, buffer + bytes_to_enc, bytes_to_enc);

		fwrite(buffer, 1, bytes_to_enc + 0x20, output);

		total_enc_bytes += bytes_to_enc;
		src += bytes_to_enc;
		length -= bytes_to_enc;
	}
	
	printf("encrypted %s to file\t\t(0x%08X)\n", filename, get_encrypted_size(total_enc_bytes));

	return 0;
}

int decrypt_to_buffer(uint8_t *key, uint8_t *src, uint8_t *dst, uint32_t enc_size, int32_t *dec_size)
{
	uint32_t bytes_to_dec = 0;
	uint32_t total_dec_bytes = 0;
	dsi_es_context dec;
	dsi_es_init(&dec, key);
	while(enc_size > 0)
	{
		bytes_to_dec = 0x20000;
		if(bytes_to_dec > enc_size - 0x20)
		{
			bytes_to_dec = enc_size - 0x20;
		}
		if(dec_size)
		{
			if(total_dec_bytes + bytes_to_dec > *(uint32_t*)dec_size)
			{
				return -2;
			}
		}
		memcpy(buffer, src, bytes_to_dec + 0x20);

		if(dsi_es_decrypt(&dec, buffer, buffer + bytes_to_dec, bytes_to_dec) != 0)
		{
			printf("total_dec_bytes: 0x%08x, bytes_to_dec: 0x%08x\n",
				total_dec_bytes, bytes_to_dec);
			return -3;
		}

		memcpy(dst, buffer, bytes_to_dec);

		total_dec_bytes += bytes_to_dec;
		src += bytes_to_dec + 0x20;
		dst += bytes_to_dec;
		enc_size -= bytes_to_dec + 0x20;
	}

	if(dec_size)
	{
		*dec_size = total_dec_bytes;
	}

	return 0;
}

int get_contentkey(uint8_t *contentkey, footer_t *footer, char *conidstr)  //this is lifted from caitsith2's dsi_srl_extract 
{
	int i, coni;
	unsigned int tmp;
	unsigned char conid[8];
	unsigned int *conid_words = (unsigned int*)conid;
	unsigned char tadsrl_keyX[16] = {0x4a, 0x00, 0x00, 0x4e, 0x4e, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; //caitsith2 is my kinda guy
	unsigned char tadsrl_keyY[16] = {0xcc, 0xfc, 0xa7, 0x03, 0x20, 0x61, 0xbe, 0x84, 0xd3, 0xeb, 0xa4, 0x26, 0xb8, 0x6d, 0xbe, 0xc2}; //''

	unsigned char keyX[16];
	unsigned char keyY[16];
	uint32_t *keyX_words = (uint32_t *)keyX;

	memset(keyX, 0, 16);
	memset(keyY, 0, 16);

	conidstr = (char*)&footer->tw.key_id[0xb];
	memset(conid, 0, 8);
	i = 0;
	for(coni=7; coni>=0; coni--)
	{
		sscanf(&conidstr[i], "%02x", &tmp);
		conid[coni] = (unsigned char)tmp;
		i+=2;
	}

	memcpy(keyX, tadsrl_keyX, 16);
	memcpy(keyY, tadsrl_keyY, 16);
	keyX_words[2] = conid_words[1] ^ 0xC80C4B72;
	keyX_words[3] = conid_words[0];

	F_XY((uint32_t*)contentkey, keyX_words, (uint32_t*)keyY);

	return 0;
}

int resign_footer(footer_t *footer, tna4_t *tna4)
{
	uint8_t tw_priv[0x1e];
	uint8_t dev_kp[0x19e];
	int rv;
	ecc_cert_t *tw_cert = &footer->tw;

	uint8_t ap_priv[0x1e] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, };

	ecc_cert_t *ap_cert = &footer->ap;

	rv = load_file_to_buffer("dev.kp", dev_kp, sizeof(dev_kp), 0);
	if(rv<0){ memcpy(dev_kp, devkp_public, devkp_public_size); printf("CAUTION: dev.kp not found, using builtin public dev.kp!\n"); certwarn=1;}
	printf("loading keys from dev.kp\n");
	memcpy(tw_cert, dev_kp, 0x180);
	memcpy(tw_priv, dev_kp+0x180, 0x1e);
	
	uint8_t tmp_pub[0x3c];
	ec_priv_to_pub(tw_priv, tmp_pub);
	if(memcmp(tmp_pub, &tw_cert->pubkey, sizeof(tmp_pub)) != 0)
	{
		printf("error: ecc priv key does not correspond to the cert\n");
		return -1;
	}

	printf("using silly (but good enough) AP privkey to generate AP cert\n");
	memset(ap_cert, 0, sizeof(*ap_cert));

	snprintf(ap_cert->issuer, sizeof(ap_cert->issuer), "%s-%s", tw_cert->issuer, tw_cert->key_id);     // cert chain
	snprintf(ap_cert->key_id, sizeof(ap_cert->key_id), "AP%08x%08x", tna4->titleid_1, tna4->titleid_2);// key_id
	ap_cert->key_type = 0x02000000; // key type 
	ec_priv_to_pub(ap_priv, ap_cert->pubkey.r);// pub key
	ap_cert->sig.type = 0x02000100; // sig 
	
	// actually sign it
	sha1((uint8_t*)&ap_cert->issuer, sizeof(ecc_cert_t) - sizeof(ap_cert->sig), temp_hash);
	printf("signing ap...\n");
	rv = generate_ecdsa(ap_cert->sig.val.r, ap_cert->sig.val.s, tw_priv, temp_hash);
	if(rv < 0)
	{
		printf("error: problem signing AP\n");
		return -1;
	}

	// now sign the actual footer
	printf("signing footer...\n");
	sha1(footer_buffer, sizeof(footer_buffer) - sizeof(ecc_point_t) - sizeof(ecc_cert_t) - sizeof(ecc_cert_t), temp_hash);
	rv = generate_ecdsa(footer->sig.r, footer->sig.s, ap_priv, temp_hash);
	if(rv < 0)
	{
		printf("error: problem signing footer\n");
		return -1;
	}

	printf("re-verifying footer sig... ");
	fflush(stdout);
	sha1(footer_buffer, sizeof(footer_t)-sizeof(ecc_cert_t)-sizeof(ecc_cert_t)-sizeof(ecc_point_t), temp_hash);
	rv = check_ecdsa(ap_cert->pubkey.r, footer->sig.r, footer->sig.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD - resign was not valid :S\n");
		return -1;
	}
	printf("re-verifying ap sig... ");
	fflush(stdout);
	sha1((uint8_t*)ap_cert->issuer, sizeof(ecc_cert_t)-sizeof(ap_cert->sig), temp_hash);
	rv = check_ecdsa(tw_cert->pubkey.r, ap_cert->sig.val.r, ap_cert->sig.val.s, temp_hash);
	if(rv == 1)
	{
		printf("GOOD!\n");
	}
	else
	{
		printf("BAD - resign didn't work... exiting\n");
		return -1;
	}

	return 0;
}

void cleanup_buffers()
{
	free(workbuf);
	free(tadbuf);
}