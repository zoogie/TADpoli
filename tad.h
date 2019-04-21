// Copyright 2010  booto 
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#ifndef _TAD_H
#define _TAD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ec.h"
#include "f_xy.h"
#include "dsi.h"
#include "cert.h"
#include "sha1.h"

#define SIZE_FOOTER 0x440

typedef struct tna4_t
{
	uint32_t magic;
	uint16_t group_id;
	uint16_t version;
	uint8_t mac[8];
	uint8_t hwinfo_n[0x10];
	uint32_t titleid_2;
	uint32_t titleid_1;
	int32_t content_elength[11];
	int32_t content_id[8];
	int32_t savedata_length;
	uint8_t reserved[0x3c];
} tna4_t;

typedef uint8_t sha1_hash[0x14];

typedef struct ecc_point_t
{
	uint8_t r[0x1e];
	uint8_t s[0x1e];
} __attribute__((packed)) ecc_point_t;

typedef struct ecc_cert_t
{
	struct {
		uint32_t type;
		ecc_point_t val;
		uint8_t padding[0x40];
	} sig;
	char issuer[0x40];
	uint32_t key_type;
	char key_id[0x40];
	uint32_t unk;
	ecc_point_t pubkey;
	uint8_t padding2[0x3c];
} __attribute__((packed)) ecc_cert_t;

typedef struct footer_t
{
	sha1_hash banner_hash;
	sha1_hash tna4_hash;
	sha1_hash content_hash[11];
	ecc_point_t sig;
	ecc_cert_t ap;
	ecc_cert_t tw;
} footer_t;

extern uint8_t buffer[0x20020];
extern int certwarn;
extern sha1_hash temp_hash;
extern uint8_t footer_buffer[SIZE_FOOTER];
extern uint8_t* workbuf;
extern uint8_t* tadbuf;

int get_encrypted_size(int normal_size);
int load_file_to_buffer(char *filename, uint8_t *buffer, int32_t expected_length, int32_t mandatory);
int dump_to_file(char *filename, uint8_t *buffer, int32_t expected_length);
int encrypt_to_file(uint8_t *key, FILE *output, uint8_t *src, int32_t length, char *filename);
int decrypt_to_buffer(uint8_t *key, uint8_t *src, uint8_t *dst, uint32_t enc_size, int32_t *dec_size);
int get_contentkey(uint8_t *contentkey, footer_t *footer, char *conidstr);  //this is lifted from caitsith2's dsi_srl_extract 
int resign_footer(footer_t *footer, tna4_t *tna4);
void cleanup_buffers();

#endif