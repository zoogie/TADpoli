// Copyright 2010  booto, 2014 caitsith2, 2019 zoogie
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "ec.h"
#include "f_xy.h"
#include "dsi.h"
#include "sha1.h"
#include "tad.h"

#define CI_CONTENT_COUNT 11
#define SIZE_TNA4 0xb4
#define ESIZE_TNA4 0xd4
#define SIZE_FOOTER 0x440
#define ESIZE_FOOTER 0x460
#define EOFF_BANNER 0
#define SIZE_BANNER 0x4000
#define ESIZE_BANNER 0x4020
#define EOFF_TNA4 (EOFF_BANNER+ESIZE_BANNER)
#define ESIZE_TNA4 0xd4
#define EOFF_FOOTER (EOFF_TNA4 + ESIZE_TNA4)
#define ESIZE_FOOTER 0x460
#define EOFF_TMD (EOFF_FOOTER + ESIZE_FOOTER)

unsigned char sd_key[16] = {0x3d, 0xa3, 0xea, 0x33, 0x4c, 0x86, 0xa6, 0xb0, 0x2a, 0xae, 0xdb, 0x51, 0x16, 0xea, 0x92, 0x62};     
unsigned char contentkey[16] = {0};
char modcrypt_shared_key[8] = {'N','i','n','t','e','n','d','o'}; //not used

char *content_namelist[]={"tmd.bin","srl.nds","2.bin","3.bin","4.bin","5.bin","6.bin","7.bin","8.bin","public.sav","banner.sav",\
"private.sav"}; //private.sav isn't accessible on dsi to my knowledge, it is on 3ds in rare circumstances.
uint8_t* workbuf;
uint8_t* tadbuf;
int certwarn=0;
uint32_t tna4_magic = 0x544e4134;
uint8_t tna4_buffer[SIZE_TNA4];
uint8_t footer_buffer[SIZE_FOOTER];
uint8_t banner_buffer[SIZE_BANNER];
uint8_t buffer[0x20020];
uint8_t *content_buffer[11] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
uint32_t content_sizes[11]={0};

int need_to_resign = 0;
sha1_hash temp_hash;

int main(int argc, char *argv[])
{
	int rv;
	int i;
	int offset=0;
	int option=0;
	char outname[128]={0};
	int dec_len;
	
	mkdir("out");
	
	if(argc == 3){
		if(!memcmp(argv[2], "d", 1) || !memcmp(argv[2], "D", 1)) option=0; //dump tad
		if(!memcmp(argv[2], "r", 1) || !memcmp(argv[2], "R", 1)) option=1; //rebuild tad
	}
	else if(argc == 2){
		//nop option=0, aka dump. this covers drag n drop too.
	}
	else{
		printf("Usage:\n");
		printf("TADpoli.exe dsiware.bin d|r\n");
		printf("example: TADpoli.exe 4B344445.bin d (to dump the dsiware into parts)\n");
		getchar();
		return 0;
	}
	uint32_t testendian=0x11223344;
	if(*(char*)&testendian==0x11){
		printf("TADpoli needs to run on a little endian device\n");
		return -1;
	};
	
	workbuf=(uint8_t*)malloc(20*0x100000); //20 MBs. unlike 3ds, there aren't any dsiware that combine to over 16MBs of filespace.
	footer_t *footer;
	tna4_t *header;
	
	printf("**** TADpoli v1.0 for dsi by booto/caitsith2/zoogie ****\n");
	
	if(option == 0){       /*----//dump TAD//----*/
	
		/********************** OPEN TAD **********************/
		dec_len=load_file_to_buffer(argv[1], workbuf, -1, 1);
		tadbuf=(uint8_t*)malloc(dec_len);
		memcpy(tadbuf, workbuf, dec_len);
		
		/********************** DECRYPT HEADER **********************/
		printf("decrypting tna4\n");
		rv = decrypt_to_buffer(sd_key, tadbuf+EOFF_TNA4, tna4_buffer, ESIZE_TNA4, NULL); 

		tna4_t *tna4 = (tna4_t*)tna4_buffer;
		if(tna4_magic != tna4->magic)
		{
			printf("error: magic is incorrect\n");
			cleanup_buffers();
			return 1;
		}

		/********************** DECRYPT FOOTER **********************/
		printf("decrypting footer\n");
		
		rv = decrypt_to_buffer(sd_key, tadbuf+EOFF_FOOTER, footer_buffer, ESIZE_FOOTER, NULL); 
		if(rv < 0)
		{
			printf("error decrypting footer: %d\n", rv);
			cleanup_buffers();
			return 1;
		}

		footer = (footer_t*)footer_buffer;
		get_contentkey(contentkey, (footer_t*)footer_buffer, NULL);
		//dump_to_file("contentkey.bin", contentkey, 16);

		/********************** DECRYPT BANNER **********************/
		printf("decrypting banner\n");
		rv = decrypt_to_buffer(sd_key, tadbuf+EOFF_BANNER, banner_buffer, ESIZE_BANNER, NULL); 
		
		/********************** DUMP INITIAL SECTIONS **********************/
		dump_to_file("out/banner.bin", banner_buffer, SIZE_BANNER);
		dump_to_file("out/header.bin", tna4_buffer, SIZE_TNA4);
		dump_to_file("out/footer.bin", footer_buffer, SIZE_FOOTER);
		
		/********************** DECRYPT CONTENT SECTIONS **********************/
		printf("decrypting content sections\n");
		offset=EOFF_TMD;
		for(i=0;i<CI_CONTENT_COUNT;i++){
			if(tna4->content_elength[i]){
				dec_len=tna4->content_elength[i];
				if(i<2) rv = decrypt_to_buffer(contentkey, tadbuf + offset, workbuf, tna4->content_elength[i], &dec_len); 
				else    rv = decrypt_to_buffer(sd_key, tadbuf + offset, workbuf, tna4->content_elength[i], &dec_len);
				snprintf(outname, 100, "out/%s", content_namelist[i]);
				dump_to_file(outname, workbuf, dec_len);
				offset+=(tna4->content_elength[i]);
			}
		}

		cleanup_buffers();
	}
	else if(option==1){         /*----//rebuild TAD//----*/
	
	    /********************** READ INITIAL SECTIONS INTO MEM **********************/
		load_file_to_buffer("out/banner.bin", banner_buffer, SIZE_BANNER, 1);
		load_file_to_buffer("out/header.bin", tna4_buffer, SIZE_TNA4, 1);
		load_file_to_buffer("out/footer.bin", footer_buffer, SIZE_FOOTER, 1);
		header = (tna4_t*)tna4_buffer;
		footer = (footer_t*)footer_buffer;

		/********************** READ/CHANGE CONTENT SECTION DATA **********************/
		for(i=0;i<CI_CONTENT_COUNT;i++){
			memset(outname, 0, 120);
			snprintf(outname, 100, "out/%s", content_namelist[i]);
			dec_len=load_file_to_buffer(outname, workbuf+offset, -1, i<2); //i<2 means we need tmd and srl
			content_buffer[i]=workbuf+offset;
			if(dec_len<=0){
				header->content_elength[i]=0;
				content_buffer[i]=NULL;
				content_sizes[i]=0;
				continue;
			}
			header->content_elength[i]=get_encrypted_size(dec_len);
			content_sizes[i]=dec_len;
			sha1(workbuf+offset, dec_len, footer->content_hash[i]);
			offset+=dec_len;
		}
			
		sha1(banner_buffer, SIZE_BANNER, footer->banner_hash);
		sha1(tna4_buffer, SIZE_TNA4, footer->tna4_hash);
		
		/********************** SIGN FOOTER **********************/
		
		printf("****** signing footer ******\n");
		resign_footer(footer, header);
		printf("****************************\n");
		
		/********************** ENCRYPT/WRITE ALL SECTIONS **********************/
		memset(outname, 0, 120);
		snprintf(outname, 100, "out/%08X.bin", header->titleid_2);
		FILE *output=fopen(outname,"wb");
		encrypt_to_file(sd_key, output, banner_buffer, SIZE_BANNER, "banner.bin");
		encrypt_to_file(sd_key, output, tna4_buffer, SIZE_TNA4, "header.bin");
		encrypt_to_file(sd_key, output, footer_buffer, SIZE_FOOTER, "footer.bin");
		
		get_contentkey(contentkey, footer, NULL);
		for(i=0;i<CI_CONTENT_COUNT;i++){ 
			if(content_sizes[i]){
				if(i<2) encrypt_to_file(contentkey, output, content_buffer[i], content_sizes[i], content_namelist[i]);
				else
						encrypt_to_file(sd_key, output, content_buffer[i], content_sizes[i], content_namelist[i]);
			}
		}
		//dump_to_file("footer.bin", footer_buffer, SIZE_FOOTER);
		if(certwarn) {
			printf("\n!!! WARNING !!!\n");
			printf("dev.kp not present so the builtin public dev.kp from dsibrew.org was used\n");
			printf("this means that TAD import will fail unless DSi is firm 1.4.1 or less, or DSi settings is downgraded!\n");
			printf("!!! WARNING !!!\n");
		}
		printf("done\n");
		fclose(output);
		free(workbuf);
	}
		
	return 0;
}