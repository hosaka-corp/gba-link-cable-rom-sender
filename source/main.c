/*
 * Copyright (C) 2018 FIX94
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */
#include <gccore.h>
#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ogc/machine/asm.h>
#include <ogc/machine/processor.h>

//from my tests 50us seems to be the lowest
//safe si transfer delay in between calls
#define SI_TRANS_DELAY 50

/* After you've compiled some multiboot image, you'll have to write 
 * gba_payload.h into this directory so we can tell the DOL about the expected
 * size of the transfer.  */

#include "gba_payload.h"
#define GBA_PAYLOAD_BASE 0x81450000

u8 *resbuf,*cmdbuf;

// Jump back to the FGX entrypoint
#define GOTO_ENTRYPOINT()       __asm__ volatile( "mtlr %0; blr;" : : "r"(0x80003154));

/* I'm *pretty sure* the trick is resetting the MSR here. The changes
 * to libogc might also make a difference -- need to test to see what
 * is actually necessary and sufficient 
 */
void do_reset(void)
{
	mtmsr(MSR_FP|MSR_IR|MSR_DR|MSR_RI);
	__asm__ volatile( "sync; isync;" :::);
	GOTO_ENTRYPOINT()
}

volatile u32 transval = 0;
void transcb(s32 chan, u32 ret)
{
	transval = 1;
}

volatile u32 resval = 0;
void acb(s32 res, u32 val)
{
	resval = val;
}

unsigned int docrc(u32 crc, u32 val)
{
	int i;
	for(i = 0; i < 0x20; i++)
	{
		if((crc^val)&1)
		{
			crc>>=1;
			crc^=0xa1c1;
		}
		else
			crc>>=1;
		val>>=1;
	}
	return crc;
}

unsigned int calckey(unsigned int size)
{
	unsigned int ret = 0;
	size=(size-0x200) >> 3;
	int res1 = (size&0x3F80) << 1;
	res1 |= (size&0x4000) << 2;
	res1 |= (size&0x7F);
	res1 |= 0x380000;
	int res2 = res1;
	res1 = res2 >> 0x10;
	int res3 = res2 >> 8;
	res3 += res1;
	res3 += res2;
	res3 <<= 24;
	res3 |= res2;
	res3 |= 0x80808080;

	if((res3&0x200) == 0)
	{
		ret |= (((res3)&0xFF)^0x4B)<<24;
		ret |= (((res3>>8)&0xFF)^0x61)<<16;
		ret |= (((res3>>16)&0xFF)^0x77)<<8;
		ret |= (((res3>>24)&0xFF)^0x61);
	}
	else
	{
		ret |= (((res3)&0xFF)^0x73)<<24;
		ret |= (((res3>>8)&0xFF)^0x65)<<16;
		ret |= (((res3>>16)&0xFF)^0x64)<<8;
		ret |= (((res3>>24)&0xFF)^0x6F);
	}
	return ret;
}
void doreset()
{
	cmdbuf[0] = 0xFF; //reset
	transval = 0;
	SI_Transfer(1,cmdbuf,1,resbuf,3,transcb,SI_TRANS_DELAY);
	while(transval == 0) ;
}
void getstatus()
{
	cmdbuf[0] = 0; //status
	transval = 0;
	SI_Transfer(1,cmdbuf,1,resbuf,3,transcb,SI_TRANS_DELAY);
	while(transval == 0) ;
}
u32 recv()
{
	memset(resbuf,0,32);
	cmdbuf[0]=0x14; //read
	transval = 0;
	SI_Transfer(1,cmdbuf,1,resbuf,5,transcb,SI_TRANS_DELAY);
	while(transval == 0) ;
	return *(vu32*)resbuf;
}
void send(u32 msg)
{
	cmdbuf[0]=0x15;cmdbuf[1]=(msg>>0)&0xFF;cmdbuf[2]=(msg>>8)&0xFF;
	cmdbuf[3]=(msg>>16)&0xFF;cmdbuf[4]=(msg>>24)&0xFF;
	transval = 0;
	resbuf[0] = 0;
	SI_Transfer(1,cmdbuf,5,resbuf,1,transcb,SI_TRANS_DELAY);
	while(transval == 0) ;
}

/* Taking these gadgets from FIXs' loader code in their other exploits */
void *_memcpy(void *ptr, const void *src, int size) {
	char* ptr2 = ptr;
	const char* src2 = src;
	while(size--) *ptr2++ = *src2++;
	return ptr;
}
static void sync_cache(void *p, u32 n)
{
	u32 start, end;

	start = (u32)p & ~31;
	end = ((u32)p + n + 31) & ~31;
	n = (end - start) >> 5;

	while (n--) {
		asm("dcbst 0,%0 ; icbi 0,%0" : : "b"(p));
		p += 32;
	}
	asm("sync ; isync");
}


int main(int argc, char *argv[]) 
{
	void *xfb = NULL;
	GXRModeObj *rmode = NULL;
	VIDEO_Init();
	rmode = VIDEO_GetPreferredMode(NULL);
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
	int x = 24, y = 32, w, h;
	w = rmode->fbWidth - (32);
	h = rmode->xfbHeight - (48);
	CON_InitEx(rmode, x, y, w, h);
	VIDEO_ClearFrameBuffer(rmode, xfb, COLOR_BLACK);
	PAD_Init();
	cmdbuf = memalign(32,32);
	resbuf = memalign(32,32);
	u8 *gbaBuf = (u8*)GBA_PAYLOAD_BASE;
	size_t gbaSize = GBA_PAYLOAD_SIZE;

	int i;
	while(1)
	{
		while(1)
		{
			printf("\x1b[2J");
			printf("\x1b[37m");
			printf("<TASbot> Wait, did it work?\n");
			printf("<TASbot> dwangoAC, did you plug a GBA in yet?\n"); 
			printf("<TASbot> Just press A when you're ready to send me over!\n");
			PAD_ScanPads();
			VIDEO_WaitVSync();
			u32 btns = PAD_ButtonsDown(0);
			//handle selected option
			if(btns & PAD_BUTTON_A)
				break;
			else if(btns & PAD_BUTTON_START)
			{
				printf("<TASbot> Here, let me restart the game for you ...\n");
				VIDEO_WaitVSync();
				VIDEO_WaitVSync();
				sleep(3);
				do_reset();
				return 0;
			}
		}
		printf("<TASbot> Alright, I'm waiting ..\n");
		resval = 0;

		SI_GetTypeAsync(1,acb);
		while(1)
		{
			if(resval)
			{
				if(resval == 0x80 || resval & 8)
				{
					resval = 0;
					SI_GetTypeAsync(1,acb);
				}
				else if(resval)
					break;
			}
		}
		if(resval & SI_GBA)
		{
			printf("<TASbot> Hey cool, a GBA!\n");
			resbuf[2]=0;
			while(!(resbuf[2]&0x10))
			{
				doreset();
				getstatus();
			}
			printf("<TASbot> Alright, this'll only take a second ...\n");
			unsigned int sendsize = (((gbaSize)+7)&~7);
			unsigned int ourkey = calckey(sendsize);
			//printf("Our Key: %08x\n", ourkey);
			//get current sessionkey
			u32 sessionkeyraw = recv();
			u32 sessionkey = __builtin_bswap32(sessionkeyraw^0x7365646F);
			//send over our own key
			send(__builtin_bswap32(ourkey));
			unsigned int fcrc = 0x15a0;
			//send over gba header
			for(i = 0; i < 0xC0; i+=4)
				send(__builtin_bswap32(*(vu32*)(gbaBuf+i)));
			//printf("Header done! Sending Goomba...\n");
			for(i = 0xC0; i < sendsize; i+=4)
			{
				u32 enc = ((gbaBuf[i+3]<<24)|(gbaBuf[i+2]<<16)|(gbaBuf[i+1]<<8)|(gbaBuf[i]));
				fcrc=docrc(fcrc,enc);
				sessionkey = (sessionkey*0x6177614B)+1;
				enc^=sessionkey;
				enc^=((~(i+(0x20<<20)))+1);
				enc^=0x20796220;
				send(enc);
			}
			fcrc |= (sendsize<<16);
			//printf("ROM done! CRC: %08x\n", fcrc);
			//send over CRC
			sessionkey = (sessionkey*0x6177614B)+1;
			fcrc^=sessionkey;
			fcrc^=((~(i+(0x20<<20)))+1);
			fcrc^=0x20796220;
			send(fcrc);
			//get crc back (unused)
			recv();
			printf("<TASbot> Alright, I think it worked!\n");
			VIDEO_WaitVSync();
			VIDEO_WaitVSync();
			printf("<TASbot> Here, let me reset the game for you!\n");
			sleep(1);
			printf("<TASbot> Alright, give me a few seconds! ..\n");
			sleep(5);
			do_reset();
		}
	}
	return 0;
}
