
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gccpch.h"
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>
#include "log.h"
#include "hfw_settings.h"
#include "x3.h"
#include "ps3_savedata_plugin.h"
#include "download_plugin.h"
#include "game_ext_plugin.h"
#include "xmb_plugin.h"
#include "explore_plugin.h"
#include "xRegistry.h"
#include <sys/memory.h>


#include "des.h"
#include "videorec.h"

xBDVD * iBdvd;
xsetting_D0261D72_class* (*xsetting_D0261D72)() = 0;

void hook_func(void * original,void * backup, void * hook_function)
{
	memcpy(backup,original,8); // copy original function offset + toc
	memcpy(original, hook_function ,8); // replace original function offset + toc by hook
}

uint64_t lv1_peek(uint64_t addr)
{
	system_call_1(8, addr);
	return_to_user_prog(uint64_t);
}

void lv1_poke( uint64_t addr, uint64_t val) 
{
	system_call_2(9, addr, val);
}

uint64_t peekq(uint64_t addr) // peekq(0x80000000002E9D70ULL)==0x4345580000000000ULL
{
	system_call_1(6, addr);
	return_to_user_prog(uint64_t);
}

void pokeq( uint64_t addr, uint64_t val) // pokeq(0x800000000000171CULL,       0x7C0802A6F8010010ULL);
{
	system_call_2(7, addr, val);
}

uint32_t GetApplicableVersion(void * data)
{
	system_call_8(863, 0x6011, 1,(uint64_t)data,0,0,0,0,0);
	return_to_user_prog(uint32_t);

}

process_id_t vsh_pid = 0;

static int poke_vsh(uint64_t address, char *buf, int size)
{
	if (!vsh_pid)
	{
		uint32_t tmp_pid_list[MAX_PROCESS];
		char name[25];
		int i;
		system_call_3(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_ALL_PROC_PID, (uint64_t)(uint32_t)tmp_pid_list);
		for (i = 0; i<MAX_PROCESS; i++)
		{
			system_call_4(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID, tmp_pid_list[i], (uint64_t)(uint32_t)name);
			if (strstr(name, "vsh"))
			{
				vsh_pid = tmp_pid_list[i];
				break;
			}
		}
		if (!vsh_pid)
			return -1;
	}
	system_call_6(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_SET_PROC_MEM, vsh_pid, address, (uint64_t)(uint32_t)buf, size);
}
//TODO: load vsh process to patch
void psn_patch(uint32_t paddr, uint32_t pbytes)
{

}

void kpatch(uint64_t kaddr, uint64_t kbytes)
{
	//peekq(paddr);
	notify("peekq %08X: Old Bytes %08X\n", kaddr, peekq(kaddr), 0, 0, false);

	pokeq(kaddr, kbytes);

	//peekq(paddr);
	notify("peekq %08X: New Bytes %08X\n", kaddr, peekq(kaddr), 0, 0, false);
}

int (*Authenticate_BD_Drive)(int cmd) = 0;
int (*vsh_E44F29F4)(const char * device_name, const char * device_fs, const char * device_path, int r6, int write_prot, int r8, int * r9) = 0;
int cellFsUtilMount(const char * device_name, const char * device_fs, const char * device_path, int r6, int write_prot, int r8, int * r9)
{
	return vsh_E44F29F4(device_name,device_fs,device_path,r6,write_prot,r8,r9);
}
int (*vsh_33ACD759)(const char * device_path, int r4) = 0;
int cellFsUtilUnMount(const char * device_path, int r4)
{
	return vsh_33ACD759(device_path,r4);
}

int (*vsh_3B4A1AC4)(void * buffer) = 0;
int cellSsAimGetDeviceId(void * idps)
{
	return vsh_3B4A1AC4(idps);
}

int (*paf_55F2C2A6)() = 0;
int (*paf_CF068D31)(int * fd,char * path, int r5, int r6, int * memorycontainer) = 0;
int* load_module(char * path)
{
	int fd;
	paf_CF068D31(&fd,path,0,0,0);
	return (int*)fd;
}
int (*sdk_7B79B6C5)(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv) = 0;
int AesCbcCfbEncrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv)
{
	return sdk_7B79B6C5(out,in,length,user_key,bits,iv);
}
int (*sdk_B45387CD)(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv) = 0;
int AesCbcCfbDecrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv)
{
	return sdk_B45387CD(out,in,length,user_key,bits,iv);
}
int (*paf_350B4536)(void *job, int(*handler1)(), void * param1, int r6, int r7, uint8_t(*handler2)()) = 0;
int Job_start(void *job, int(*handler1)(), void * param1, int r6, int r7, uint8_t(*handler2)())
{
	return paf_350B4536(job,handler1,param1,r6,r7,handler2);
}
int (*vshmain_74A54CBF)(int r3) = 0;
int (*vshmain_5F5729FB)(int r3) = 0;
uint8_t* (*paf_AF58E756)() = 0;

void load_cfw_functions()
{
	(void*&)(vsh_2B58A92C) = (void*)((int)getNIDfunc("vsh",0x2B58A92C)); // disc hash key syscall
	(void*&)(vsh_E20104BE) = (void*)((int)getNIDfunc("vsh",0xE20104BE)); // disc hash key syscall
	(void*&)(vsh_E44F29F4) = (void*)((int)getNIDfunc("vsh",0xE44F29F4));
	(void*&)(vsh_33ACD759) = (void*)((int)getNIDfunc("vsh",0x33ACD759));
	(void*&)(vsh_3B4A1AC4) = (void*)((int)getNIDfunc("vsh",0x3B4A1AC4));
	(void*&)(Authenticate_BD_Drive) = (void*)((int)getNIDfunc("vsh",0x26709B91));
	
	(void*&)(paf_CF068D31) = (void*)((int)getNIDfunc("paf",0xCF068D31));
	(void*&)(paf_55F2C2A6) = (void*)((int)getNIDfunc("paf",0x55F2C2A6));
	(void*&)(paf_350B4536) = (void*)((int)getNIDfunc("paf",0x350B4536));
	(void*&)(paf_AF58E756) = (void*)((int)getNIDfunc("paf",0xAF58E756));
	
	(void*&)(sdk_7B79B6C5) = (void*)((int)getNIDfunc("sdk",0x7B79B6C5));
	(void*&)(sdk_B45387CD) = (void*)((int)getNIDfunc("sdk",0xB45387CD));
	
	(void*&)(update_mgr_read_eprom) = (void*)((int)getNIDfunc("vshmain",0x2C563C92));	// packet id 0x600B
	(void*&)(update_mgr_write_eprom) = (void*)((int)getNIDfunc("vshmain",0x172B05CD));	// packet id 0x600C
	(void*&)(vshmain_74A54CBF) = (void*)((int)getNIDfunc("vshmain",0x74A54CBF));	
	(void*&)(vshmain_5F5729FB) = (void*)((int)getNIDfunc("vshmain",0x5F5729FB));	
	
	
	(void*&)(xBDVDGetInstance) = (void*)((int)getNIDfunc("x3",0x9C246A91));
	iBdvd = (xBDVD*)xBDVDGetInstance();

	
	(void*&)(xsetting_D0261D72) = (void*)((int)getNIDfunc("xsetting",0xD0261D72));
}


int load_video_rec_plugin()
{	
	log("VideoRec.prx ");
	int * prx = load_module("/dev_flash/vsh/module/videorec.sprx");
	log("load: ");
	log("%x\n", prx[7]);

	return *prx;
}

void clean_log()
{
	int ret = cellFsUnlink(getlogpath());
	notify((ret==CELL_OK)?"Log-File cleaned.":"Error cleaning: %x", ret);	
}


void log_klic()
{
	int ret;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_klicensee();
	notify((ret==CELL_OK)?"KLicensee logging enabled.":"Klicensee logging disabled.", ret);	
}


void log_secureid()
{	
	int ret;
	ret = load_video_rec_plugin();

	ret = _videorec_export_function_secureid();
	notify((ret==CELL_OK)?"Secure File Id logging enabled.":"Secure File Id logging disabled.",ret);
}

void enable_recording()
{	
	int ret = -1;
	//ret = load_video_rec_plugin();

	//ret = _videorec_export_function_video_rec();
	notify((ret==CELL_OK)?"Gameplay recording enabled.":"Gameplay recording disabled.",ret);
}


void enable_screenshot()
{
	//hook_func(getNIDfunc("vshmain",0x981D7E9F), (void*)GetScreenShotEnabled_ ,(void*)GetScreenShotEnabled_hook );
	//((int*)GetScreenShotEnabled_)[0] -= 0x2C;
	((int*)getNIDfunc("vshmain",0x981D7E9F))[0] -= 0x2C;
	notify("InGame XMB Screenshots enabled.");
}		


void override_sfo()
{	
	int ret;
	ret = load_video_rec_plugin();
	
	ret = _videorec_export_function_sfoverride();
	notify((ret==CELL_OK)?"SFOverride enabled.":"SFOverride disabled.",ret);

	paf_55F2C2A6(); // drive unload
}

explore_plugin_interface * explore_interface;
int handler1_enabled()
{
	return vshmain_5F5729FB(0xC);
}
int handler1_disabled()
{
	return vshmain_74A54CBF(0xC);
}
uint8_t handler2()
{
	return paf_AF58E756()[0x3C];
}
void toggle_dlna()
{
	explore_interface = (explore_plugin_interface *)GetPluginInterface("explore_plugin",1);

	int dlna = xsetting_D0261D72()->loadRegistryDlnaFlag();
	log("loadRegistryDlnaFlag(): %x\n", dlna);
	dlna = dlna ^ 1;
	int ret = xsetting_D0261D72()->saveRegistryDlnaFlag(dlna);
	log("saveRegistryDlnaFlag(): %x\n", ret);
	if(ret != CELL_OK)
	{
		notify("Unable to set DLNA flag: %x",ret);
	}
	else
	{
		Job_start(0,(dlna==1)?handler1_enabled:handler1_disabled,0,-1,-1,handler2);
		explore_interface->DoUnk6("reload_category photo",0,0);
		explore_interface->DoUnk6("reload_category music",0,0);
		explore_interface->DoUnk6("reload_category video",0,0);
		notify((dlna==1)?"DLNA enabled.":"DLNA disabled.",ret);
	}
}


bool enable_hvdbg()
{
	// patch whitelist for write eprom
	log("Looking for lv1 offset\n"); // lets hope this work on all fw's without hardcoding offsets
	for(uint64_t offset = 0xE0000; offset < 0x1000000;offset = offset + 4)
	{	
		//.text:000000008000A9C0                 cmplwi    cr7, r0, 0xF
		//.text:000000008000A9C4                 ble       cr7, loc_8000A9F0
		//.text:000000008000A9C8                 addi      r0, r9, 0x73E8 # System Language XRegistry.sys#Settings ( /setting/system/language)
		//.text:000000008000A9CC                 cmplwi    cr7, r0, 3
		//.text:000000008000A9D0                 ble       cr7, loc_8000A9F0
		//.text:000000008000A9D4                 addi      r0, r9, 0x73E4 # VSH Target?
		//.text:000000008000A9D8                 cmplwi    cr7, r0, 3
		//.text:000000008000A9DC                 ble       cr7, loc_8000A9F0
		//.text:000000008000A9E0                 addi      r0, r9, 0x73BD # 0x48C43
		//.text:000000008000A9E4                 li        r31, 9
		//.text:000000008000A9E8                 cmplwi    cr7, r0, 3
		//.text:000000008000A9EC                 bgt       cr7, return   # err 9
		if(lv1_peek(offset) == 0x2B800003419D02B4ULL)
		{
			log("Found lv1 code @0x%x\n",(int)offset);
			// before
			//.text:000000008000A9E8                 cmplwi    cr7, r0, 3
			//.text:000000008000A9EC                 bgt       cr7, return   # err 9
			// after
			//.text:000000008000A9E8                 cmplwi    cr7, r0, 3
			//.text:000000008000A9EC                 cmplwi    cr7, r0, 3
			lv1_poke(offset,0x2B8000032B800003ULL);
			break;			
		}
	}

	// patch whitelist for read eprom
	for(uint64_t offset = 0xE0000; offset < 0x1000000;offset = offset + 4)
	{	
		//.text:000000008000848C                 cmplwi    cr7, r0, 0xF
		//.text:0000000080008490                 ble       cr7, sc_read_eprom
		//.text:0000000080008494                 addi      r0, r9, 0x73E8 # System Language
		//.text:0000000080008498                 cmplwi    cr7, r0, 3
		//.text:000000008000849C                 ble       cr7, sc_read_eprom
		//.text:00000000800084A0                 addi      r0, r9, 0x73E4 # setting/net/emulationtype ?
		//.text:00000000800084A4                 cmplwi    cr7, r0, 3
		//.text:00000000800084A8                 ble       cr7, sc_read_eprom
		//.text:00000000800084AC                 addi      r0, r9, 0x73BD # 0x48C43
		//.text:00000000800084B0                 li        r3, 9
		//.text:00000000800084B4                 cmplwi    cr7, r0, 3
		//.text:00000000800084B8                 bgt       cr7, loc_8000850C
		if(lv1_peek(offset) == 0x2B800003419D0054ULL)
		{
			log("Found lv1 code @0x%x\n",(int)offset);
			// before
			//.text:00000000800084B4                 cmplwi    cr7, r0, 3
			//.text:00000000800084B8                 bgt       cr7, loc_8000850C err 9
			// after
			//.text:000000008000A9E8                 cmplwi    cr7, r0, 3
			//.text:000000008000A9EC                 cmplwi    cr7, r0, 3
			lv1_poke(offset,0x2B8000032B800003ULL);
			break;			
		}
	}

	uint8_t data;
	int ret = update_mgr_read_eprom(0x48CF0, &data);
	if(ret != 0)
	{
		notify("Read EPROM failed: %0x\n",ret);
		return false;
	}
	if(data == 0xFF)
	{
		ret = update_mgr_write_eprom(0x48CF0,0x00);
		for(int i = 0x48CF1; i < 0x48D00; i++)
		{
			ret = update_mgr_write_eprom(i,0xCC);			
		}
		notify( (ret == 0) ? "HV Proc enabled\n" : "Write EPROM failed: %0x\n", ret);
	}
	if(data == 0x00)
	{
		ret = update_mgr_write_eprom(0x48CF0,0xFF);
		for(int i = 0x48CF1; i < 0x48D00; i++)
		{
			ret = update_mgr_write_eprom(i,0xFF);			
		}
		notify( (ret == 0) ? "HV Proc disabled\n" : "Write EPROM failed: %0x\n", ret);
	}
	wait(2);
	return (ret == 0) ? true : false;
}


void backup_registry()
{
	int ret;
	CellFsStat sb;
	ret = cellFsStat("/dev_flash2",&sb);
	if(ret != CELL_OK)
	{
		log("mount(dev_flash2)\n");
		ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH2","CELL_FS_FAT","/dev_flash2",0,0,0,0);
		if(ret != CELL_OK)
		{
			notify("HDD Mount Error: %x",ret);
		}
	}	

	int fda;
	ret = cellFsOpen("/dev_flash2/etc/xRegistry.sys",CELL_FS_O_RDONLY, &fda,0,0);
	if(ret != CELL_OK)
	{
		notify("xRegistry.sys Open Error: %x",ret);
	}	
	else
	{
		int fdb;
		ret = cellFsOpen("/dev_hdd0/tmp/xRegistry.sys.bak",CELL_FS_O_CREAT|CELL_FS_O_RDWR, &fdb,0,0);

		
		uint8_t buf[0x1000];
		uint64_t nr;
		uint64_t nrw;

		while((ret = cellFsRead(fda,buf,0x1000,&nr)) == CELL_FS_SUCCEEDED)
		{
			if((int)nr == 0x1000)
			{
				ret = cellFsWrite(fdb,buf,nr,&nrw);
				memset(buf,0,0x1000);
			}
			else
			{
				break;
			}
		}

		cellFsClose(fda);
		cellFsClose(fdb);

		notify("/dev_hdd0/tmp/xRegistry.sys.bak created!");
	}	
}


void usb_firm_loader()
{	
	CellFsStat sb;
	int ret = cellFsStat("/dev_usb",&sb);
	if(ret != CELL_OK)
	{
		notify("Please attach an USB Device");
		return;
	}
	uint64_t dev_flash  = 0x5F666C6173680000ULL; // '_flash..'
	uint64_t dev_flashO = 0x5F666C6173684F00ULL; // '_flashO.'
	uint64_t dev_hdd0   = 0x5F68646430000000ULL;
	uint64_t dev_hdd1   = 0x5F68646431000000ULL;
	uint64_t dev_hdd2   = 0x5F68646432000000ULL;
	uint64_t dev_usb000 = 0x5F75736230303000ULL;
	uint64_t dev_usb001 = 0x5F75736230303100ULL;
	uint64_t dev_usb002 = 0x5F75736230303200ULL;
	uint64_t dev_usb003 = 0x5F75736230303300ULL;
	uint64_t dev_usb004 = 0x5F75736230303400ULL;
	uint64_t dev_usb005 = 0x5F75736230303500ULL;
	uint64_t dev_usb006 = 0x5F75736230303600ULL;

	uint64_t Start= 0x80000000003EE470ULL;		//MTAB  // 0x80000000003EE870
	uint64_t Stop=  0x8000000000500000ULL;		//end
	uint64_t Current;
	uint64_t Data;
	
	log("Looking for test value\n");
	for (uint64_t i = 0x8000000000500000ULL; i > 0x80000000003D0000ULL; i = i - 4 )
	{
		if( peekq(i) == 0x0101000000000009ULL)
		{
			Start = i - 0x3000;
			log("Found value @: %08x", (int)(Start>>32)); log("%08x\n",(int)Start);
			i = 0x80000000003D0000ULL;
		}
	}

	// Jailcrab code
	for (Current=Start;Current<Stop;Current=Current+4)
	{
		Data = peekq(Current);
		//Flash -> FlashO
		//HDD   -> Flash
		//USB   -> HDD
		if (Data==dev_flash){
			log("Found dev_flash @: %08x", (int)(Current>>32)); log("%08x\n",(int)Current);
			//	sprintf(debugt,"Found in %016llX -> _flash\n",Current);
			//	DebugTest(debugt);
			pokeq(Current,dev_flashO);
			//	sprintf(debugt,"Parchet in %016llX -> _flashO\n",Current);
			//	DebugTest(debugt);	
			//VolcarLv2("/dev_usb000/dumpf.bin");
		}

		if ((Data==dev_usb000)||(Data==dev_usb001)||(Data==dev_usb002)||(Data==dev_usb003)||(Data==dev_usb004)||(Data==dev_usb005)||(Data==dev_usb006)){
			log("Found dev_usb @: %08x", (int)(Current>>32)); log("%08x\n",(int)Current);
			//	sprintf(debugt,"Found in %016llX -> _usb000\n",Current);
			//	DebugTest(debugt);
			pokeq(Current,dev_flash);
			//	sprintf(debugt,"Parchet in %016llX -> dev_hdd0\n",Current);
			//	DebugTest(debugt);	
			//VolcarLv2("/dev_hdd0/dumpx.bin");
			Current=Stop;
		}
	}
	
	notify("Level2 Kernel poked.");
}


int vtrm_manager_init()
{
    system_call_5(862, 0x2001,0, 0, 0, 0);
    return_to_user_prog(int);
}
bool rsod_fix()
{			
	uint8_t data;
	int ret = read_product_mode_flag(&data);
	if(ret != CELL_OK)
	{
		notify("Read Product Mode Flag failed: %x", ret);
		return false;
	}
	if(data == 0xFF)
	{
		notify("Please toggle Factory Service Mode");
		return false;
	}

	ret = vtrm_manager_init();
	if(ret != CELL_OK)
	{
		notify("VTRM Init failed: %x",ret);
		return false;
	}
	notify("VTRM Init succeeded");
	wait(2);
	return true;
}


bool patch_laidpaid_sserver2()
{
	log("Looking for lv1 offset\n"); // lets hope this work on all fw's without hardcoding offsets
	for(uint64_t offset = 0x60000; offset < 0x1000000;offset = offset + 4)
	{
		// ss_server2.fself
		//.text:0000000080002544 loc_80002544:                           # CODE XREF: laid_paid_check:loc_80002578j
		//.text:0000000080002544                 ld        r0, 0(r11)
		//.text:0000000080002548                 ld        r9, 0(r4)     # laid
		//.text:000000008000254C                 cmpd      cr7, r9, r0
		//.text:0000000080002550                 bne       cr7, next_laid_paid
		//.text:0000000080002554                 ld        r0, 8(r11)
		//.text:0000000080002558                 ld        r9, 8(r4)     # paid
		//.text:000000008000255C                 cmpd      cr7, r9, r0
		//.text:0000000080002560                 bne       cr7, next_laid_paid
		//.text:0000000080002564                 ld        r0, 0x18(r11)
		//.text:0000000080002568                 ld        r9, 0(r5)
		//.text:000000008000256C                 cmpd      cr7, r9, r0
		//.text:0000000080002570                 beq       cr7, loc_80002584
		//.text:0000000080002574
		//.text:0000000080002574 next_laid_paid:                         # CODE XREF: laid_paid_check+3Cj
		//.text:0000000080002574                                         # laid_paid_check+4Cj
		//.text:0000000080002574                 addi      r11, r11, 0x20
		//.text:0000000080002578
		//.text:0000000080002578 loc_80002578:                           # CODE XREF: laid_paid_check+2Cj
		//.text:0000000080002578                 bdnz      loc_80002544
		//.text:000000008000257C                 li        r3, 5
		//.text:0000000080002580                 b         return
		if(lv1_peek(offset) == 0x396B00204200FFCCULL)
		{
			if(lv1_peek(offset+8) == 0x3860000548000010ULL)
			{
				log("Found lv1 code @0x%x\n",(int)offset);
				// before
				//.text:000000008000257C                 li        r3, 5
				//.text:0000000080002580                 b         return
				// after
				//.text:000000008000257C                 li        r3, 0 <-- allow
				//.text:0000000080002580                 b         return
				lv1_poke(offset+8,0x3860000048000010ULL);
				return true;
			}
		}
	}
	return false;
}
// Decrypt EID2
bool load_iso_root(void * iso_key, void * iso_iv)
{	
	int root_fd;
	uint64_t nread;
	int ret = cellFsOpen("/dev_usb/eid_root_key",CELL_FS_O_RDONLY, &root_fd,0,0);
	if(ret != CELL_OK)
	{
		return false;
	}	
	else
	{
		cellFsRead(root_fd,iso_key,0x20, &nread );
		cellFsRead(root_fd,iso_iv,0x10, &nread );
		cellFsClose(root_fd);
		return true;
	}
}
int get_individual_info_size(uint16_t eid_index, uint64_t * size)
{
	system_call_5(868, (uint64_t)0x17001,(uint64_t)eid_index,(uint64_t)size,0,0);
	return_to_user_prog(int);
}
int read_individual_info(uint64_t eid_index, void * buffer,uint64_t size, uint64_t * nread)
{
	system_call_5(868, (uint64_t)0x17002,(uint64_t)eid_index,(uint64_t)buffer,(uint64_t)size,(uint64_t)nread);
	return_to_user_prog(int);
}
eid2_struct eid2; //uint8_t eid2[0x730];
bool decrypt_eid2()
{
	int ret;
	uint8_t iso_root_key[0x20];
	uint8_t iso_root_iv[0x10];
	memset(iso_root_key,0,0x20);
	memset(iso_root_iv,0,0x10);

	uint8_t eid2_indiv_seed[0x40];
	memcpy(eid2_indiv_seed,eid2_indiv_seed_,0x40);
	
	memset(&eid2,0,sizeof(eid2_struct));	
	
	uint64_t nread=0;
	ret = get_individual_info_size(2,&nread);
	if(ret != CELL_OK)
	{
		// incase not patched
		if(patch_laidpaid_sserver2() == false)
		{
			notify("Unable to patch ss_server2");
			return false;
		}
	}

	if(load_iso_root(iso_root_key,iso_root_iv) == false)
	{
		notify("Please insert a USB stick with eid_root_key");
		return false;
	}

	nread=0;
	ret = get_individual_info_size(2,&nread);
	//log("EID2 size ret: %x, ",ret); log("size: %x\n",(int)nread);
	if(ret != CELL_OK)
	{
		notify("Cannot get EID2 size: %x",ret);
		return false;
	}
	if(nread != sizeof(eid2_struct))
	{
		notify("Wrong EID2 size: %x",nread);
		return false;
	}

	nread=0;
	ret = read_individual_info(2,&eid2,(uint64_t)sizeof(eid2_struct),&nread);
	//log("EID2 ret: %x\n",ret);
	if(ret != CELL_OK)
	{
		notify("Cannot get EID2: %x",ret);
		return false;
	}

	ret = AesCbcCfbEncrypt(eid2_indiv_seed,eid2_indiv_seed,0x40,iso_root_key,256,iso_root_iv);	// correct!
	//log_data(eid2_indiv_seed,0x40);
	//log("EID2 AES: %x\n",ret);
	if(ret != CELL_OK)
	{
		notify("Cannot create EID2 Keys: %x",ret);
		return false;
	}
	
	uint8_t eid2_key[0x20];
	uint8_t eid2_iv[0x20];
	memcpy(eid2_iv,eid2_indiv_seed+0x10,0x10);
	memcpy(eid2_key,eid2_indiv_seed+0x20,0x20);

	ret = AesCbcCfbDecrypt(&eid2.pblock_aes,&eid2.pblock_aes,sizeof(pblock_aes_struct),eid2_key,256,eid2_iv);
	//log_data(&eid2.pblock_aes,sizeof(pblock_aes_struct));
	//log("aes decrypt EID2 P-Block: %x\n",ret);
	if(ret != CELL_OK)
	{
		notify("Cannot decrypt EID2 P-Block: %x",ret);
		return false;
	}
	if( eid2.pblock_aes.pblock_hdr[0] != 1)
	{
		notify("Wrong eid2/eid_root_key");
		return false;
	}

	uint64_t eid2_des_key = 0x6CCAB35405FA562CULL;
	uint64_t eid2_des_iv = 0;
    mbedtls_des_context des_ctx;
	memset(&des_ctx, 0, sizeof( mbedtls_des_context ));
	mbedtls_des_setkey_dec( &des_ctx, (const unsigned char*)&eid2_des_key );
	mbedtls_des_crypt_cbc( &des_ctx, MBEDTLS_DES_DECRYPT, 0x70, (unsigned char*)&eid2_des_iv, (unsigned char*)(eid2.pblock_aes.pblock_des), (unsigned char*)(eid2.pblock_aes.pblock_des) );
	//log_data(eid2.pblock_aes.pblock_des,0x60);
	log("EID2 P-Block decrypted\n");

	ret = AesCbcCfbDecrypt(&eid2.sblock_aes,&eid2.sblock_aes,sizeof(sblock_aes_struct),eid2_key,256,eid2_iv);
	//log_data(&eid2.sblock_aes,sizeof(sblock_aes_struct));
	//log("aes decrypt EID2 S-Block: %x\n",ret);
	if(ret != CELL_OK)
	{
		notify("Cannot decrypt EID2 S-Block: %x",ret);
		return false;
	}
	
	eid2_des_key = 0x6CCAB35405FA562CULL;
	eid2_des_iv = 0;
	
	memset(&des_ctx, 0, sizeof( mbedtls_des_context ));
	mbedtls_des_setkey_dec( &des_ctx, (const unsigned char*)&eid2_des_key );
	mbedtls_des_crypt_cbc( &des_ctx, MBEDTLS_DES_DECRYPT, 0x680, (unsigned char*)&eid2_des_iv, (unsigned char*)(eid2.sblock_aes.sblock_des), (unsigned char*)(eid2.sblock_aes.sblock_des) );
	//log_data(eid2.sblock_aes.sblock_des,0x670);
	log("EID2 S-Block decrypted\n");

	return true;
}


// send decrypted buffers to drive
int sys_storage_open(uint64_t id, int *fd)
{
    system_call_4(600, id, 0, (uint64_t) fd, 0);
    return_to_user_prog(int);
}
int sys_storage_close(int fd)
{
    system_call_1(601, fd);
    return_to_user_prog(int);
}
int sys_storage_send_device_command(int device_handle, unsigned int command, void *indata, uint64_t inlen, void *outdata, uint64_t outlen)
{
	system_call_6(SYS_STORAGE_SEND_DEVICE_COMMAND, device_handle, command, (uint64_t)(uint32_t)indata, inlen, (uint64_t)(uint32_t)outdata, outlen);
    return_to_user_prog(int);
}

int bdvd_fd;
bool open_bdvd_device()
{
	int ret = sys_storage_open(0x101000000000006ULL,&bdvd_fd);
	if(ret != CELL_OK)
	{
		notify("sys_storage_open err: %x",ret);
		return false;
	}
	log("sys_storage_open(bdvd) = %x\n", ret);
	

	int indata = 1;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30,&indata,4,0,0);
	log("stg BDVD Auto Request Sense OFF returned = %x\n", ret);
	if(ret != CELL_OK)
	{
		notify("stg BDVD Auto Request Sense OFF Error!! code = %x",ret);
		return false;
	}
	return true;
}

int sys_storage_send_atapi_command(uint32_t fd, struct lv2_atapi_cmnd_block *atapi_cmnd, uint8_t *buffer) 
{
	return sys_storage_send_device_command(fd,1, atapi_cmnd , sizeof (struct lv2_atapi_cmnd_block), buffer, atapi_cmnd->block_size * atapi_cmnd->blocks);
}
void init_atapi_cmnd_block( struct lv2_atapi_cmnd_block *atapi_cmnd, uint32_t block_size, uint32_t proto, uint32_t type) {
    memset(atapi_cmnd, 0, sizeof(struct lv2_atapi_cmnd_block));
    atapi_cmnd->pktlen = 12; // 0xC
    atapi_cmnd->blocks = 1;
    atapi_cmnd->block_size = block_size; /* transfer size is block_size * blocks */
    atapi_cmnd->proto = proto;
    atapi_cmnd->in_out = type;
}
int ps3rom_lv2_read_buffer(int fd,uint8_t buffer,uint32_t length, uint8_t *data) {
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;
	log("ps3rom_lv2_read_buffer(%d,",(int)buffer);
	log("%x)", (int)length);
    init_atapi_cmnd_block(&atapi_cmnd, length, PIO_DATA_IN_PROTO, DIR_READ);
    atapi_cmnd.pkt[0] = 0x3C; // Read Buffer 
    atapi_cmnd.pkt[1] = 0x02; // /* mode */
    atapi_cmnd.pkt[2] = buffer;
    atapi_cmnd.pkt[3] = 0; 
    atapi_cmnd.pkt[4] = 0;
    atapi_cmnd.pkt[5] = 0;
	atapi_cmnd.pkt[6] = (length >> 16) & 0xff;
	atapi_cmnd.pkt[7] = (length >> 8) & 0xff;
	atapi_cmnd.pkt[8] = length & 0xff;
	atapi_cmnd.pkt[9] = 0x00;
    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, data);
	log(" = %x\n",res);
    return res;
}
int ps3rom_lv2_write_buffer(int fd,uint8_t buffer,uint32_t length, uint8_t *data) {
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;
	log("ps3rom_lv2_write_buffer(%d,",(int)buffer);
	log("%x)", (int)length);
    init_atapi_cmnd_block(&atapi_cmnd, length, PIO_DATA_OUT_PROTO, DIR_WRITE);
    atapi_cmnd.pkt[0] = 0x3B; // Read Buffer 
    atapi_cmnd.pkt[1] = 0x05; // /* mode */
    atapi_cmnd.pkt[2] = buffer;
    atapi_cmnd.pkt[3] = 0; 
    atapi_cmnd.pkt[4] = 0;
    atapi_cmnd.pkt[5] = 0;
	atapi_cmnd.pkt[6] = (length >> 16) & 0xff;
	atapi_cmnd.pkt[7] = (length >> 8) & 0xff;
	atapi_cmnd.pkt[8] = length & 0xff;
	atapi_cmnd.pkt[9] = 0x00;
    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, data);
	log(" = %x\n",res);
    return res;
}
int ps3rom_lv2_get_inquiry(int fd, uint8_t *buffer) {
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;

    init_atapi_cmnd_block(&atapi_cmnd, 0x3C, PIO_DATA_IN_PROTO, DIR_READ);
    atapi_cmnd.pkt[0] = 0x12;
    atapi_cmnd.pkt[1] = 0;
    atapi_cmnd.pkt[2] = 0;
    atapi_cmnd.pkt[3] = 0;
    atapi_cmnd.pkt[4] = 0x3C;

    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, buffer);
    return res;
}
int ps3rom_lv2_mode_sense(int fd, uint8_t *buffer)
{
    int                         res;
    struct lv2_atapi_cmnd_block atapi_cmnd;

    init_atapi_cmnd_block(&atapi_cmnd, 0x10, PIO_DATA_IN_PROTO, DIR_READ);

    atapi_cmnd.pkt[0] = 0x5a; //GPCMD_MODE_SENSE_10;
    atapi_cmnd.pkt[1] = 0x08;
    atapi_cmnd.pkt[2] = 0x03;
    atapi_cmnd.pkt[8] = 0x10;

    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, buffer);
    // if (buffer[11] == 2) exec_mode_select
    return res;
}

int ps3rom_lv2_mode_select(int fd, uint8_t *buffer) {
    int res;
    struct lv2_atapi_cmnd_block atapi_cmnd;

    init_atapi_cmnd_block(&atapi_cmnd, 0x10, PIO_DATA_OUT_PROTO, DIR_WRITE);

    atapi_cmnd.pkt[0] = 0x55; //GPCMD_MODE_SENSE_10;
	atapi_cmnd.pkt[1] = 0x10;
	atapi_cmnd.pkt[2] = 0x00;
	atapi_cmnd.pkt[3] = 0x00;
	atapi_cmnd.pkt[4] = 0x00;
	atapi_cmnd.pkt[5] = 0x00;
	atapi_cmnd.pkt[6] = 0x00;
	atapi_cmnd.pkt[7] = 0x00;
	atapi_cmnd.pkt[8] = 0x10;
	atapi_cmnd.pkt[9] = 0x00;

    res = sys_storage_send_atapi_command(fd, &atapi_cmnd, buffer);    
    return res;
}

bool MODE_SELECT(uint8_t buffer_id)
{
	log("ps3rom_lv2_mode_select(%d)", (int) buffer_id);
	uint8_t data[0x10] = {0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00 ,0x00, 0x2D, 0x06, buffer_id, 0x00, 0x00, 0x00, 0x00, 0x00};
	int ret = ps3rom_lv2_mode_select(bdvd_fd,data);
	log(" = %x\n",ret);
	return (ret==CELL_OK)?true:false;
}

bool GET_bd_drive_sflash()
{	
	log("[ BD DRIVE SFLASH ]");
	uint8_t sflash_test[0x800];
	memset(sflash_test,0,0x800);

	int ret = ps3rom_lv2_read_buffer(bdvd_fd,1,0x800,sflash_test);
	log_data(sflash_test,0x800);
	return (ret==CELL_OK)?true:false;
}

bool CEX_drive_init_pblock()
{
	MODE_SELECT(2);

	uint8_t pblock_test[sizeof(eid2.pblock_aes.pblock_des)];
	memset(pblock_test,0,sizeof(eid2.pblock_aes.pblock_des));

	// READ
	//int ret = ps3rom_lv2_read_buffer(bdvd_fd,2,sizeof(eid2.pblock_aes.pblock_des),pblock_test);
	//log_data(pblock_test,sizeof(eid2.pblock_aes.pblock_des));
	// WRITE
	int ret = ps3rom_lv2_write_buffer(bdvd_fd,2,sizeof(eid2.pblock_aes.pblock_des),eid2.pblock_aes.pblock_des);
	return (ret==CELL_OK)?true:false;
}

bool CEX_drive_init_sblock()
{
	MODE_SELECT(3);

	uint8_t sblock_test[sizeof(eid2.sblock_aes.sblock_des)];
	memset(sblock_test,0,sizeof(eid2.sblock_aes.sblock_des));

	// READ
	//int ret = ps3rom_lv2_read_buffer(bdvd_fd,3,sizeof(eid2.sblock_aes.sblock_des),sblock_test);
	//log_data(sblock_test,sizeof(eid2.sblock_aes.sblock_des));
	// WRITE
	int ret = ps3rom_lv2_write_buffer(bdvd_fd,3,sizeof(eid2.sblock_aes.sblock_des),eid2.sblock_aes.sblock_des);
	return (ret==CELL_OK)?true:false;
}
bool CEX_drive_init_AACS_HRL()
{
	MODE_SELECT(4);
	
	sys_addr_t hrl;
	int ret = sys_memory_allocate(1*1024*1024,SYS_MEMORY_PAGE_SIZE_1M,&hrl);

	uint8_t data[0x54] = {0x10,0x00,0x00,0x0c,0x00,0x03,0x10,0x03,0x00,0x00,0x00,0x01,0x21,0x00,0x00,0x34,
							0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1b,0x0b,0xf2,0x6d,0x47,0x9e,0x77,0x62,
							0x3d,0x91,0xfc,0x78,0xb1,0x59,0xc9,0x52,0xca,0xa4,0xc7,0x41,0x85,0x24,0x96,0x64,
							0x8d,0x1d,0x95,0x8e,0x9b,0x84,0xc6,0xfa,0x4a,0xdd,0x43,0x9b,0x42,0x98,0xfe,0xff,
							0xdf,0xe6,0xf3,0x56,0x85,0x81,0xe1,0x1b,0x27,0x53,0x08,0x14,0x16,0x6d,0x97,0x3c,
							0x20,0x2d,0xe2,0x97};
	memcpy((void*)hrl,data,0x54);
	
	int ret2 = ps3rom_lv2_write_buffer(bdvd_fd,4,0x8000, (uint8_t*)hrl);//hrl_default);
	ret = sys_memory_free(hrl);
	return (ret2==CELL_OK)?true:false;
}
bool CEX_drive_init()
{
	int ret;
	if( open_bdvd_device() == false)
	{
		return false;
	}
		
	// identify drive
	char inquiry[0x3C];
	memset(inquiry,0,0x3C);
	ret = ps3rom_lv2_get_inquiry(bdvd_fd,(uint8_t*)inquiry);
	log("Identified Drive = %s\n",(char*)(inquiry+8));

	//if( GET_bd_drive_sflash() == false)
	//{
	//	return false;
	//}

	if( CEX_drive_init_pblock() == false)
	{
		notify("CEX_drive_init_pblock() failed");
		return false;
	}
	
	int indata = 0;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30,&indata,4,0,0);
	log("stg BDVD Auto Request Sense ON returned = %x\n",ret);
	if( ret != CELL_OK)
	{
		notify("stg BDVD Auto Request Sense ON Error!! code = %x",ret);
		return false;
	}

	ret = Authenticate_BD_Drive(0x29);
	log("Authenticate_BD_Drive(0x29) = %x\n",ret);
	if( ret != CELL_OK)
	{
		notify("Authenticate BD Drive error code = %x",ret);
		return false;
	}

	indata = 1;
	ret = sys_storage_send_device_command(bdvd_fd, 0x30,&indata,4,0,0);
	log("stg BDVD Auto Request Sense OFF returned = %x\n",ret);
	if( ret != CELL_OK)
	{
		notify("stg BDVD Auto Request Sense OFF Error!! code = %x",ret);
		return false;
	}

	if( CEX_drive_init_sblock() == false)
	{
		notify("CEX_drive_init_sblock() failed");
		return false;
	}
	
	if( CEX_drive_init_AACS_HRL() == false)
	{
		notify("CEX_drive_init_AACS_HRL() failed");
		return false;
	}

	return true;
}
void remarry_bd()
{	
	uint8_t data;
	int fsmret = read_product_mode_flag(&data);
	if(fsmret != CELL_OK)
	{		
		notify("Read EPROM failed: %0x\n",fsmret);
		return;
	}
	if(data == 0xFF)
	{
		notify("Please toggle Factory Service Mode\n",0);
		return;
	}

	if(decrypt_eid2() == false)
	{
		return;
	}

	bool ret = CEX_drive_init();
	sys_storage_close(bdvd_fd);

	if( ret == false)
	{
		notify("CEX_drive_init() failed");
	}
	else 
	{
		notify("CEX_drive_init() succeeded");
	}
}



void dump_disc_key()
{
	int ret;
	int disc_type = iBdvd->GetDiscType();
	if(disc_type != BDGAME)
	{
		notify("Please insert a game disc\n");
	}
	else
	{
		uint8_t discinfo[0x20];
		memset(discinfo,0,0x20);
		iBdvd->DoUnk17(discinfo);
		log("TitleID: %s\n",(char*)(discinfo+0x10));

		ret = vsh_E20104BE(); // auth disc, get disc profile, etc. information

		uint8_t dhk[0x10];
		memset(dhk,0,0x10);
		ret = vsh_2B58A92C(dhk); // get disc hash key
		if(ret == CELL_OK)
			log_key("disc_hash_key",dhk);	
		notify( (ret == 0) ? "Disc Hash Key Dumped" : "Disc Hash Key Dump failed: %0x", ret);
	}
}

int sys_sm_control_led(uint8_t led_id,uint8_t led_action)
{ 	
	system_call_2(386, (uint64_t)led_id,(uint64_t)led_action);
	return_to_user_prog(int);
}
void control_led(const char * action)
{
	if(strcmp(action,"ledmod_s")==0)
	{
		sys_sm_control_led(1,0);
		sys_timer_usleep(100000);
		sys_sm_control_led(1,1);
		sys_timer_sleep(2);
	}
	else if(strcmp(action,"ledmod_f_v")==0)
	{
		sys_sm_control_led(1,0);
		sys_timer_usleep(100000);
		sys_sm_control_led(1,1);
		sys_sm_control_led(2,1);
		sys_timer_usleep(250000);
		sys_sm_control_led(2,0);
		sys_sm_control_led(1,1);
		sys_timer_sleep(2);
	}
	else if(strcmp(action,"ledmod_f_z")==0)
	{
		sys_sm_control_led(1,0);
		sys_timer_usleep(100000);
		sys_sm_control_led(1,1);
		sys_sm_control_led(2,1);
		sys_timer_usleep(850000);
		sys_sm_control_led(2,0);
		sys_sm_control_led(1,1);
		sys_timer_sleep(2);
	}
	else if(strcmp(action,"ledmod_bd_an")==0)
	{
		sys_sm_control_led(1,0);
		sys_timer_usleep(100000);
		sys_sm_control_led(2,1);	
		sys_timer_usleep(270000);
		sys_sm_control_led(2,0);
		sys_sm_control_led(1,1);							
		sys_timer_sleep(2);
	}
	else if(strcmp(action,"ledmod_bd_aus")==0)
	{
		sys_sm_control_led(1,0);
		sys_timer_usleep(100000);
		sys_sm_control_led(2,1);
		sys_timer_usleep(850000);
		sys_sm_control_led(2,0);
		sys_sm_control_led(1,1);
		sys_timer_sleep(2);
	}
}

int sys_ss_get_console_id(void * idps)
{
	system_call_1(870, (uint64_t)idps);
	return_to_user_prog(int);
}

int sys_ss_get_open_psid(void * psid)
{
	system_call_1(872, (uint64_t)psid);
	return_to_user_prog(int);
}

void dump_idps()
{
	uint8_t idps[0x10];
	memset(idps, 0, 0x10);
	int ret = sys_ss_get_console_id(idps);
	if (ret == EPERM)
		ret = cellSsAimGetDeviceId(idps);
	if (ret != CELL_OK)
	{
		notify("IDPS Dump failed: %x\n", ret);
		return;
	}
	log_key("IDPS", idps);
	notify("IDPS Dumped!\n%08X%08X\n%08X%08X", *(int*)idps, *((int*)idps + 1), *((int*)idps + 2), *((int*)idps + 3), false);
}

void dump_psid()
{
	uint8_t psid[0x10];
	memset(psid, 0, 0x10);
	int ret = sys_ss_get_open_psid(psid);
	if (ret != CELL_OK)
	{
		notify("PSID Dump failed: %x\n", ret);
		return;
	}
	log_key("PSID", psid);
	notify("PSID Dumped!\n%08X%08X\n%08X%08X", *(int*)psid, *((int*)psid + 1), *((int*)psid + 2), *((int*)psid + 3), false);
}


void rebuild_db()
{	
	int fd;	
	cellFsOpen("/dev_hdd0/mms/db.err", CELL_FS_O_RDWR|CELL_FS_O_CREAT, &fd, NULL, 0);

	uint64_t nrw;
	int rebuild_flag = 0x000003E9;
	cellFsWrite(fd, &rebuild_flag, 4, &nrw);

	cellFsClose(fd);
}


int fs_check()
{
	int ret;
	ret = cellFsUtilMount("CELL_FS_UTILITY:HDD0","CELL_FS_SIMPLEFS","/dev_simple_hdd0",0,0,0,0);
	if(ret != CELL_OK)
	{
		notify("HDD Mount Error: %x",ret);
		return ret;
	}	
	else
	{
		int fd;
		ret = cellFsOpen("/dev_simple_hdd0",CELL_FS_O_RDWR, &fd,0,0);
		if(ret != CELL_OK)
		{
			notify("HDD Open Error: %x",ret);
			return ret;
		}	
		else
		{
			uint64_t pos;
			cellFsLseek(fd,0x10520,0,&pos);
	
			int buf;
			uint64_t nrw;
			cellFsRead(fd,&buf,4,&nrw);

			buf = buf | 4;

			cellFsLseek(fd,0x10520,0,&pos);

			cellFsWrite(fd,&buf,4,&nrw);

			cellFsClose(fd);
		}
		cellFsUtilUnMount("/dev_simple_hdd0",0);
		return CELL_OK;
	}
}


int read_recovery_mode_flag(void * data)
{	
	return update_mgr_read_eprom(RECOVERY_MODE_FLAG_OFFSET,data);
}
int set_recovery_mode_flag(uint8_t value)
{
	return update_mgr_write_eprom(RECOVERY_MODE_FLAG_OFFSET,value);
}
void recovery_mode()
{
	uint8_t data;
	int ret = read_recovery_mode_flag(&data);
	if(ret != 0)
	{
		notify("Read EPROM failed: %0x\n",ret);
		return;
	}
	if(data == 0xFF)
	{
		ret = set_recovery_mode_flag(0x00);
		notify( (ret == 0) ? "Recovery Mode Enabled\n" : "Write EPROM failed: %0x\n", ret);
	}
	if(data == 0x00)
	{
		ret = set_recovery_mode_flag(0xFF);
		notify( (ret == 0) ? "Recovery Mode Disabled\n" : "Write EPROM failed: %0x\n", ret);
	}
}	


int read_product_mode_flag(void * data)
{
	return update_mgr_read_eprom(PRODUCT_MODE_FLAG_OFFSET,data);
}
int set_product_mode_flag(uint8_t value)
{
	return update_mgr_write_eprom(PRODUCT_MODE_FLAG_OFFSET,value);
}
bool service_mode()
{
	uint8_t data;
	int ret = read_product_mode_flag(&data);
	if(ret != 0)
	{
		notify("Read EPROM failed: %0x\n",ret);
		return false;
	}
	if(data == 0xFF)
	{
		log("Looking for lv1 offset\n"); // lets hope this work on all fw's without hardcoding offsets
		for(uint64_t offset = 0xE0000; offset < 0x1000000;offset = offset + 4)
		{
			// ss_server1.fself
			//.text:000000008000ABA8                 bl        update_manager__get_secure_product_mode
			//.text:000000008000ABAC                 cmpwi     cr7, r3, 0
			//.text:000000008000ABB0                 mr        r31, r3
			//.text:000000008000ABB4                 bne       cr7, exit
			//.text:000000008000ABB8                 lbz       r0, 0xF0+var_80+1(r1)
			//.text:000000008000ABBC                 cmpwi     cr7, r0, 0xFF
			//.text:000000008000ABC0                 bne       cr7, allowed			# we're in product mode
			//.text:000000008000ABC4												# we're not in product mode
			//.text:000000008000ABC4                 lbz       r0, 0xF0+arg_40(r1)	# value to write
			//.text:000000008000ABC8                 cmpwi     cr7, r0, 0xFF		# Only allowed to write 0xFF
			//.text:000000008000ABCC                 beq       cr7, allowed
			//.text:000000008000ABD0                 mr        r3, r30
			//.text:000000008000ABD4                 ld        r5, off_C000D738 # asc_80049AB0 # write_eprom() denied
			//.text:000000008000ABD8                 li        r4, 1
			//.text:000000008000ABDC                 li        r31, 5
			if(lv1_peek(offset) == 0x2F8000FF409E0028ULL)
			{
				if(lv1_peek(offset+8) == 0x880101302F8000FFULL)
				{
					log("Found lv1 code @0x%x\n",(int)offset);
					// before
					//.text:000000008000ABBC                 cmpwi     cr7, r0, 0xFF
					//.text:000000008000ABC0                 bne       cr7, allowed
					// after
					//.text:000000008000ABBC                 cmpwi     cr7, r0, 0xFF
					//.text:000000008000ABC0                 b         cr7, allowed
					lv1_poke(offset,0x2F8000FF48000028ULL);
					break;
				}
			}
		}

		ret = set_product_mode_flag(0x00);
		notify( (ret == 0) ? "Product Mode Enabled" : "Write EPROM failed: %0x", ret);
	}
	else if(data == 0x00)
	{
		ret = set_product_mode_flag(0xFF);
		notify( (ret == 0) ? "Product Mode Disabled" : "Write EPROM failed: %0x", ret);
	}
	else
	{
		notify("Unknown EPROM Flag: %x",data);
		return false;
	}
	wait(2);
	return true;
}


char pkg_path[255];
game_ext_plugin_interface * game_ext_interface;

void installPKG_thread()
{
	game_ext_interface = (game_ext_plugin_interface *)GetPluginInterface("game_ext_plugin",1);

	game_ext_interface->DoUnk0();
	log("File: %s\n",pkg_path);
	game_ext_interface->DoUnk34(pkg_path);
}

void installPKG(char * path)
{
	strcpy(pkg_path, path);
	LoadPlugin("game_ext_plugin",(void*)installPKG_thread);
}
void searchDirectory(char * pDirectoryPath, char * fileformat, char * fileout )
{
    int fd;
	int ret; 
	ret = cellFsOpendir(pDirectoryPath, &fd);
	log("cellFsOpendir(pDirectoryPath, &fd) = %x\n",ret);
	
	
    CellFsDirent dirent;
	for(int i = 0; i < 64; i++)
	{
		wait(1);
		uint64_t n;
		ret = cellFsReaddir(fd, &dirent, &n);
		log("cellFsReaddir(fd, &dirent, &n) = %x -> ",ret);
		log(dirent.d_name); log("\n");
		if(CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			if(strncmp(dirent.d_name, fileformat, strlen(fileformat)) == 0)
			{
				strcpy(fileout, pDirectoryPath);
				strcat(fileout, dirent.d_name);
				log("Fileout: %s\n",fileout);
				break;
			}
		}
	}

    ret = cellFsClosedir(fd);
	log("cellFsClosedir(fd) = %x\n",ret);
}

void applicable_version()
{
	//update_mgr_get_appl_ver get_appl_ver;
	uint8_t data[0x20];
	memset(data,0,0x20);

	int ret = GetApplicableVersion(data);
	if(ret != CELL_OK)
	{
		notify("Applicable Version failed: %x\n",ret);
		return;
	}
	
	char tmp[0x20];
	sprintf_(tmp, "Minimum Downgrade: %x.%02x", data[1],data[3]);
	notify(tmp);	
}


wchar_t * url_path;
download_if * download_interface;

void download_thread(int id)
{	

	download_interface = (download_if *)GetPluginInterface("download_plugin",1);
	download_interface->DoUnk5(0,url_path, L"/dev_hdd0"); 	
}

void downloadPKG(wchar_t * url)
{	
	url_path = url;
	LoadPlugin("download_plugin",(void*)download_thread);			
}
