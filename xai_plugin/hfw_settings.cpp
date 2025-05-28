
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

void buzzer(uint8_t mode)
{	
	system_call_3(392, 0x1007, 0xA, mode);
}

int lv2_ss_get_cache_of_flash_ext_flag(uint8_t *flag)
{
	system_call_1(874, (uint64_t) flag);
	return_to_user_prog(int);
}

int sys_storage_open(uint64_t dev_id, int *dev_handle)
{
    system_call_4(600, dev_id, 0, (uint64_t) dev_handle, 0);
    return_to_user_prog(int);
}

int sys_storage_close(int fd)
{
    system_call_1(601, fd);
    return_to_user_prog(int);
}

xBDVD * iBdvd;
xsetting_D0261D72_class* (*xsetting_D0261D72)() = 0;

void hook_func(void * original,void * backup, void * hook_function)
{
	memcpy(backup,original,8); // copy original function offset + toc
	memcpy(original, hook_function ,8); // replace original function offset + toc by hook
}

uint64_t lv1_peek(uint64_t addr)
{
	//system_call_1(8, addr);
	system_call_1(11, addr);
	return_to_user_prog(uint64_t);
}

uint8_t lv1_peek8(uint64_t addr)
{
	return (lv1_peek(addr) >> 56) & 0xFFUL;
}

uint16_t lv1_peek16(uint64_t addr)
{
	return (lv1_peek(addr) >> 48) & 0xFFFFUL;
}

uint32_t lv1_peek32(uint64_t addr)
{
	return (lv1_peek(addr) >> 32) & 0xFFFFFFFFUL;
}

void lv1_poke( uint64_t addr, uint64_t val)
{
	system_call_2(9, addr, val);
}

void lv1_poke8(uint64_t addr, uint8_t value) 
{
    uint64_t old_value = lv1_peek(addr);
    uint64_t new_value = ((old_value & 0xFFFFFFFFFFFFFF00ULL) | value);
    lv1_poke(addr, new_value);
}

void lv1_poke16(uint64_t addr, uint16_t value) 
{
    uint64_t old_value = lv1_peek(addr);
    uint64_t new_value = ((old_value & 0xFFFFFFFFFFFFFF00ULL) | ((uint64_t)value << 8));
    lv1_poke(addr, new_value);
}

void lv1_poke32(uint64_t addr, uint32_t value)
{
	uint64_t old_value = lv1_peek(addr);
	lv1_poke(addr, ((uint64_t)value << 32) | (old_value & 0xFFFFFFFFULL));
}

uint64_t peekq(uint64_t addr) // peekq(0x80000000002E9D70ULL)==0x4345580000000000ULL
{
	system_call_1(6, addr);
	return_to_user_prog(uint64_t);
}

uint32_t peekq32(uint64_t addr) 
{
	return (peekq(addr) >> 32) & 0xFFFFFFFFUL;
}

void pokeq( uint64_t addr, uint64_t val) // pokeq(0x800000000000171CULL,       0x7C0802A6F8010010ULL);
{
	system_call_2(7, addr, val);
}

void pokeq32(uint64_t address, uint32_t value) 
{
	uint64_t old_value = peekq(address);
	pokeq(address, ((uint64_t)value << 32) | (old_value & 0xFFFFFFFFULL));
}

void lv1_read(uint64_t addr, uint64_t size, void *out_Buf)
{
	if (size == 0)
		return;

	uint64_t curOffset = 0;
	uint64_t left = size;

	uint64_t chunkSize = sizeof(uint64_t);

	uint8_t *outBuf = (uint8_t *)out_Buf;

	uint64_t zz = (addr % chunkSize);

	if (zz != 0)
	{
		uint64_t readSize = (chunkSize - zz);

		if (readSize > left)
			readSize = left;

		uint64_t a = (addr - zz);

		uint64_t v = lv1_peek(a);
		uint8_t *vx = (uint8_t *)&v;

		memcpy(&outBuf[curOffset], &vx[zz], readSize);

		curOffset += readSize;
		left -= readSize;
	}

	while (1)
	{
		if (left == 0)
			break;

		uint64_t readSize = (left > chunkSize) ? chunkSize : left;

		uint64_t v = lv1_peek(addr + curOffset);

		memcpy(&outBuf[curOffset], &v, readSize);

		curOffset += readSize;
		left -= readSize;
	}
}

void lv1_write(uint64_t addr, uint64_t size, const void *in_Buf)
{
	if (size == 0)
		return;

	uint64_t curOffset = 0;
	uint64_t left = size;

	uint64_t chunkSize = sizeof(uint64_t);

	const uint8_t *inBuf = (const uint8_t *)in_Buf;

	uint64_t zz = (addr % chunkSize);

	if (zz != 0)
	{
		uint64_t writeSize = (chunkSize - zz);

		if (writeSize > left)
			writeSize = left;

		uint64_t a = (addr - zz);

		uint64_t v = lv1_peek(a);
		uint8_t *vx = (uint8_t *)&v;

		memcpy(&vx[zz], &inBuf[curOffset], writeSize);

		lv1_poke(a, v);

		curOffset += writeSize;
		left -= writeSize;
	}

	while (1)
	{
		if (left == 0)
			break;

		uint64_t writeSize = (left > chunkSize) ? chunkSize : left;

		uint64_t v = lv1_peek(addr + curOffset);
		memcpy(&v, &inBuf[curOffset], writeSize);

		lv1_poke(addr + curOffset, v);

		curOffset += writeSize;
		left -= writeSize;
	}
}

static inline uint64_t lv1_read2(uint64_t addr)
{
    uint64_t v = 0;
    // read exactly 8 bytes into v
    lv1_read(addr, sizeof(v), &v);
    return v;
}

static inline void lv1_write2(uint64_t addr, uint64_t value)
{
    // write exactly 8 bytes from value
    lv1_write(addr, sizeof(value), &value);
}

uint32_t GetApplicableVersion(void * data)
{
	system_call_8(863, 0x6011, 1,(uint64_t)data,0,0,0,0,0);
	return_to_user_prog(uint32_t);

}

int sys_game_get_temperature(int sel, uint32_t *temperature) 
{
    uint32_t temp;  
    system_call_2(383, (uint64_t) sel, (uint64_t) &temp);
    *temperature = (temp >> 24);
    return_to_user_prog(int);
}

uint32_t celsius_to_fahrenheit(uint32_t *temp)
{
	uint32_t f_temp = 0;
	f_temp = ((uint32_t)(*temp * 9 / 5) + 32);
	return f_temp;
}

process_id_t vsh_pid = 0;

int poke_vsh(uint64_t address, char *buf, int size)
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

int read_vsh(uint64_t address, char *buf, int size)
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
	system_call_6(8, SYSCALL8_OPCODE_PS3MAPI, PS3MAPI_OPCODE_GET_PROC_MEM, vsh_pid, address, (uint64_t)(uint32_t)buf, size);
}

//TODO: Fix this function
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset)
{
	if (reset)
	{
		reset_psn_patches();
		poke_vsh(paddr, (char*)&pbytes, 4);
	}
	else
	{
		poke_vsh(paddr, (char*)&pbytes, 4);
	}
}

void reset_psn_patches()
{
	uint32_t amazon1 = 0x3D200072;
	uint32_t amazon2 = 0x7C0802A6;
	//uint32_t hulu1 = 0x2B9D0001;
	//uint32_t hulu2 = 0x3C608002;
	uint32_t youtube = 0x2F800000;
	poke_vsh(0x242454, (char*)&amazon1, 4);
	poke_vsh(0x242458, (char*)&amazon2, 4);
	//poke_vsh(0x2455BC, (char*)&hulu1, 4);
	//poke_vsh(0x2455C0, (char*)&hulu2, 4);
	poke_vsh(0x1B60A4, (char*)&youtube, 4);
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

	(void*&)(allocator_759E0635) = (void*)((int)getNIDfunc("allocator", 0x759E0635));
	(void*&)(allocator_77A602DD) = (void*)((int)getNIDfunc("allocator", 0x77A602DD));

	(void*&)(vsh_sprintf) = (void*)((int)getNIDfunc("stdc", 0x273B9711));
}

/*void convert_utf16_to_ascii(const uint16_t *utf16, char *ascii, size_t maxLen)
{
    size_t i = 0;
    while(i < maxLen - 1 && utf16[i] != 0)
    {
        ascii[i] = (char)utf16[i];
        i++;
    }
    ascii[i] = '\0';
}

void ascii_to_utf16(const char *ascii, uint16_t *utf16, size_t maxLen)
{
    size_t i = 0;
    while (i < maxLen - 1 && ascii[i] != '\0')
    {
         utf16[i] = (uint16_t)ascii[i];
         i++;
    }
    utf16[i] = 0;
}

int getHexInput(const char *prompt, uint64_t *outValue)
{
    int ret;
    CellOskDialogParam dialogParam;
    memset(&dialogParam, 0, sizeof(dialogParam));

    // Configure dialog parameters.
    dialogParam.allowOskPanelFlg = CELL_OSKDIALOG_FULLKEY_PANEL;
    dialogParam.firstViewPanel = CELL_OSKDIALOG_PANELMODE_ALPHABET;
    dialogParam.controlPoint.x = 100.0f;
    dialogParam.controlPoint.y = 100.0f;
    dialogParam.prohibitFlgs = CELL_OSKDIALOG_NO_RETURN;

    // Create local buffers for the UTF-16 prompt and initial text.
    uint16_t utf16Prompt[256];
    uint16_t utf16InitText[16];
    ascii_to_utf16(prompt, utf16Prompt, sizeof(utf16Prompt) / sizeof(uint16_t));
    ascii_to_utf16("0x", utf16InitText, sizeof(utf16InitText) / sizeof(uint16_t));

    CellOskDialogInputFieldInfo inputFieldInfo;
    // Use the converted UTF-16 strings instead of L(prompt)
    inputFieldInfo.message = utf16Prompt;
    inputFieldInfo.init_text = utf16InitText;
    inputFieldInfo.limit_length = 32;

    // Load the OSK dialog asynchronously.
    ret = cellOskDialogLoadAsync(0, &dialogParam, &inputFieldInfo);
    if(ret != 0)
    {
        printf("cellOskDialogLoadAsync failed: 0x%x\n", ret);
        return ret;
    }

    // Poll for user input.
    CellOskDialogCallbackReturnParam callbackParam;
    memset(&callbackParam, 0, sizeof(callbackParam));
    while (1)
    {
        ret = cellOskDialogGetInputText(&callbackParam);
        if(ret == 0)
        {
            if (callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_OK ||
                callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_CANCELED ||
                callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_ABORT)
            {
                break;
            }
        }
        sys_timer_usleep(100 * 1000);  // wait 100ms
    }

    // Unload the OSK dialog.
    cellOskDialogUnloadAsync(&callbackParam);

    // If the input was confirmed, convert the UTF-16 result to ASCII.
    if (callbackParam.result == CELL_OSKDIALOG_INPUT_FIELD_RESULT_OK)
    {
        char asciiInput[256];
        // Here, convert_utf16_to_ascii() converts the OSK result (callbackParam.pResultString) into a C string.
        convert_utf16_to_ascii(callbackParam.pResultString, asciiInput, sizeof(asciiInput));
        printf("User entered: %s\n", asciiInput);
        *outValue = strtoull(asciiInput, NULL, 16);
        return 0;
    }
    else
    {
        printf("Input canceled or error (result = %d)\n", callbackParam.result);
        return -1;
    }
}*/

int dump_lv2()
{
	int final_offset;
	int mem = 0, max_offset = 0x40000;
	int fd, fseek_offset = 0, start_offset = 0;

	char usb[120], dump_file_path[120], lv_file[120];

	uint8_t platform_info[0x18];
	uint64_t nrw, seek, offset_dumped;
	CellFsStat st;	

	// Check if CFW Syscalls are disabled
	if(peekq(0x8000000000363BE0ULL) == 0xFFFFFFFF80010003ULL)
	{
		notify("Syscalls are disabled");
		return 1;
	}
	
    system_call_1(387, (uint64_t)platform_info);

	final_offset = 0x800000ULL;	

	vsh_sprintf(lv_file, LV2_DUMP, platform_info[0], platform_info[1], platform_info[2] >> 4);	
	vsh_sprintf(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);

	for(int i = 0; i < 127; i++)
	{				
		vsh_sprintf(usb, "/dev_usb%03d", i, NULL);

		if(!cellFsStat(usb, &st))
		{
			vsh_sprintf(dump_file_path, "%s/%s", (int)usb, (int)lv_file);
			break;
		}
	}

	if(cellFsOpen(dump_file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
	{
		notify("An error occurred while dumping LV2");
		return 1;
	}

	cellFsChmod(dump_file_path, 0666);

	notify("Dumping LV2, please wait...");

	// Quickest method to dump LV2 and LV1 through xai_plugin
	// Default method will take at least two minutes to dump LV2, and even more for LV1
	uint8_t *dump = (uint8_t *)allocator_759E0635(0x40000);
	memset(dump, 0, 0x40000);			

	for(uint64_t offset = start_offset; offset < max_offset; offset += 8)
	{
		offset_dumped = peekq(0x8000000000000000ULL + offset);

		memcpy(dump + mem, &offset_dumped, 8);

		mem += 8;

		if(offset == max_offset - 8)
		{
			//cellFsLseek(fd, fseek_offset, SEEK_SET, &seek);
			if(cellFsWrite(fd, dump, 0x40000, &nrw) != SUCCEEDED)
			{
				allocator_77A602DD(dump);				
				cellFsClose(fd);
				cellFsUnlink(dump_file_path);
				notify("An error occurred while dumping LV2");		

				return 1;
			}

			// Done dumping
			if(max_offset == final_offset)
				break;

			fseek_offset += 0x40000;
			memset(dump, 0, 0x40000);
			mem = 0;

			start_offset = start_offset + 0x40000;
			max_offset = max_offset + 0x40000;
		}
	}

	allocator_77A602DD(dump);
	cellFsClose(fd);

	notify("LV2 dumped in\n%s", dump_file_path);
	buzzer(SINGLE_BEEP);

	return 0;
}


int dump_lv1()
{
    int final_offset;
    int mem = 0, max_offset = 0x40000;
    int fd, fseek_offset = 0, start_offset = 0;

    char usb[120], dump_file_path[120], lv_file[120];

    uint8_t platform_info[0x18];
    uint64_t nrw, seek, offset_dumped;
    CellFsStat st;  

    // Check if CFW Syscalls are disabled
    if(peekq(0x8000000000363BE0ULL) == 0xFFFFFFFF80010003ULL)
    {
        notify("Syscalls are disabled");
        return 1;
    }
    
    system_call_1(387, (uint64_t)platform_info);

    final_offset = 0x1000000ULL;

    vsh_sprintf(lv_file, LV1_DUMP, platform_info[0], platform_info[1], platform_info[2] >> 4);  
    vsh_sprintf(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);

    for(int i = 0; i < 127; i++)
    {                
        vsh_sprintf(usb, "/dev_usb%03d", i, NULL);

        if(!cellFsStat(usb, &st))
        {
            vsh_sprintf(dump_file_path, "%s/%s", (int)usb, (int)lv_file);
            break;
        }
    }

    if(cellFsOpen(dump_file_path, CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR, &fd, 0, 0) != SUCCEEDED)
    {
        notify("An error occurred while dumping LV1");
        return 1;
    }

    cellFsChmod(dump_file_path, 0666);

    notify("Dumping LV1, please wait...");

    // Quickest method to dump LV2 and LV1 through xai_plugin
    // Default method will take at least two minutes to dump LV2, and even more for LV1
    uint8_t *dump = (uint8_t *)allocator_759E0635(0x40000);
    memset(dump, 0, 0x40000);            

    for(uint64_t offset = start_offset; offset < max_offset; offset += 8)
    {
        // Use lv1_read to fetch data
        lv1_read(0x8000000000000000ULL + offset, 8, &offset_dumped);

        memcpy(dump + mem, &offset_dumped, 8);

        mem += 8;

        if(offset == max_offset - 8)
        {
            //cellFsLseek(fd, fseek_offset, SEEK_SET, &seek);
            if(cellFsWrite(fd, dump, 0x40000, &nrw) != SUCCEEDED)
            {
                allocator_77A602DD(dump);                
                cellFsClose(fd);
                cellFsUnlink(dump_file_path);
                notify("An error occurred while dumping LV1");        

                return 1;
            }

            // Done dumping
            if(max_offset == final_offset)
                break;

            fseek_offset += 0x40000;
            memset(dump, 0, 0x40000);
            mem = 0;

            start_offset = start_offset + 0x40000;
            max_offset = max_offset + 0x40000;
        }
    }

    allocator_77A602DD(dump);
    cellFsClose(fd);

    notify("LV1 dumped in\n%s", dump_file_path);
    buzzer(SINGLE_BEEP);

    return 0;
}

// 3141card's PS3 Unlock HDD Space
void unlock_hdd_space()
{
	uint64_t offset1 = 0, offset2 = 0;
	uint64_t value1 = 0, value2 = 0;

	// Check if CFW Syscalls are disabled
	if(peekq(0x8000000000363BE0ULL) == 0xFFFFFFFF80010003ULL)
	{
		notify("Syscalls are disabled");
		return;
	}

	for(uint64_t i = 0x8000000000590000ULL; i < 0x8000000000640000ULL; i += 8)
	{
		if(peekq(i) == 0xFFFFC000FFFFF000ULL && peekq(i + 0x90) == 0x6C5F6D775F636673ULL)
		{
			offset1 = i - 0x0C;
			offset2 = i + 0x38;

			value1 = peekq32(offset1);

			if(value1 == 0x08)
			{
				// Unlock 
				pokeq32(offset1, 0x01);
				pokeq32(offset2, 0x01);			

				if(peekq32(offset1) != 0x01 && peekq32(offset2) != 0x01)
					goto error;
			}
			else
			{				
				// Restore
				pokeq32(offset1, 0x08);
				pokeq32(offset2, 0x00);

				if(peekq32(offset1) != 0x08 && peekq32(offset2) != 0x00)
					goto error;
			}

			if(peekq32(offset1) == 0x08)
				notify("Restored HDD space");
			else
				notify("Unlocked HDD space");
			
			return;
		}		
	}

error:
	notify("Unable to toggle HDD space");
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

void check_temperature()
{
	uint32_t temp_cpu_c = 0, temp_rsx_c = 0;
	uint32_t temp_cpu_f = 0, temp_rsx_f = 0;

	// Enabling sys_game_get_temperature() in 4.90 CEX
	pokeq32(0x800000000000C6A4ULL, 0x38600000);

	sys_game_get_temperature(0, &temp_cpu_c);
    sys_game_get_temperature(1, &temp_rsx_c);

	temp_cpu_f = celsius_to_fahrenheit(&temp_cpu_c);
	temp_rsx_f = celsius_to_fahrenheit(&temp_rsx_c);

	if(!temp_cpu_c || !temp_rsx_c || !temp_cpu_f || !temp_rsx_f)
		notify("Unable to get temperature values");
	else
		notify("[CPU: %uC] - [RSX: %uC]\n[CPU: %uF] - [RSX: %uF]", (int)temp_cpu_c, (int)temp_rsx_c, (int)temp_cpu_f, (int)temp_rsx_f);
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

void read_qa_flag()
{
	uint8_t value = 0;
	update_mgr_read_eprom(QA_FLAG_OFFSET, &value);

	if(!value)
		notify("QA Flags are enabled");
	else
		notify("QA Flags are disabled");
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

void write_toggle(char* path_to_file, char* message)
{
	int fd = 0;
	cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
	cellFsClose(fd);
	notify("%s", message);
}

void toggle_generic(char* path_to_file, char* name, int reverse_toggle)
{
	int ret = 0;
	int fd = 0;
	CellFsStat stat;
	ret = cellFsStat(path_to_file, &stat);
	if (ret != CELL_OK)
	{
		if (reverse_toggle == 0)
		{
			cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
			cellFsClose(fd);
			notify("%s Disabled", name);
		}
		else
		{
			cellFsOpen(path_to_file, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fd, 0, 0);
			cellFsClose(fd);
			notify("%s Enabled", name);
		}
	}
	else
	{
		if (reverse_toggle == 0)
		{
			cellFsUnlink(path_to_file);
			notify("%s Enabled", name);
		}
		else
		{
			cellFsUnlink(path_to_file);
			notify("%s Disabled", name);
		}
	}
}

void read_write_generic(const char* src, const char* dest)
{
	int ret, fda;
	ret = cellFsOpen(src, CELL_FS_O_RDONLY, &fda, 0, 0);

	if (ret != CELL_OK)
		notify("%s Open Error: %x", src, ret);
	else
	{
		int fdb;
		ret = cellFsOpen(dest, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fdb, 0, 0);

		//log("src: %s\n", (char*)src);
		//log("dest: %s\n", (char*)dest);

		uint8_t buf[0x1000];
		uint64_t nr, nrw;

		while ((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
		{
			if ((int)nr > 0)
			{
				ret = cellFsWrite(fdb, buf, nr, &nrw);

				if (ret != CELL_FS_SUCCEEDED)
				{
					notify("%s Copy Error: %x", src, ret);
					return;
				}

				memset(buf, 0, 0x1000);
			}
			else
				break;
		}

		cellFsChmod(dest, 0666);

		cellFsClose(fda);
		cellFsClose(fdb);

		//notify("%s created!", (char*)dest);
	}
}

void read_write_generic_notify(const char* src, const char* dest)
{
	int ret, fda;
	ret = cellFsOpen(src, CELL_FS_O_RDONLY, &fda, 0, 0);

	if (ret != CELL_OK)
		notify("%s Open Error: %x", src, ret);
	else
	{
		int fdb;
		ret = cellFsOpen(dest, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fdb, 0, 0);

		//log("src: %s\n", (char*)src);
		//log("dest: %s\n", (char*)dest);

		uint8_t buf[0x1000];
		uint64_t nr, nrw;

		while ((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
		{
			if ((int)nr > 0)
			{
				ret = cellFsWrite(fdb, buf, nr, &nrw);

				if (ret != CELL_FS_SUCCEEDED)
				{
					notify("%s Copy Error: %x", src, ret);
					return;
				}

				memset(buf, 0, 0x1000);
			}
			else
				break;
		}

		cellFsChmod(dest, 0666);

		cellFsClose(fda);
		cellFsClose(fdb);

		notify("%s created!", (char*)dest);
	}
}

void read_write_generic2(const char* src, const char* dest, CellFsMode chmod)
{
	int ret, fda;
	ret = cellFsOpen(src, CELL_FS_O_RDONLY, &fda, 0, 0);

	if (ret != CELL_OK)
		notify("%s Open Error: %x", src, ret);
	else
	{
		int fdb;
		ret = cellFsOpen(dest, CELL_FS_O_CREAT | CELL_FS_O_RDWR, &fdb, 0, 0);

		//log("src: %s\n", (char*)src);
		//log("dest: %s\n", (char*)dest);

		uint8_t buf[0x1000];
		uint64_t nr, nrw;

		while ((ret = cellFsRead(fda, buf, 0x1000, &nr)) == CELL_FS_SUCCEEDED)
		{
			if ((int)nr > 0)
			{
				ret = cellFsWrite(fdb, buf, nr, &nrw);

				if (ret != CELL_FS_SUCCEEDED)
				{
					notify("%s Copy Error: %x", src, ret);
					return;
				}

				memset(buf, 0, 0x1000);
			}
			else
				break;
		}

		cellFsChmod(dest, chmod);

		cellFsClose(fda);
		cellFsClose(fdb);

		//notify("%s created!", (char*)dest);
	}
}

void remove_directory(char*src)
{
	int fd;
	int ret;
	char list[1024];
	ret = cellFsOpendir(src, &fd);
	//log("cellFsOpendir(%s, &fd) = %x\n", (char*)src, (char*)ret);

	CellFsDirent dirent;
	uint64_t n;
	while ((ret = cellFsReaddir(fd, &dirent, &n)) == CELL_FS_SUCCEEDED && n > 0)
	{
		//log("cellFsReaddir(fd, &dirent, &n) = %x -> ", ret);
		//log(dirent.d_name); log("\n");

		if (CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			//log("Fileout: %s\n", list);

			// Delete file
			ret = cellFsUnlink(list);
			//log("cellFsUnlink(%s) = %x\n", (char*)list, (char*)ret);
		}
		else if (strcmp(dirent.d_name, ".") != 0 && strcmp(dirent.d_name, "..") != 0)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			//log("Dirout: %s\n", list);

			// Recursively delete subdirectory
			remove_directory(list);

			// Delete empty subdirectory
			ret = cellFsRmdir(list);
			//log("cellFsRmdir(%s) = %x\n", (char*)list, (char*)ret);
		}
	}

	ret = cellFsClosedir(fd);
	//log("cellFsClosedir(fd) = %x\n", ret);
}

/*
void remove_directory_bug(char*_src)
{
	int fd;
	int ret;
	char list[1024];
	char src[1024];
	vsh_sprintf(src, "/dev_hdd0/theme/../..%s", _src);// Insert recursive bug in path
	ret = cellFsOpendir(src, &fd);
	log("cellFsOpendir(%s, &fd) = %x\n", (char*)src, (char*)ret);

	CellFsDirent dirent;
	uint64_t n;
	while ((ret = cellFsReaddir(fd, &dirent, &n)) == CELL_FS_SUCCEEDED && n > 0)
	{
		log("cellFsReaddir(fd, &dirent, &n) = %x -> ", ret);
		log(dirent.d_name); log("\n");

		if (CELL_FS_TYPE_DIRECTORY != dirent.d_type)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			log("Fileout: %s\n", list);

			// Delete file
			ret = cellFsUnlink(list);
			log("cellFsUnlink(%s) = %x\n", (char*)list, (char*)ret);
		}
		else if (strcmp(dirent.d_name, ".") != 0 && strcmp(dirent.d_name, "..") != 0)
		{
			vsh_sprintf(list, "%s/%s", src, dirent.d_name);
			log("Dirout: %s\n", list);

			// Recursively delete subdirectory
			remove_directory(list);

			// Delete empty subdirectory
			ret = cellFsRmdir(list);
			log("cellFsRmdir(%s) = %x\n", (char*)list, (char*)ret);
		}
	}

	ret = cellFsClosedir(fd);
	log("cellFsClosedir(fd) = %x\n", ret);
}
*/

void remove_file(char* path_to_file, char* message)
{
	cellFsUnlink(path_to_file);
	char text[256];
	vsh_sprintf(text, "Removed: %s.\n%s",path_to_file, message);
	notify("%s", text);
}

int dump_full_ram() {
    //#define CHUNK_SIZE    0x10000        // 64 KB
    #define CHUNK_SIZE    0x40000        // 256 KB
    #define FULL_RAM_SIZE 0x10000000ULL    // 256 MB

	uint8_t platform_info[0x18];
	system_call_1(387, (uint64_t)platform_info);

    char dump_file_path[120], lv_file[120];

	vsh_sprintf(lv_file, RAM_DUMP, platform_info[0], platform_info[1], platform_info[2] >> 4);  
    //vsh_sprintf(dump_file_path, "%s/%s", (int)TMP_FOLDER, (int)lv_file);
    vsh_sprintf(dump_file_path, "%s/%s", TMP_FOLDER, RAM_DUMP);

    // Check for an attached USB drive; if found, use its path instead.
    char usb[120];
    CellFsStat st;
    for (int i = 0; i < 8; i++) {
        vsh_sprintf(usb, "/dev_usb%03d", i);
        if (cellFsStat(usb, &st) == CELL_FS_SUCCEEDED) {
            vsh_sprintf(dump_file_path, "%s/%s", usb, RAM_DUMP);
            break;
        }
    }

    int fd;
    if (cellFsOpen(dump_file_path,
                   CELL_FS_O_CREAT | CELL_FS_O_TRUNC | CELL_FS_O_RDWR,
                   &fd, 0, 0) != CELL_FS_SUCCEEDED) {
        notify("Failed to open dump file: %s", dump_file_path);
        return 1;
    }
    cellFsChmod(dump_file_path, 0666);
    notify("Starting full RAM dump");

    uint8_t *buffer = (uint8_t *)allocator_759E0635(CHUNK_SIZE);
    if (!buffer) {
        notify("Memory allocation error");
        cellFsClose(fd);
        return 1;
    }
    memset(buffer, 0, CHUNK_SIZE);

    uint64_t offset = 0;
    uint64_t nrw = 0;
    while (offset < FULL_RAM_SIZE) {
        // Use lv1_read to fetch the memory chunk
        lv1_read(0x8000000000000000ULL + offset, CHUNK_SIZE, buffer);

        if (cellFsWrite(fd, buffer, CHUNK_SIZE, &nrw) != CELL_FS_SUCCEEDED) {
            notify("Error writing dump at offset 0x%llX", offset);
            allocator_77A602DD(buffer);
            cellFsClose(fd);
            return 1;
        }

        sys_timer_usleep(1000);
        offset += CHUNK_SIZE;
    }

    allocator_77A602DD(buffer);
    cellFsClose(fd);
    notify("Full RAM dump complete:\n%s", dump_file_path);
    buzzer(SINGLE_BEEP);
    return 0;
}

// BadHTAB LV1 Testing
/*
uint64_t lv1_peek2(uint64_t addr) {
    if ((addr & 7ULL) == 0)
        return lv1_peek(addr);
    
    uint64_t aligned = addr & ~7ULL;
    int offset = addr & 7;
    uint64_t first  = lv1_peek(aligned);
    uint64_t second = lv1_peek(aligned + 8);
    
    int numFirstBytes = 8 - offset;
    uint64_t mask = (1ULL << (numFirstBytes * 8)) - 1;
    uint64_t part1 = first & mask;
    uint64_t part2 = second >> (numFirstBytes * 8);
    
    return (part1 << (offset * 8)) | part2;
}

void lv1_poke2(uint64_t addr, uint64_t val)
{
    // If address is already aligned, use the standard poke.
    if ((addr & 7ULL) == 0) {
        lv1_poke(addr, val);
        return;
    }

    // Calculate the aligned base address and the offset within it.
    uint64_t aligned = addr & ~7ULL;  // aligned address (multiple of 8)
    int r = addr & 7;                 // offset in bytes (1..7)
    int numFirst = 8 - r;             // number of bytes in the first word to update

    // Read the two aligned 64-bit words covering the region.
    uint64_t orig1 = lv1_peek(aligned);
    uint64_t orig2 = lv1_peek(aligned + 8);

    // For the first aligned word:
    // We want to replace its lower (numFirst*8) bits with the upper part of val.
    // Create a mask to isolate the lower numFirst bytes.
    uint64_t mask1 = (1ULL << (numFirst * 8)) - 1;
    // Extract from val the bits that should go into the first word.
    // (Shift val right by r bytes so that its upper (8 - r) bytes line up.)
    uint64_t A = val >> (r * 8);
    // Build the new first word by preserving the upper bytes and inserting A.
    uint64_t new1 = (orig1 & ~mask1) | (A & mask1);

    // For the second aligned word:
    // We want to replace its upper r bytes with the lower part of val.
    // Create a mask that isolates the upper r bytes.
    uint64_t mask2 = 0xFFFFFFFFFFFFFFFFULL << ((8 - r) * 8);
    // Extract the lower r bytes from val.
    uint64_t B = val & ((1ULL << (r * 8)) - 1);
    // Build the new second word:
    // Preserve the lower (8 - r) bytes of orig2 and insert B shifted into the upper r bytes.
    uint64_t new2 = (orig2 & ~mask2) | (B << ((8 - r) * 8));

    // Write back the modified aligned words.
    lv1_poke(aligned, new1);
    lv1_poke(aligned + 8, new2);
}
*/

// Patches the 64-bit word at addr only if (current & mask) equals (expected & mask).
// Then it writes (current & ~mask) | (patch & mask) to preserve any bytes outside the mask.
bool lv1_patch_pattern(uint64_t addr, uint64_t expected, uint64_t patch, uint64_t mask)
{
    uint64_t current = lv1_peek(addr);
    if ((current & mask) != (expected & mask))
    {
        return false;
    }
    
    // Construct the new value: preserve bytes outside the mask,
    // and use patch bytes for the masked part.
    uint64_t new_val = (current & ~mask) | (patch & mask);
    lv1_poke(addr, new_val);
    
    return (lv1_peek(addr) & mask) == (patch & mask);
}

bool test_lv1_peek()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79 20 43 65 6C  Sony Cel
	uint64_t val = lv1_peek(addr);

	if (val != 0 && val != 0xFFFFFFFFFFFFFFFFULL)
	{
		notify64("lv1_peek() success\naddr: 0x%016llX\nval: 0x%016llX", addr, val);
		return true;
	}
	else
	{
		notify64("lv1_peek() failed\naddr: 0x%016llX\nval: 0x%016llX", addr, val);
		return false;
	}
}

bool test_lv1_peek32()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79  Sony
	uint32_t val = lv1_peek32(addr);

	if (val != 0 && val != 0xFFFFFFF)
	{
		notify("lv1_peek32() success\naddr: 0x%08X\nval: 0x%08X", addr, val);
		return true;
	}
	else
	{
		notify("lv1_peek32() failed\naddr: 0x%08X\nval: 0x%08X", addr, val);
		return false;
	}
}

bool test_lv1_poke()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 79 20 43 65 6C  Sony Cel
	//uint64_t patch = 0x7C01012438000000ULL;
	uint64_t patch = 0x4141414142424242ULL;// 0x536F6E792043656CULL
	uint64_t original = lv1_peek(addr);
	
	lv1_poke(addr, patch);
	

	uint64_t verify = lv1_peek(addr);

	if (verify == patch)
	{
		notify64("lv1_poke() success\naddr: 0x%016llX\npatch: 0x%016llX\noriginal: 0x%016llX", addr, patch, original);
		return true;
	}
	else
	{
		notify64("lv1_poke() failed\naddr: 0x%016llX\npatch: 0x%016llX\noriginal: 0x%016llX", addr, patch, original);
		return false;
	}
}

bool test_lv1_poke32()
{
	//uint64_t addr = 0x1130;
	uint64_t addr = 0x323740;// 0000000000323740  53 6F 6E 7  Sony
	//uint32_t patch = 0x7C010124;
	uint32_t patch = 0x41414141;// 0x536F6E79
	//uint32_t patch2 = 0x42424242;// 0x2043656C
	uint32_t original = lv1_peek32(addr);
	
	lv1_poke32(addr, patch);
	

	uint32_t verify = lv1_peek32(addr);

	if (verify == patch)
	{
		notify("lv1_poke32() success\naddr: 0x%08X\npatch: 0x%08X\noriginal: 0x%08X", addr, patch, original);
		return true;
	}
	else
	{
		notify("lv1_poke32() failed\naddr: 0x%08X\npatch: 0x%08X\noriginal: 0x%08X", addr, patch, original);
		return false;
	}
}

int unmask_bootldr()
{
    uint64_t addr1 = 0x27B638;
    uint64_t addr2 = 0x27B640;

    uint64_t orig1 = 0x7C7F1B7839840200ULL;
    uint64_t orig2 = 0xF8010090FBC10070ULL;

    uint64_t patch1 = 0x7C7F1B7800000000ULL;
    uint64_t patch2 = 0x00000000FBC10070ULL;

    uint64_t full_mask = 0xFFFFFFFFFFFFFFFFULL;

    bool patch1_ok = lv1_patch_pattern(addr1, orig1, patch1, full_mask);
    bool patch2_ok = lv1_patch_pattern(addr2, orig2, patch2, full_mask);

    if (patch1_ok && patch2_ok)
    {
        notify("Apply LV1 Patch 1: Unmask bootldr Success at 0x%016llX", lv1_peek(addr1));
        notify("Apply LV1 Patch 2: Unmask bootldr Success at 0x%016llX", lv1_peek(addr2));
        return 0;
    }
    else
    {
        notify("Apply LV1 Patch Failed at 0x%016llX\nval:0x%016llX", addr1, lv1_peek(addr1));
        notify("Apply LV1 Patch Failed at 0x%016llX\nval:0x%016llX", addr2, lv1_peek(addr2));
        return 1;
    }
}

int toggle_lv1_patch(const char* name, uint64_t addr, uint64_t ovalue, uint64_t pvalue)
{
	uint64_t verify = 0;
	uint64_t cvalue = lv1_peek(addr);
	//notify("Current Value 0x%016llX", cvalue);

	if(cvalue==ovalue)
	{
		lv1_poke(addr, pvalue);
		verify = lv1_peek(addr);
		if (verify == pvalue)
		{
			notify64("Apply LV1 Patch: %s Success\naddr: 0x%016llX\ncvalue: 0x%016llX\nverify: 0x%016llX", (char*)name, addr, cvalue, verify);
			return 0;
		}
		else
		{
			notify64("Apply LV1 Patch: %s Failed\naddr: 0x%016llX\ncvalue: 0x%08X\nverify: 0x%016llX", (char*)name, addr, cvalue, verify);
			return 1;
		}
	}
	else
	{
		//notify64("Expected Original Value Not Found\naddr: 0x%016llX\ncvalue: 0x%08X\npvalue: 0x%016llX", (char*)name, addr, cvalue, ovalue);
	}

	if(cvalue==pvalue)
	{
		lv1_poke(addr, ovalue);
		verify = lv1_peek(addr);
		if (verify == ovalue)
		{
			notify64("Restore LV1 Patch: %s Success\naddr: 0x%016llX\ncvalue: 0x%016llX\nverify: 0x%016llX", (char*)name, addr, cvalue, verify);
			return 0;
		}
		else
		{
			notify64("Restore LV1 Patch: %s Failed\naddr: 0x%016llX\ncvalue: 0x%016llX\nverify: 0x%016llX", (char*)name, addr, cvalue, verify);
			return 1;
		}
	}
	else
	{
		//notify64("Expected Patched Value Not Found\naddr: 0x%016llX\ncvalue: 0x%016llX\npvalue: 0x%016llX", (char*)name, addr, cvalue, pvalue);
	}
}

int toggle_lv1_patch32(const char* name, uint64_t addr, uint32_t ovalue, uint32_t pvalue)
{
	uint32_t verify = 0;
	uint32_t cvalue = lv1_peek32(addr);
	//notify("Current Value 0x%08X", cvalue);

	if(cvalue==ovalue)
	{
		lv1_poke32(addr, pvalue);
		verify = lv1_peek32(addr);
		if (verify == pvalue)
		{
			notify("Apply LV1 32-bit Patch: %s Success\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify);
			return 0;
		}
		else
		{
			notify("Apply LV1 32-bit Patch: %s Failed\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify);
			return 1;
		}
	}
	else
	{
		//notify("Expected Original Value Not Found\naddr: 0x%08X\ncvalue: 0x%08X\npvalue: 0x%08X", (char*)name, addr, cvalue, ovalue);
	}

	if(cvalue==pvalue)
	{
		lv1_poke32(addr, ovalue);
		verify = lv1_peek32(addr);
		if (verify == ovalue)
		{
			notify("Restore LV1 32-bit Patch: %s Success\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify);
			return 0;
		}
		else
		{
			notify("Restore LV1 32-bit Patch: %s Failed\naddr: 0x%08X\ncvalue: 0x%08X\nverify: 0x%08X", (char*)name, addr, cvalue, verify);
			return 1;
		}
	}
	else
	{
		//notify("Expected Patched Value Not Found\naddr: 0x%08X\ncvalue: 0x%08X\npvalue: 0x%08X", (char*)name, addr, cvalue, pvalue);
	}
}

/*int lv1_peek_keyboard()
{
    uint64_t addr, value;
    // Prompt user for address input
    if(getHexInput("Enter hex address to peek:", &addr) != 0) {
         notify("Failed to get address input.");
         return -1;
    }
    // Call the low-level peek
    value = lv1_peek(addr);
    // Display the result
    notify64("Peek: addr: 0x%016llX, value: 0x%016llX", addr, value);
    return 0;
}

int lv1_poke_keyboard()
{
    uint64_t addr, value, verify;
    // Prompt user for address input
    if(getHexInput("Enter hex address to poke:", &addr) != 0) {
         notify("Failed to get address input.");
         return -1;
    }
    // Prompt user for value input
    if(getHexInput("Enter hex value to poke:", &value) != 0) {
         notify("Failed to get value input.");
         return -1;
    }
    // Write the value
    lv1_poke(addr, value);
    // Verify the write by reading back the value
    verify = lv1_peek(addr);
    if(verify == value) {
         notify64("Poke: Success.\naddr: 0x%016llX, value: 0x%016llX", addr, verify);
         return 0;
    } else {
         notify64("Poke: Failed.\naddr: 0x%016llX, expected: 0x%016llX, got: 0x%016llX", addr, value, verify);
         return 1;
    }
}*/


#define USB_PATH    "/dev_usb000"
#define CHUNK_SZ    0x10000ULL
#define HV_BASE     0x8000000000000000ULL

//------------------------------------------------------------------------------
// Generic dumper: read HV @ (HV_BASE+phys) for 'size' bytes and write to USB_PATH/fname
//------------------------------------------------------------------------------
static int dump_hv_region(const char *fname, uint64_t phys, uint64_t size) {
    char path[128];
    vsh_sprintf(path, "%s/%s", USB_PATH, fname);

    int fd;
    if (cellFsOpen(path,
                   CELL_FS_O_CREAT|CELL_FS_O_TRUNC|CELL_FS_O_RDWR,
                   &fd, NULL, 0) != CELL_FS_SUCCEEDED) {
        notify("OPEN_FAIL %s", path);
        return -1;
    }
    cellFsChmod(path, 0666);

    uint8_t *buf = (uint8_t*)allocator_759E0635(CHUNK_SZ);
    if (!buf) {
        notify("ALLOC_FAIL");
        cellFsClose(fd);
        return -1;
    }

    uint64_t off = 0, written;
    while (off < size) {
        uint64_t chunk = (size - off > CHUNK_SZ) ? CHUNK_SZ : (size - off);
        lv1_read(HV_BASE + phys + off, chunk, buf);
        if (cellFsWrite(fd, buf, chunk, &written) != CELL_FS_SUCCEEDED) {
            notify("WRITE_ERR @%llx", off);
            break;
        }
        off += chunk;
        sys_timer_usleep(1000);
    }

    allocator_77A602DD(buf);
    cellFsClose(fd);
    notify("%s dumped %llx bytes", fname, size);
    return 0;
}

//------------------------------------------------------------------------------
// 1) LV0 / LV1 / LV2
//------------------------------------------------------------------------------
int dump_lv0_code() {
    return dump_hv_region("hv_lv0_code.bin",
                          0x0000000000080000ULL, 0x0000000000020000ULL);
}
int dump_lv1_code() {
    return dump_hv_region("hv_lv1_code.bin",
                          0x0000000000200000ULL, 0x0000000000040000ULL);
}
int dump_lv2_region() {
    return dump_hv_region("hv_lv2_region.bin",
                          0x0000000008000000ULL, 0x0000000000800000ULL);
}

//------------------------------------------------------------------------------
// 2) SPE0–6 MMIO (base=0x20000000000 + idx*0x80000, size=0x80000)
//------------------------------------------------------------------------------
int dump_spe0_mmio() {
    return dump_hv_region("hv_spe0_mmio.bin",
                          0x00000020000000000ULL, 0x80000ULL);
}
int dump_spe1_mmio() {
    return dump_hv_region("hv_spe1_mmio.bin",
                          0x00000020000080000ULL, 0x80000ULL);
}
int dump_spe2_mmio() {
    return dump_hv_region("hv_spe2_mmio.bin",
                          0x00000020000100000ULL, 0x80000ULL);
}
int dump_spe3_mmio() {
    return dump_hv_region("hv_spe3_mmio.bin",
                          0x00000020000180000ULL, 0x80000ULL);
}
int dump_spe4_mmio() {
    return dump_hv_region("hv_spe4_mmio.bin",
                          0x00000020000200000ULL, 0x80000ULL);
}
int dump_spe5_mmio() {
    return dump_hv_region("hv_spe5_mmio.bin",
                          0x00000020000280000ULL, 0x80000ULL);
}
int dump_spe6_mmio() {
    return dump_hv_region("hv_spe6_mmio.bin",
                          0x00000020000300000ULL, 0x80000ULL);
}

/*int dump_spe_mmio(int idx) {
    static const uint64_t base[7] = {
        0x00000020000000000ULL,
        0x00000020000080000ULL,
        0x00000020000100000ULL,
        0x00000020000180000ULL,
        0x00000020000200000ULL,
        0x00000020000280000ULL,
        0x00000020000300000ULL
    };
    if (idx<0||idx>6) return -1;
    char fn[32]; vsh_sprintf(fn,"hv_spe%d_mmio.bin",idx);
    return dump_hv_region(fn, base[idx], 0x80000ULL);
}*/

//------------------------------------------------------------------------------
// 3) Pervasive Memory (0x20000509000, sz=0x1000)
//------------------------------------------------------------------------------
int dump_pervasive_mem() {
    return dump_hv_region("hv_pervasive_mem.bin",
                          0x00000020000509000ULL, 0x1000ULL);
}

//------------------------------------------------------------------------------
// 4) SPE1–6 Shadow Registers (each sz=0x1000 at given phys addrs)
//------------------------------------------------------------------------------
int dump_spe1_shadow() {
    return dump_hv_region("hv_spe1_shadow.bin",
                          0x0000002000050C000ULL, 0x1000ULL);
}
int dump_spe2_shadow() {
    return dump_hv_region("hv_spe2_shadow.bin",
                          0x00000020000514290ULL, 0x1000ULL);
}
int dump_spe3_shadow() {
    return dump_hv_region("hv_spe3_shadow.bin",
                          0x00000020000508A00ULL, 0x1000ULL);
}
int dump_spe4_shadow() {
    return dump_hv_region("hv_spe4_shadow.bin",
                          0x0000002000050B0F0ULL, 0x1000ULL);
}
int dump_spe5_shadow() {
    return dump_hv_region("hv_spe5_shadow.bin",
                          0x0000002000051FFC90ULL, 0x1000ULL);
}
int dump_spe6_shadow() {
    return dump_hv_region("hv_spe6_shadow.bin",
                          0x0000002000051AE5B0ULL, 0x1000ULL);
}

/*int dump_spe_shadow(int idx) {
    static const uint64_t addr[7] = {
        0ULL,
        0x0000002000050C000ULL,  // SPE1 @ …0C000
        0x00000020000514290ULL,  // SPE2 @ …4290
        0x00000020000508A00ULL,  // SPE3 @ …8A00
        0x0000002000050B0F0ULL,  // SPE4 @ …50F0
        0x0000002000051FFC90ULL, // SPE5 @ …FC90
        0x0000002000051AE5B0ULL  // SPE6 @ …E5B0
    };
    if (idx<1||idx>6) return -1;
    char fn[32]; vsh_sprintf(fn,"hv_spe%d_shadow.bin",idx);
    return dump_hv_region(fn, addr[idx], 0x1000ULL);
}*/

//------------------------------------------------------------------------------
// 5) XDR Memory Channel Sizes & Type (each sz=4)
//------------------------------------------------------------------------------
int dump_xdr_ch1_size() {
    return dump_hv_region("hv_xdr_ch1_sz.bin",
                          0x0000002000050A0C8ULL, 4ULL);
}
int dump_xdr_ch0_size() {
    return dump_hv_region("hv_xdr_ch0_sz.bin",
                          0x0000002000050A188ULL, 4ULL);
}
int dump_xdr_type() {
    return dump_hv_region("hv_xdr_type.bin",
                          0x0000002000050A210ULL, 4ULL);
}

//------------------------------------------------------------------------------
// 6) SB bus subsystem @0x24000000000 (no size → skip or set 0)
//------------------------------------------------------------------------------
int dump_sb_bus_base() {
    return dump_hv_region("hv_sb_bus_base.bin",
                          0x00000024000000000ULL, 0ULL);
}

// 6.a) SB devices @ offsets 0x2000…0x2C00 (sz=0x200)
int dump_sata1_regs()  { return dump_hv_region("hv_sata1_regs.bin",0x24000002000ULL,0x200ULL); }
int dump_sata2_regs()  { return dump_hv_region("hv_sata2_regs.bin",0x24000002200ULL,0x200ULL); }
int dump_usb1_regs()   { return dump_hv_region("hv_usb1_regs.bin", 0x24000002400ULL,0x200ULL); }
int dump_usb2_regs()   { return dump_hv_region("hv_usb2_regs.bin", 0x24000002600ULL,0x200ULL); }
int dump_gelic_regs()  { return dump_hv_region("hv_gelic_regs.bin",0x24000002800ULL,0x200ULL); }
int dump_encdec_regs() { return dump_hv_region("hv_encdec_regs.bin",0x24000002C00ULL,0x200ULL); }

// 6.b) SB external interrupt ctrl @0x24000008000 sz=0x1000
int dump_sb_ext_intc() { return dump_hv_region("hv_sb_ext_intc.bin",0x24000008000ULL,0x1000ULL); }

// 6.c) SB bus interrupt handler @0x24000008100 & 0x24000008104 (sz=4)
int dump_sb_int_hdl1() { return dump_hv_region("hv_sb_int_hdl1.bin",0x24000008100ULL,4ULL); }
int dump_sb_int_hdl2() { return dump_hv_region("hv_sb_int_hdl2.bin",0x24000008104ULL,4ULL); }

// 6.d) SB status/info @0x24000087000 (no size→0)
int dump_sb_status() { return dump_hv_region("hv_sb_status.bin",0x24000087000ULL,0ULL); }

//------------------------------------------------------------------------------
// 7) SYSCON offsets (all sz=4 unless noted)
//------------------------------------------------------------------------------
int dump_syscon_pkt_hdr() { return dump_hv_region("hv_syscon_pkt_hdr.bin",0x2400008C000ULL,4ULL); }
int dump_syscon_pkt_bdy() { return dump_hv_region("hv_syscon_pkt_bdy.bin",0x2400008C010ULL,4ULL); }
int dump_syscon_recv1()   { return dump_hv_region("hv_syscon_recv1.bin", 0x2400008CFF0ULL,4ULL); }
int dump_syscon_recv2()   { return dump_hv_region("hv_syscon_recv2.bin", 0x2400008CFF4ULL,4ULL); }
int dump_syscon_send_hdr(){ return dump_hv_region("hv_syscon_snd_hdr.bin",0x2400008D000ULL,4ULL); }
int dump_syscon_send_bdy(){ return dump_hv_region("hv_syscon_snd_bdy.bin",0x2400008D010ULL,4ULL); }
int dump_syscon_send1()   { return dump_hv_region("hv_syscon_snd1.bin", 0x2400008DFF0ULL,4ULL); }
int dump_syscon_send2()   { return dump_hv_region("hv_syscon_snd2.bin", 0x2400008DFF4ULL,4ULL); }
int dump_syscon_rcv3()    { return dump_hv_region("hv_syscon_rcv3.bin", 0x2400008E000ULL,4ULL); }
int dump_syscon_testbit() { return dump_hv_region("hv_syscon_testbit.bin",0x2400008E004ULL,4ULL); }
int dump_syscon_notify()  { return dump_hv_region("hv_syscon_notify.bin",0x2400008E100ULL,4ULL); }

//------------------------------------------------------------------------------
// 8) BAR‑spaced SB devices @0x24003000000… each sz=0x1000 unless noted
//------------------------------------------------------------------------------
int dump_sata1_bar()     { return dump_hv_region("hv_sata1_bar.bin",    0x24003000000ULL,0x1000ULL); }
int dump_sata2_bar()     { return dump_hv_region("hv_sata2_bar.bin",    0x24003001000ULL,0x1000ULL); }
int dump_gelic_bar()     { return dump_hv_region("hv_gelic_bar.bin",    0x24003004000ULL,0x1000ULL); }
int dump_encdec_bar()    { return dump_hv_region("hv_encdec_bar.bin",   0x24003005000ULL,0x1000ULL); }
int dump_encdec_test()   { return dump_hv_region("hv_encdec_test.bin",  0x24003005200ULL,4ULL); }
int dump_encdec_cmd()    { return dump_hv_region("hv_encdec_cmd.bin",   0x240030060A0ULL,4ULL); }

// 8.a) USB bar @0x24003010000/20000 sz=0x10000
int dump_usb1_bar()      { return dump_hv_region("hv_usb1_bar.bin",     0x24003010000ULL,0x10000ULL); }
int dump_usb2_bar()      { return dump_hv_region("hv_usb2_bar.bin",     0x24003020000ULL,0x10000ULL); }

//------------------------------------------------------------------------------
// 9) SB SATA/USB repeats @0x24003800000… 
//------------------------------------------------------------------------------
int dump_sata1_bar2()    { return dump_hv_region("hv_sata1_bar2.bin",   0x24003800000ULL,0x1000ULL); }
int dump_sata2_bar2()    { return dump_hv_region("hv_sata2_bar2.bin",   0x24003801000ULL,0x1000ULL); }
int dump_sata1_bar3()    { return dump_hv_region("hv_sata1_bar3.bin",   0x24003802000ULL,0x1000ULL); }
int dump_sata2_bar3()    { return dump_hv_region("hv_sata2_bar3.bin",   0x24003803000ULL,0x1000ULL); }
int dump_usb1_bar2()     { return dump_hv_region("hv_usb1_bar2.bin",    0x24003810000ULL,0x10000ULL); }
int dump_usb2_bar2()     { return dump_hv_region("hv_usb2_bar2.bin",    0x24003820000ULL,0x10000ULL); }

//------------------------------------------------------------------------------
// 10) NOR Flash @0x2401F000000 sz=0x1000000
//------------------------------------------------------------------------------
int dump_nor_flash()     { return dump_hv_region("hv_nor_flash.bin",   0x2401F000000ULL,0x1000000ULL); }
// 10.a) SYS ROM @0x2401FC00000 sz=0x40000
int dump_sys_rom()       { return dump_hv_region("hv_sys_rom.bin",     0x2401FC00000ULL,0x40000ULL); }

//------------------------------------------------------------------------------
// 11) AV Manager (/dev/ioif0) @0x28000000000 sz=0x2000
//------------------------------------------------------------------------------
int dump_avmngr_regs1()  { return dump_hv_region("hv_avmngr1.bin",    0x28000000000ULL,0x2000ULL); }
// 11.a) AV Manager @0x28001800000 sz=0x1000
int dump_avmngr_regs2()  { return dump_hv_region("hv_avmngr2.bin",    0x28001800000ULL,0x1000ULL); }
// 11.b) AV OutCtrl @0x28000600000 sz=0x4000
int dump_av_outctrl()    { return dump_hv_region("hv_av_outctrl.bin",  0x28000600000ULL,0x4000ULL); }
// 11.c) AV PLL Ctrl @0x28000680000 sz=0x4000
int dump_av_pllctrl()    { return dump_hv_region("hv_av_pllctrl.bin",  0x28000680000ULL,0x4000ULL); }
// 11.d) AV other regs...
int dump_av_misc1()      { return dump_hv_region("hv_av_misc1.bin",    0x28000080000ULL,0x8000ULL); }
int dump_av_misc2()      { return dump_hv_region("hv_av_misc2.bin",    0x28000088000ULL,0x1000ULL); }
int dump_av_misc3()      { return dump_hv_region("hv_av_misc3.bin",    0x2800000C000ULL,0x1000ULL); }
int dump_av_misc4()      { return dump_hv_region("hv_av_misc4.bin",    0x2800008A000ULL,0x1000ULL); }
int dump_av_misc5()      { return dump_hv_region("hv_av_misc5.bin",    0x2800008C000ULL,0x1000ULL); }

//------------------------------------------------------------------------------
// 12) GPU Device Memory Regions
//------------------------------------------------------------------------------
int dump_gpu_mem1()      { return dump_hv_region("hv_gpu_mem1.bin",   0x28080000000ULL,0xFE00000ULL); }
int dump_gpu_mem2()      { return dump_hv_region("hv_gpu_mem2.bin",   0x00000000003C0000ULL,0xC000ULL); }
int dump_gpu_mem3()      { return dump_hv_region("hv_gpu_mem3.bin",   0x2808FE00000ULL,0x40000ULL); }
int dump_gpu_mem4()      { return dump_hv_region("hv_gpu_mem4.bin",   0x28000C00000ULL,0x20000ULL); }
int dump_gpu_mem5()      { return dump_hv_region("hv_gpu_mem5.bin",   0x28000080100ULL,0x8000ULL); }

//------------------------------------------------------------------------------
// 13) RSX / RAMIN / GRAPH
//------------------------------------------------------------------------------
int dump_rsx_intstate()  { return dump_hv_region("hv_rsx_intst.bin",  0x2808FC00000ULL,0x400000ULL); }
int dump_ramin_all()     { return dump_hv_region("hv_ramin_all.bin",  0x2808FF80000ULL,0x80000ULL); }
int dump_ramin_hash()    { return dump_hv_region("hv_ramin_hash.bin", 0x2808FF90000ULL,0x4000ULL); }
int dump_ramin_fifo()    { return dump_hv_region("hv_ramin_fifo.bin", 0x2808FFA0000ULL,0x1000ULL); }
int dump_dma_objs()      { return dump_hv_region("hv_dma_objs.bin",   0x2808FFC0000ULL,0x10000ULL); }
int dump_graph_objs()    { return dump_hv_region("hv_graph_objs.bin", 0x2808FFD0000ULL,0x10000ULL); }
int dump_graph_ctx()     { return dump_hv_region("hv_graph_ctx.bin",  0x2808FFE0000ULL,0x10000ULL); }

//------------------------------------------------------------------------------
// 14) GameOS regions / HTAB
//------------------------------------------------------------------------------
int dump_gameos0()       { return dump_hv_region("hv_gameos0.bin",    0x0000000000000000ULL,0x1000000ULL); }
int dump_gameos1()       { return dump_hv_region("hv_gameos1.bin",    0x700020000000ULL,   0xA0000ULL); }
int dump_gameos2()       { return dump_hv_region("hv_gameos2.bin",    0x700020000000ULL,   0xE900000ULL); }
int dump_gameos_htab()   { return dump_hv_region("hv_gameos_htab.bin",0x800000000F000000ULL,0x40000ULL); }

//------------------------------------------------------------------------------
// 15) All‑in‑one dumper
//------------------------------------------------------------------------------
int dump_all_regions() {
    dump_lv0_code();
	dump_lv1_code();
	dump_lv2_region();
    //for(int i=0;i<=6;i++) dump_spe_mmio(i);
	dump_spe0_mmio();
	dump_spe1_mmio();
	dump_spe2_mmio();
	//dump_spe3_mmio();// crashes
	dump_spe4_mmio();
	dump_spe5_mmio();
	dump_spe6_mmio();
    dump_pervasive_mem();
    //for(int i=1;i<=6;i++) dump_spe_shadow(i);
	dump_spe1_shadow();
	dump_spe2_shadow();
	dump_spe3_shadow();
	dump_spe4_shadow();
	dump_spe5_shadow();
	dump_spe6_shadow();
    dump_xdr_ch1_size();
	dump_xdr_ch0_size();
	dump_xdr_type();
    dump_sb_bus_base();
    dump_sata1_regs();
	dump_sata2_regs();
	dump_usb1_regs();
	dump_usb2_regs();
    dump_gelic_regs();
	dump_encdec_regs();
	dump_sb_ext_intc();
    dump_sb_int_hdl1();
	dump_sb_int_hdl2();
	dump_sb_status();
    dump_syscon_pkt_hdr();
	dump_syscon_pkt_bdy();
	dump_syscon_recv1();
	dump_syscon_recv2();
    dump_syscon_send_hdr();
	dump_syscon_send_bdy();
	dump_syscon_send1();
	dump_syscon_send2();
    dump_syscon_rcv3();
	dump_syscon_testbit();
	dump_syscon_notify();
    dump_sata1_bar();
	dump_sata2_bar();
	dump_gelic_bar();
	dump_encdec_bar();
    dump_encdec_test();
	dump_encdec_cmd();
	dump_usb1_bar();
	dump_usb2_bar();
    dump_sata1_bar2();
	dump_sata2_bar2();
	dump_sata1_bar3();
	dump_sata2_bar3();
    dump_usb1_bar2();
	dump_usb2_bar2();
	//dump_nor_flash();// crashes
	//dump_sys_rom();// crashes
    dump_avmngr_regs1();
	dump_avmngr_regs2();
	dump_av_outctrl();
	dump_av_pllctrl();
    dump_av_misc1();
	dump_av_misc2();
	dump_av_misc3();
	dump_av_misc4();
	dump_av_misc5();
    dump_gpu_mem1();
	dump_gpu_mem2();
	dump_gpu_mem3();
	dump_gpu_mem4();
	dump_gpu_mem5();
    dump_rsx_intstate();
	dump_ramin_all();
	dump_ramin_hash();
	dump_ramin_fifo();
    dump_dma_objs();
	dump_graph_objs();
	dump_graph_ctx();
    dump_gameos0();
	//dump_gameos1();// crashes
	dump_gameos2();
	dump_gameos_htab();
    return 0;
}

void get_rsx_clock_speeds()
{
	clock_s clock;

    // Read core multiplier
    clock.value = lv1_peek(0x28000004028ULL);
    //clock.value = lv1_read2(0x28000004028ULL);
    uint8_t core_mul = clock.mul;
    uint32_t core_mhz = core_mul * 50;

    // Read memory multiplier
    clock.value = lv1_peek(0x28000004010ULL);
    //clock.value = lv1_read2(0x28000004010ULL);
    uint8_t mem_mul = clock.mul;
    uint32_t mem_mhz = mem_mul * 25;

    notify(
        "RSX Core Clock: %u MHz (Mul=0x%x)\n"
        "RSX Memory Clock: %u MHz (Mul=0x%x)",
        core_mhz, core_mul,
        mem_mhz,  mem_mul
    );
}

void apply_rsx_clock(uint64_t core, uint64_t mem)
{
	// apply core
 
	clock_s clock;
	clock.value = lv1_peek(0x28000004028ULL);
	//clock.value = lv1_read2(0x28000004028ULL);
 
	clock.mul = (core / 50);
 
	//lv1_poke(0x28000004028ULL, clock.value);
	lv1_write2(0x28000004028ULL, clock.value);
	eieio();
 
	sys_timer_usleep(500000);// 500ms
 
	// apply mem
 
	{
		uint8_t target_mul = (mem / 25);
 
		clock_s clock;
		//clock.value = lv1_peek(0x28000004010ULL);
		clock.value = lv1_read2(0x28000004010ULL);
 
		bool up = (target_mul > clock.mul);
 
		while (clock.mul != target_mul)
		{
			// must apply slowly in 25mhz step, wait, repeat until reach target
 
			clock.mul += up ? 1 : -1;
 
			lv1_poke(0x28000004010ULL, clock.value);
			//lv1_write2(0x28000004010ULL, clock.value);
			eieio();
 
			sys_timer_usleep(200000);// 200ms
 
			notify("%lx\n", (uint64_t)clock.mul);
		}
	}
}

void apply_rsx_core_clock(uint64_t core_mhz)
{
    clock_s clock;
    // read current core‐clock register
    clock.value = lv1_peek(0x28000004028ULL);
    //clock.value = lv1_read2(0x28000004028ULL);
	
    // calculate and set new multiplier
    clock.mul   = (core_mhz / 50);
    lv1_poke(0x28000004028ULL, clock.value);
    //lv1_write2(0x28000004028ULL, clock.value);
    eieio();
    // give it a moment to take effect
    sys_timer_usleep(500000);// 500ms
    notify("RSX Core Multiplier → 0x%x (%u MHz)\n", clock.mul, clock.mul * 25);
}

void apply_rsx_mem_clock(uint64_t mem_mhz)
{
    // compute target multiplier
    uint8_t target_mul = (mem_mhz / 25);

    clock_s clock;
    // read current memory‐clock register
    clock.value = lv1_peek(0x28000004010ULL);
    //clock.value = lv1_read2(0x28000004010ULL);

    // decide ramp direction
    bool up = (target_mul > clock.mul);

    // step one 25 MHz increment at a time until we hit target
    while (clock.mul != target_mul) {
        clock.mul += up ? +1 : -1;
        lv1_poke(0x28000004010ULL, clock.value);
        //lv1_write2(0x28000004010ULL, clock.value);
        eieio();
        sys_timer_usleep(200000);// 200ms
        notify("RSX Memory Multiplier → 0x%x (%u MHz)\n", clock.mul, clock.mul * 25);
    }
}

void OverclockGpuCoreTest()
{
	clock_s clock;
	lv1_read(0x2800000402CULL, 4, &clock.value);
	notify("gpu core clock = 0x%x\n", (uint32_t)clock.mul);

	clock.mul = 0x02; // 100 MHz
	lv1_write(0x2800000402CULL, 4, &clock.value);

	lv1_read(0x2800000402CULL, 4, &clock.value);
	notify("gpu core clock = 0x%x\n", (uint32_t)clock.mul);
}

void OverclockGpuMemTest()
{
	clock_s clock;
	lv1_read(0x28000004014ULL, 4, &clock.value);
	notify("gpu memory clock = 0x%x\n", (uint32_t)clock.mul);

	clock.mul = 0x1A; // 650 MHz
	lv1_write(0x28000004014ULL, 4, &clock.value);

	lv1_read(0x28000004014ULL, 4, &clock.value);
	notify("gpu memory clock = 0x%x\n", (uint32_t)clock.mul);
}

void SetRsxClockSpeed(uint32_t core_freq, uint32_t mem_freq) {
    clock_s clock;

    // Validate core frequency, it should be in 50 MHz steps between 100 MHz and 1 GHz
    if (core_freq < 100 || core_freq > 1000 || core_freq % 50 != 0) {
        notify("Invalid core frequency, must be between 100 MHz and 1 GHz in 50 MHz steps.");
        return;
    }

    // Validate memory frequency, it should be in 25 MHz steps between 100 MHz and 1 GHz
    if (mem_freq < 100 || mem_freq > 1000 || mem_freq % 25 != 0) {
        notify("Invalid memory frequency, must be between 100 MHz and 1 GHz in 25 MHz steps.");
        return;
    }

    // Core clock multiplier: 50 MHz steps
    uint8_t core_mul = (core_freq / 50);

    // Memory clock multiplier: 25 MHz steps
    uint8_t mem_mul = (mem_freq / 25);

    // Set the GPU core clock
    //lv1_read(0x2800000402CULL, 4, &clock.value);
    clock.mul = core_mul;
    lv1_write(0x2800000402CULL, 4, &clock.value);
    //lv1_read(0x2800000402CULL, 4, &clock.value);

    // Set the GPU memory clock
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    clock.mul = mem_mul;
    lv1_write(0x28000004014ULL, 4, &clock.value);
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    
    notify("RSX Core Clock: %d MHz / 0x%x\nRSX Memory Clock: %d MHz/ 0x%x", core_freq, core_mul, mem_freq, mem_mul);
}

void SetRsxCoreClockSpeed(uint32_t core_freq) {
    clock_s clock;

    // Validate core frequency, it should be in 50 MHz steps between 100 MHz and 1 GHz
    if (core_freq < 100 || core_freq > 1000 || core_freq % 50 != 0) {
        notify("Invalid core frequency, must be between 100 MHz and 1 GHz in 50 MHz steps.");
        return;
    }

    // Core clock multiplier: 50 MHz steps
    uint8_t core_mul = (core_freq / 50);

    // Set the GPU core clock
    //lv1_read(0x2800000402CULL, 4, &clock.value);
    clock.mul = core_mul;
    lv1_write(0x2800000402CULL, 4, &clock.value);
    //lv1_read(0x2800000402CULL, 4, &clock.value);
    
    notify("RSX Core Clock: %d MHz / 0x%x", core_freq, core_mul);
}

void SetRsxMemoryClockSpeed(uint32_t mem_freq) {
    clock_s clock;

    // Validate memory frequency, it should be in 25 MHz steps between 100 MHz and 1 GHz
    if (mem_freq < 100 || mem_freq > 1000 || mem_freq % 25 != 0) {
        notify("Invalid memory frequency, must be between 100 MHz and 1 GHz in 25 MHz steps.");
        return;
    }

    // Memory clock multiplier: 25 MHz steps
    uint8_t mem_mul = (mem_freq / 25);

    // Set the GPU memory clock
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    clock.mul = mem_mul;
    lv1_write(0x28000004014ULL, 4, &clock.value);
    //lv1_read(0x28000004014ULL, 4, &clock.value);
    
    notify("RSX Memory Clock: %d MHz/ 0x%x", mem_freq, mem_mul);
}

void TestRsxClockSettings() {
    uint32_t core_freqs[] = {100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700, 750, 800, 850, 900, 950, 1000}; // Core frequencies (50 MHz steps)
    uint32_t mem_freqs[] = {100, 125, 150, 175, 200, 225, 250, 275, 300, 325, 350, 375, 400, 425, 450, 475, 500, 525, 550, 575, 600, 625, 650, 675, 700, 725, 750, 775, 800, 825, 850, 875, 900, 925, 950, 975, 1000}; // Memory frequencies (25 MHz steps)

    notify("Test RSX Clock Settings [100MHz - 1Ghz]");
    sys_timer_usleep(3000000);

    // Start at 100 MHz and 100 MHz, then 100 MHz and 125 MHz, and so on.
    // This loop goes through core_freqs sequentially and pairs them with increasing memory_freqs
    int core_idx = 0;
    for (int i = 0; i < sizeof(mem_freqs) / sizeof(mem_freqs[0]); i++) {
        for (int j = core_idx; j < sizeof(core_freqs) / sizeof(core_freqs[0]); j++) {
            apply_rsx_clock(core_freqs[j], mem_freqs[i]);

            notify("Setting RSX Core Clock to %d MHz and Memory Clock to %d MHz", core_freqs[j], mem_freqs[i]);

            sys_timer_usleep(10000000);

            // After setting, move to the next memory frequency for the current core
            if (i == sizeof(mem_freqs) / sizeof(mem_freqs[0]) - 1) {
                core_idx++; // Move to the next core frequency after we've cycled through all memory frequencies
            }
        }
    }
    notify("Test completed! All settings applied.");
}

void TestRsxClockSettingsSafe() {
    uint32_t core_freqs[] = {550, 600, 650, 650, 650, 700, 700, 700, 750, 750, 750, 800, 800, 800, 850, 850, 850, 900, 900, 950};
    uint32_t mem_freqs[] = {700, 750, 800, 850, 875, 850, 900, 925, 900, 950, 1000, 950, 975, 1000, 950, 975, 1000, 975, 1000, 1000};
    
    notify("Test RSX Clock Settings [SAFE VALUES]");
    sys_timer_usleep(3000000);

    for (int i = 0; i < sizeof(core_freqs) / sizeof(core_freqs[0]); i++) {
        uint32_t core_freq = core_freqs[i];
        uint32_t mem_freq = mem_freqs[i];
		
        //SetRsxClockSpeed(core_freq, mem_freq);
        apply_rsx_clock(core_freq, mem_freq);

        notify("Setting RSX Core Clock to %d MHz and Memory Clock to %d MHz", core_freq, mem_freq);

        sys_timer_usleep(10000000);
    }
    notify("Test completed! All settings applied.");
}

void uninstall_hen()
{
	int ret = 0;
	CellFsStat stat;
	
	// Restore OFW Files
	const char* src_paths[] = {
		"/dev_hdd0/hen/restore/coldboot.raf",
		"/dev_hdd0/hen/restore/explore_plugin_full.rco",
		"/dev_hdd0/hen/restore/software_update_plugin.rco",
		"/dev_hdd0/hen/restore/category_game.xml",
		"/dev_hdd0/hen/restore/category_game_tool2.xml",
		"/dev_hdd0/hen/restore/category_network.xml",
		"/dev_hdd0/hen/restore/category_network_tool2.xml",
		"/dev_hdd0/hen/restore/category_psn.xml",
		"/dev_hdd0/hen/restore/category_video.xml",
		"/dev_hdd0/hen/restore/download_list.xml",
		"/dev_hdd0/hen/restore/registory.xml"
	};

	const char* dest_paths[] = {
		"/dev_rewrite/vsh/resource/coldboot.raf",
		"/dev_rewrite/vsh/resource/explore_plugin_full.rco",
		"/dev_rewrite/vsh/resource/software_update_plugin.rco",
		"/dev_rewrite/vsh/resource/explore/xmb/category_game.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_game_tool2.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_network.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_network_tool2.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_psn.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/category_video.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/download_list.xml",
		"/dev_rewrite/vsh/resource/explore/xmb/registory.xml"
	};

	for (int i = 0; i < sizeof(src_paths) / sizeof(src_paths[0]); i++) {
		CellFsStat stat;
		if (cellFsStat(src_paths[i], &stat) != CELL_FS_SUCCEEDED) {
			// Source file does not exist
			continue;
		}
		cellFsUnlink(dest_paths[i]);
		sys_timer_usleep(100000);
		read_write_generic(src_paths[i], dest_paths[i]);
	}

	// Remove HEN Files in Flash
	const char* flash_files[] = {
		"/dev_rewrite/vsh/resource/explore/icon/hen_boot.png",
		"/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png",
		"/dev_rewrite/vsh/resource/explore/icon/hen_enable.png",
		"/dev_rewrite/vsh/resource/explore/icon/hen_repair.png",
		"/dev_rewrite/vsh/resource/videodownloader_plugin.rco",
		"/dev_rewrite/vsh/resource/videorec.rco",
		"/dev_rewrite/vsh/resource/xai_plugin.rco",
		"/dev_rewrite/vsh/module/videodownloader_plugin.sprx",
		"/dev_rewrite/vsh/module/videorec.sprx",
		"/dev_rewrite/vsh/module/xai_plugin.sprx"
	};
	for (int i = 0; i < sizeof(flash_files) / sizeof(flash_files[0]); i++) {
		if (cellFsUnlink(flash_files[i]) != CELL_FS_SUCCEEDED) {
			log("Unlink Error: %x", ret);
		}
	}
	
	sys_timer_usleep(2000000);

	// Remove HEN Directories
	remove_directory("/dev_hdd0/theme/../../dev_hdd0/hen");
	remove_directory("/dev_hdd0/theme/../../dev_hdd0/game/PS3XPLOIT");
	remove_directory("/dev_hdd0/theme/../../dev_rewrite/hen");
	cellFsRmdir("/dev_hdd0/hen");
	cellFsRmdir("/dev_hdd0/game/PS3XPLOIT");
	cellFsRmdir("/dev_rewrite/hen");
	
	sys_timer_usleep(1000000);
	
	notify("PS3HEN has been removed.\nSystem will now reboot back into HFW...");

	sys_timer_usleep(5000000);

	xmb_reboot(SYS_SOFT_REBOOT);
}

int switch_hen_mode(int mode)
{
	/*
	0 = Release
	1 = Debug
	2 = USB 000
	3 = USB 001
	*/

	switch (mode)
	{
		case 0:
			notify("Switching To RELEASE Mode.\nPlease Wait...");
			read_write_generic("/dev_hdd0/hen/mode/release/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/release/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/release/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/release/PS3HEN.BIN", "/dev_rewrite/hen/PS3HEN.BIN");
			read_write_generic("/dev_hdd0/hen/mode/release/ps3hen_updater.xml", "/dev_rewrite/hen/xml/ps3hen_updater.xml");
			notify("Please reboot to activate RELEASE mode!");
			break;
		case 1:
			notify("Switching To DEBUG Mode.\nPlease Wait...");
			read_write_generic("/dev_hdd0/hen/mode/debug/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/debug/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/debug/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/debug/PS3HEN.BIN", "/dev_rewrite/hen/PS3HEN.BIN");
			read_write_generic("/dev_hdd0/hen/mode/debug/ps3hen_updater.xml", "/dev_rewrite/hen/xml/ps3hen_updater.xml");
			notify("Please reboot to activate DEBUG mode!");
			break;
		case 2:
			notify("Switching To USB000 Mode.\nPlease Wait...");
			read_write_generic("/dev_hdd0/hen/mode/usb/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/000/hen_enable.xml", "/dev_hdd0/hen/xml/hen_enable.xml");
			notify("Please reboot to activate USB000 mode!");
			break;
		case 3:
			notify("Switching To USB001 Mode.\nPlease Wait...");
			read_write_generic("/dev_hdd0/hen/mode/usb/coldboot.raf", "/dev_rewrite/vsh/resource/coldboot.raf");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_enable.png", "/dev_rewrite/vsh/resource/explore/icon/hen_enable.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/hen_disabled.png", "/dev_rewrite/vsh/resource/explore/icon/hen_disabled.png");
			read_write_generic("/dev_hdd0/hen/mode/usb/001/hen_enable.xml", "/dev_hdd0/hen/xml/hen_enable.xml");
			notify("Please reboot to activate USB001 mode!");
			break;
		default:
			break;
	}

}

// HFW XML Entries
void toggle_auto_update()
{
	toggle_generic("/dev_hdd0/hen_updater.off", "HEN Auto Update", 0);// Legacy Path 3.1.1 and lower
	//toggle_generic("/dev_hdd0/hen/toggles/hen_updater.off", "HEN Auto Update", 0);// New Path 3.2.0+
}

void toggle_hen_repair()
{
	toggle_generic("/dev_hdd0/hen/toggles/hen_repair.off", "HEN Repair", 0);
}

void toggle_patch_libaudio()
{
	toggle_generic("/dev_hdd0/hen/toggles/patch_libaudio.on", "libaudio Patch", 1);
}

// Clear Web Cache Functions (History, Auth Cache, Cookie)
void toggle_clear_web_history()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_web_history.on", "Clear Web Cache: History", 1);
}

void toggle_clear_web_auth_cache()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_web_auth_cache.on", "Clear Web Cache: Auth Cache", 1);
}

void toggle_clear_web_cookie()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_web_cookie.on", "Clear Web Cache: Cookie", 1);
}

void toggle_clear_psn_ci()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_ci.on", "Clear PSN Cache: CI.TMP", 1);
}

void toggle_clear_psn_mi()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_mi.on", "Clear PSN Cache: MI.TMP", 1);
}

void toggle_clear_psn_ptl()
{
	toggle_generic("/dev_hdd0/hen/toggles/clear_ptl.on", "Clear PSN Cache: PTL.TMP", 1);
}

void toggle_hen_dev_build()
{
	toggle_generic("/dev_hdd0/hen/toggles/dev_build_type.on", "Development Build Type", 1);
}

void disable_remaps_on_next_boot()
{
	write_toggle("/dev_hdd0/hen/toggles/remap_files.off", "MapPath Remappings Will Be Disabled On Next Boot");
}

void toggle_rap_bin()
{
	toggle_generic("/dev_hdd0/hen/toggles/rap_bin.on", "Reading from rap.bin", 1);
}

void toggle_hotkey_polling()
{
	toggle_generic("/dev_hdd0/hen/toggles/hotkey_polling.off", "HotKey Polling at Launch", 0);
}

void toggle_app_home()
{
	toggle_generic("/dev_hdd0/hen/toggles/app_home.on", "app_home Support", 1);
	sys_timer_usleep(100000);
	CellFsStat stat;
	if (cellFsStat("/dev_hdd0/hen/toggles/app_home.on", &stat) == CELL_OK)
	{
		cellFsUnlink("/dev_rewrite/vsh/resource/explore/xmb/category_game.xml");
		//cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/app_home/on/category_game.xml", "/dev_rewrite/vsh/resource/explore/xmb/category_game.xml", 0600);
		//read_write_generic2("/dev_hdd0/hen/toggles/app_home/on/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		notify("app_home Enabled.\nRefresh XMB or Reboot.");
	}
	else
	{
		cellFsUnlink("/dev_rewrite/vsh/resource/explore/xmb/category_game.xml");
		//cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/app_home/off/category_game.xml", "/dev_rewrite/vsh/resource/explore/xmb/category_game.xml", 0600);
		//read_write_generic2("/dev_hdd0/hen/toggles/app_home/off/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		notify("app_home Disabled.\nRefresh XMB or Reboot.");
	}
}

void toggle_quick_preview()
{
	toggle_generic("/dev_hdd0/hen/toggles/quick_preview.on", "Quick Preview Support", 1);
	sys_timer_usleep(100000);
	CellFsStat stat;
	if (cellFsStat("/dev_hdd0/hen/toggles/quick_preview.on", &stat) == CELL_OK)
	{
		cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/quick_preview/on/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		notify("Quick Preview Enabled\nexplore_plugin.sprx will have visual artifacts on 4.89+\nRefresh XMB or Reboot.");
	}
	else
	{
		cellFsUnlink("/dev_rewrite/vsh/module/explore_plugin.sprx");
		read_write_generic2("/dev_hdd0/hen/toggles/quick_preview/off/explore_plugin.sprx", "/dev_rewrite/vsh/module/explore_plugin.sprx", 0644);
		notify("Quick Preview Disabled\nOriginal explore_plugin.sprx copied\nRefresh XMB or Reboot.");
	}
}

// BadHTAB Testing
void badhtab_copy_log()
{
	read_write_generic_notify("/dev_hdd0/BadHTAB.txt", "/dev_usb000/BadHTAB.txt");
}

void badhtab_toggle_glitcher_test()
{
	toggle_generic("/dev_hdd0/BadHTAB_doGlitcherTest.txt", "Glitcher Test", 1);
}

void badhtab_toggle_skip_stage1()
{
	toggle_generic("/dev_hdd0/BadHTAB_doSkipStage1.txt", "Skip Stage 1", 1);
}

/*void badhtab_toggle_skip_stage_cfw()
{
	toggle_generic("/dev_hdd0/BadHTAB_doStage1_CFW.txt", "Skip Stage CFW", 1);
}*/

void badhtab_toggle_skip_stage2()
{
	toggle_generic("/dev_hdd0/BadHTAB_doSkipStage2.txt", "Skip Stage 2", 1);
}

void badhtab_toggle_skip_patch_more_lv1()
{
	toggle_generic("/dev_hdd0/BadHTAB_doSkipPatchMoreLv1.txt", "Skip Patch More LV1", 1);
}

void badhtab_toggle_lv1_dump()
{
	toggle_generic("/dev_hdd0/BadHTAB_doDumpLv1.txt", "BadHTAB LV1 Dump", 1);
}

void badhtab_toggle_lv1_dump_240m()
{
	toggle_generic("/dev_hdd0/BadHTAB_doDumpLv1_240M.txt", "BadHTAB LV1 Dump 240M", 1);
}

void badhtab_toggle_otheros()
{
	toggle_generic("/dev_hdd0/BadHTAB_doOtherOS.txt", "BadHTAB OtherOS", 1);
}

void badhtab_toggle_lv2_kernel_self()
{
	toggle_generic("/dev_hdd0/BadHTAB_doLoadLv2Kernel_Self.txt", "BadHTAB LV2 Kernel SELF", 1);
}

void badhtab_toggle_lv2_kernel_fself()
{
	toggle_generic("/dev_hdd0/BadHTAB_doLoadLv2Kernel_Fself.txt", "BadHTAB LV2 Kernel FSELF", 1);
}

// BadWDSD Testing
void badwdsd_copy_log()
{
	read_write_generic_notify("/dev_hdd0/BadWDSD.txt", "/dev_usb000/BadWDSD.txt");
}

void badwdsd_toggle_lv2_kernel_fself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doLoadLv2Kernel_Fself.txt", "BadWDSD LV2 Kernel FSELF", 1);
}

void badwdsd_toggle_lv2_kernel_zfself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doLoadLv2Kernel_ZFself.txt", "BadWDSD LV2 Kernel ZFSELF", 1);
}

void badwdsd_toggle_otheros_fself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doOtherOS_Fself.txt", "BadWDSD OtherOS FSELF", 1);
}

void badwdsd_toggle_otheros_zfself()
{
	toggle_generic("/dev_hdd0/BadWDSD_doOtherOS_ZFself.txt", "BadWDSD OtherOS ZFSELF", 1);
}

void badwdsd_toggle_skip_ros_compare()
{
	toggle_generic("/dev_hdd0/BadWDSD_doSkipRosCompare.txt", "BadWDSD Skip ROS Compare", 1);
}

void badwdsd_toggle_flash_ros1()
{
	toggle_generic("/dev_hdd0/BadWDSD_doFlashRos1.txt", "BadWDSD Reflash ROS1", 1);
}

// LV1 Patches
void toggle_lv1_patch_unmask_bootldr()
{
	toggle_lv1_patch("Unmask bootldr", 0x27B630, 0x39840200f8010090ULL, 0x0000000000000000ULL);
}

void toggle_lv1_patch_test1()
{
	toggle_lv1_patch("Patch #1", 0x323740, 0x536F6E792043656CULL, 0x4141414142424242ULL);

	//toggle_lv1_patch("Patch #1", 0x3B1890, 0x0100000046726920ULL, 0x0100000047726920ULL);
	//toggle_lv1_patch("Patch #2", 0x3B1898, 0x4170722031362032ULL, 0x4270722031362032ULL);
	//toggle_lv1_patch("Patch #3", 0x3B18A0, 0x303A31373A323320ULL, 0x313A31373A323320ULL);
	//toggle_lv1_patch("Patch #4", 0x3B18A8, 0x3230313000000000ULL, 0x3230333000000000ULL);

	//lv1_patch_pattern(0x3B1890, 0x0100000046726920ULL, 0x0100000047726920ULL, 0xFFFFFFFFFFFFFFFFULL);// 0100000046726920
	//lv1_patch_pattern(0x3B1894, 0x4170722031362032ULL, 0x4270722031362032ULL, 0xFFFFFFFFFFFFFFFFULL);// 4170722031362032
	//lv1_patch_pattern(0x3B1894, 0x303A31373A323320ULL, 0x313A31373A323320ULL, 0xFFFFFFFFFFFFFFFFULL);// 303A31373A323320
	//lv1_patch_pattern(0x3B1894, 0x0100000046726920ULL, 0x0100000047726920ULL, 0xFFFFFFFFFFFFFFFFULL);// 3230313000000000
}

void toggle_lv1_patch_test2()
{
	toggle_lv1_patch32("Patch #1", 0x323740, 0x536F6E79, 0x41414141);
	toggle_lv1_patch32("Patch #2", 0x323744, 0x2043656C, 0x42424242);

	//toggle_lv1_patch32("Patch #1", 0x3B1894, 0x46726920, 0x57656420);
	//toggle_lv1_patch32("Patch #2", 0x3B1898, 0x41707220, 0x4D617920);
	//toggle_lv1_patch32("Patch #3", 0x3B189C, 0x31362032, 0x30342031);
	//toggle_lv1_patch32("Patch #4", 0x3B18A0, 0x303A3137, 0x323A3131);
	//toggle_lv1_patch32("Patch #5", 0x3B18A4, 0x3A323320, 0x3A313020);
	//toggle_lv1_patch32("Patch #6", 0x3B18A8, 0x32303130, 0x32303235);
}

// Default Speed
//void set_rsx_clock_defaults()   { SetRsxClockSpeed(500, 650); }
void set_rsx_clock_defaults()   { apply_rsx_clock(500, 650); }

// Matched Speeds
/*void set_rsx_clock_100_100()    { SetRsxClockSpeed(100, 100); }
void set_rsx_clock_150_150()    { SetRsxClockSpeed(150, 150); }
void set_rsx_clock_200_200()    { SetRsxClockSpeed(200, 200); }
void set_rsx_clock_250_250()    { SetRsxClockSpeed(250, 250); }
void set_rsx_clock_300_300()    { SetRsxClockSpeed(300, 300); }
void set_rsx_clock_350_350()    { SetRsxClockSpeed(350, 350); }
void set_rsx_clock_400_400()    { SetRsxClockSpeed(400, 400); }
void set_rsx_clock_450_450()    { SetRsxClockSpeed(450, 450); }
void set_rsx_clock_500_500()    { SetRsxClockSpeed(500, 500); }
void set_rsx_clock_550_550()    { SetRsxClockSpeed(550, 550); }
void set_rsx_clock_600_600()    { SetRsxClockSpeed(600, 600); }
void set_rsx_clock_650_650()    { SetRsxClockSpeed(650, 650); }
void set_rsx_clock_700_700()    { SetRsxClockSpeed(700, 700); }
void set_rsx_clock_750_750()    { SetRsxClockSpeed(750, 750); }
void set_rsx_clock_800_800()    { SetRsxClockSpeed(800, 800); }
void set_rsx_clock_850_850()    { SetRsxClockSpeed(850, 850); }
void set_rsx_clock_900_900()    { SetRsxClockSpeed(900, 900); }
void set_rsx_clock_950_950()    { SetRsxClockSpeed(950, 950); }
void set_rsx_clock_1000_1000()  { SetRsxClockSpeed(1000, 1000); }*/

void set_rsx_clock_100_100()    { apply_rsx_clock(100, 100); }
void set_rsx_clock_150_150()    { apply_rsx_clock(150, 150); }
void set_rsx_clock_200_200()    { apply_rsx_clock(200, 200); }
void set_rsx_clock_250_250()    { apply_rsx_clock(250, 250); }
void set_rsx_clock_300_300()    { apply_rsx_clock(300, 300); }
void set_rsx_clock_350_350()    { apply_rsx_clock(350, 350); }
void set_rsx_clock_400_400()    { apply_rsx_clock(400, 400); }
void set_rsx_clock_450_450()    { apply_rsx_clock(450, 450); }
void set_rsx_clock_500_500()    { apply_rsx_clock(500, 500); }
void set_rsx_clock_550_550()    { apply_rsx_clock(550, 550); }
void set_rsx_clock_600_600()    { apply_rsx_clock(600, 600); }
void set_rsx_clock_650_650()    { apply_rsx_clock(650, 650); }
void set_rsx_clock_700_700()    { apply_rsx_clock(700, 700); }
void set_rsx_clock_750_750()    { apply_rsx_clock(750, 750); }
void set_rsx_clock_800_800()    { apply_rsx_clock(800, 800); }
void set_rsx_clock_850_850()    { apply_rsx_clock(850, 850); }
void set_rsx_clock_900_900()    { apply_rsx_clock(900, 900); }
void set_rsx_clock_950_950()    { apply_rsx_clock(950, 950); }
void set_rsx_clock_1000_1000()  { apply_rsx_clock(1000, 1000); }

// Core Only Speeds (mem fixed at 650)
/*void set_rsx_clock_100_650()    { SetRsxClockSpeed(100, 650); }
void set_rsx_clock_150_650()    { SetRsxClockSpeed(150, 650); }
void set_rsx_clock_200_650()    { SetRsxClockSpeed(200, 650); }
void set_rsx_clock_250_650()    { SetRsxClockSpeed(250, 650); }
void set_rsx_clock_300_650()    { SetRsxClockSpeed(300, 650); }
void set_rsx_clock_350_650()    { SetRsxClockSpeed(350, 650); }
void set_rsx_clock_400_650()    { SetRsxClockSpeed(400, 650); }
void set_rsx_clock_450_650()    { SetRsxClockSpeed(450, 650); }
void set_rsx_clock_500_650()    { SetRsxClockSpeed(500, 650); }
void set_rsx_clock_550_650()    { SetRsxClockSpeed(550, 650); }
void set_rsx_clock_600_650()    { SetRsxClockSpeed(600, 650); }
void set_rsx_clock_650_650()    { SetRsxClockSpeed(650, 650); }
void set_rsx_clock_700_650()    { SetRsxClockSpeed(700, 650); }
void set_rsx_clock_750_650()    { SetRsxClockSpeed(750, 650); }
void set_rsx_clock_800_650()    { SetRsxClockSpeed(800, 650); }
void set_rsx_clock_850_650()    { SetRsxClockSpeed(850, 650); }
void set_rsx_clock_900_650()    { SetRsxClockSpeed(900, 650); }
void set_rsx_clock_950_650()    { SetRsxClockSpeed(950, 650); }
void set_rsx_clock_1000_650()   { SetRsxClockSpeed(1000, 650); }*/

// Memory Only Speeds (core fixed at 500)
/*void set_rsx_clock_500_100()    { SetRsxClockSpeed(500, 100); }
void set_rsx_clock_500_150()    { SetRsxClockSpeed(500, 150); }
void set_rsx_clock_500_200()    { SetRsxClockSpeed(500, 200); }
void set_rsx_clock_500_250()    { SetRsxClockSpeed(500, 250); }
void set_rsx_clock_500_300()    { SetRsxClockSpeed(500, 300); }
void set_rsx_clock_500_350()    { SetRsxClockSpeed(500, 350); }
void set_rsx_clock_500_400()    { SetRsxClockSpeed(500, 400); }
void set_rsx_clock_500_450()    { SetRsxClockSpeed(500, 450); }
void set_rsx_clock_500_500()    { SetRsxClockSpeed(500, 500); }
void set_rsx_clock_500_550()    { SetRsxClockSpeed(500, 550); }
void set_rsx_clock_500_600()    { SetRsxClockSpeed(500, 600); }
void set_rsx_clock_500_650()    { SetRsxClockSpeed(500, 650); }
void set_rsx_clock_500_700()    { SetRsxClockSpeed(500, 700); }
void set_rsx_clock_500_750()    { SetRsxClockSpeed(500, 750); }
void set_rsx_clock_500_800()    { SetRsxClockSpeed(500, 800); }
void set_rsx_clock_500_850()    { SetRsxClockSpeed(500, 850); }
void set_rsx_clock_500_900()    { SetRsxClockSpeed(500, 900); }
void set_rsx_clock_500_950()    { SetRsxClockSpeed(500, 950); }
void set_rsx_clock_500_1000()   { SetRsxClockSpeed(500, 1000); }*/

//------------------------------------------------------------------------------
// Core clock: 100 MHz → 1000 MHz in 50 MHz steps
//------------------------------------------------------------------------------
/*void set_rsx_core_clock_100()  { SetRsxCoreClockSpeed(100);  }
void set_rsx_core_clock_150()  { SetRsxCoreClockSpeed(150);  }
void set_rsx_core_clock_200()  { SetRsxCoreClockSpeed(200);  }
void set_rsx_core_clock_250()  { SetRsxCoreClockSpeed(250);  }
void set_rsx_core_clock_300()  { SetRsxCoreClockSpeed(300);  }
void set_rsx_core_clock_350()  { SetRsxCoreClockSpeed(350);  }
void set_rsx_core_clock_400()  { SetRsxCoreClockSpeed(400);  }
void set_rsx_core_clock_450()  { SetRsxCoreClockSpeed(450);  }
void set_rsx_core_clock_500()  { SetRsxCoreClockSpeed(500);  }
void set_rsx_core_clock_550()  { SetRsxCoreClockSpeed(550);  }
void set_rsx_core_clock_600()  { SetRsxCoreClockSpeed(600);  }
void set_rsx_core_clock_650()  { SetRsxCoreClockSpeed(650);  }
void set_rsx_core_clock_700()  { SetRsxCoreClockSpeed(700);  }
void set_rsx_core_clock_750()  { SetRsxCoreClockSpeed(750);  }
void set_rsx_core_clock_800()  { SetRsxCoreClockSpeed(800);  }
void set_rsx_core_clock_850()  { SetRsxCoreClockSpeed(850);  }
void set_rsx_core_clock_900()  { SetRsxCoreClockSpeed(900);  }
void set_rsx_core_clock_950()  { SetRsxCoreClockSpeed(950);  }
void set_rsx_core_clock_1000() { SetRsxCoreClockSpeed(1000); }*/

void set_rsx_core_clock_100()  { apply_rsx_core_clock(100);  }
void set_rsx_core_clock_150()  { apply_rsx_core_clock(150);  }
void set_rsx_core_clock_200()  { apply_rsx_core_clock(200);  }
void set_rsx_core_clock_250()  { apply_rsx_core_clock(250);  }
void set_rsx_core_clock_300()  { apply_rsx_core_clock(300);  }
void set_rsx_core_clock_350()  { apply_rsx_core_clock(350);  }
void set_rsx_core_clock_400()  { apply_rsx_core_clock(400);  }
void set_rsx_core_clock_450()  { apply_rsx_core_clock(450);  }
void set_rsx_core_clock_500()  { apply_rsx_core_clock(500);  }
void set_rsx_core_clock_550()  { apply_rsx_core_clock(550);  }
void set_rsx_core_clock_600()  { apply_rsx_core_clock(600);  }
void set_rsx_core_clock_650()  { apply_rsx_core_clock(650);  }
void set_rsx_core_clock_700()  { apply_rsx_core_clock(700);  }
void set_rsx_core_clock_750()  { apply_rsx_core_clock(750);  }
void set_rsx_core_clock_800()  { apply_rsx_core_clock(800);  }
void set_rsx_core_clock_850()  { apply_rsx_core_clock(850);  }
void set_rsx_core_clock_900()  { apply_rsx_core_clock(900);  }
void set_rsx_core_clock_950()  { apply_rsx_core_clock(950);  }
void set_rsx_core_clock_1000() { apply_rsx_core_clock(1000); }

//------------------------------------------------------------------------------
// Memory clock: 100 MHz → 1000 MHz in 25 MHz steps
//------------------------------------------------------------------------------
/*void set_rsx_mem_clock_100()  { SetRsxMemoryClockSpeed(100);  }
void set_rsx_mem_clock_125()  { SetRsxMemoryClockSpeed(125);  }
void set_rsx_mem_clock_150()  { SetRsxMemoryClockSpeed(150);  }
void set_rsx_mem_clock_175()  { SetRsxMemoryClockSpeed(175);  }
void set_rsx_mem_clock_200()  { SetRsxMemoryClockSpeed(200);  }
void set_rsx_mem_clock_225()  { SetRsxMemoryClockSpeed(225);  }
void set_rsx_mem_clock_250()  { SetRsxMemoryClockSpeed(250);  }
void set_rsx_mem_clock_275()  { SetRsxMemoryClockSpeed(275);  }
void set_rsx_mem_clock_300()  { SetRsxMemoryClockSpeed(300);  }
void set_rsx_mem_clock_325()  { SetRsxMemoryClockSpeed(325);  }
void set_rsx_mem_clock_350()  { SetRsxMemoryClockSpeed(350);  }
void set_rsx_mem_clock_375()  { SetRsxMemoryClockSpeed(375);  }
void set_rsx_mem_clock_400()  { SetRsxMemoryClockSpeed(400);  }
void set_rsx_mem_clock_425()  { SetRsxMemoryClockSpeed(425);  }
void set_rsx_mem_clock_450()  { SetRsxMemoryClockSpeed(450);  }
void set_rsx_mem_clock_475()  { SetRsxMemoryClockSpeed(475);  }
void set_rsx_mem_clock_500()  { SetRsxMemoryClockSpeed(500);  }
void set_rsx_mem_clock_525()  { SetRsxMemoryClockSpeed(525);  }
void set_rsx_mem_clock_550()  { SetRsxMemoryClockSpeed(550);  }
void set_rsx_mem_clock_575()  { SetRsxMemoryClockSpeed(575);  }
void set_rsx_mem_clock_600()  { SetRsxMemoryClockSpeed(600);  }
void set_rsx_mem_clock_625()  { SetRsxMemoryClockSpeed(625);  }
void set_rsx_mem_clock_650()  { SetRsxMemoryClockSpeed(650);  }
void set_rsx_mem_clock_675()  { SetRsxMemoryClockSpeed(675);  }
void set_rsx_mem_clock_700()  { SetRsxMemoryClockSpeed(700);  }
void set_rsx_mem_clock_725()  { SetRsxMemoryClockSpeed(725);  }
void set_rsx_mem_clock_750()  { SetRsxMemoryClockSpeed(750);  }
void set_rsx_mem_clock_775()  { SetRsxMemoryClockSpeed(775);  }
void set_rsx_mem_clock_800()  { SetRsxMemoryClockSpeed(800);  }
void set_rsx_mem_clock_825()  { SetRsxMemoryClockSpeed(825);  }
void set_rsx_mem_clock_850()  { SetRsxMemoryClockSpeed(850);  }
void set_rsx_mem_clock_875()  { SetRsxMemoryClockSpeed(875);  }
void set_rsx_mem_clock_900()  { SetRsxMemoryClockSpeed(900);  }
void set_rsx_mem_clock_925()  { SetRsxMemoryClockSpeed(925);  }
void set_rsx_mem_clock_950()  { SetRsxMemoryClockSpeed(950);  }
void set_rsx_mem_clock_975()  { SetRsxMemoryClockSpeed(975);  }
void set_rsx_mem_clock_1000() { SetRsxMemoryClockSpeed(1000); }*/

void set_rsx_mem_clock_100()  { apply_rsx_mem_clock(100);  }
void set_rsx_mem_clock_125()  { apply_rsx_mem_clock(125);  }
void set_rsx_mem_clock_150()  { apply_rsx_mem_clock(150);  }
void set_rsx_mem_clock_175()  { apply_rsx_mem_clock(175);  }
void set_rsx_mem_clock_200()  { apply_rsx_mem_clock(200);  }
void set_rsx_mem_clock_225()  { apply_rsx_mem_clock(225);  }
void set_rsx_mem_clock_250()  { apply_rsx_mem_clock(250);  }
void set_rsx_mem_clock_275()  { apply_rsx_mem_clock(275);  }
void set_rsx_mem_clock_300()  { apply_rsx_mem_clock(300);  }
void set_rsx_mem_clock_325()  { apply_rsx_mem_clock(325);  }
void set_rsx_mem_clock_350()  { apply_rsx_mem_clock(350);  }
void set_rsx_mem_clock_375()  { apply_rsx_mem_clock(375);  }
void set_rsx_mem_clock_400()  { apply_rsx_mem_clock(400);  }
void set_rsx_mem_clock_425()  { apply_rsx_mem_clock(425);  }
void set_rsx_mem_clock_450()  { apply_rsx_mem_clock(450);  }
void set_rsx_mem_clock_475()  { apply_rsx_mem_clock(475);  }
void set_rsx_mem_clock_500()  { apply_rsx_mem_clock(500);  }
void set_rsx_mem_clock_525()  { apply_rsx_mem_clock(525);  }
void set_rsx_mem_clock_550()  { apply_rsx_mem_clock(550);  }
void set_rsx_mem_clock_575()  { apply_rsx_mem_clock(575);  }
void set_rsx_mem_clock_600()  { apply_rsx_mem_clock(600);  }
void set_rsx_mem_clock_625()  { apply_rsx_mem_clock(625);  }
void set_rsx_mem_clock_650()  { apply_rsx_mem_clock(650);  }
void set_rsx_mem_clock_675()  { apply_rsx_mem_clock(675);  }
void set_rsx_mem_clock_700()  { apply_rsx_mem_clock(700);  }
void set_rsx_mem_clock_725()  { apply_rsx_mem_clock(725);  }
void set_rsx_mem_clock_750()  { apply_rsx_mem_clock(750);  }
void set_rsx_mem_clock_775()  { apply_rsx_mem_clock(775);  }
void set_rsx_mem_clock_800()  { apply_rsx_mem_clock(800);  }
void set_rsx_mem_clock_825()  { apply_rsx_mem_clock(825);  }
void set_rsx_mem_clock_850()  { apply_rsx_mem_clock(850);  }
void set_rsx_mem_clock_875()  { apply_rsx_mem_clock(875);  }
void set_rsx_mem_clock_900()  { apply_rsx_mem_clock(900);  }
void set_rsx_mem_clock_925()  { apply_rsx_mem_clock(925);  }
void set_rsx_mem_clock_950()  { apply_rsx_mem_clock(950);  }
void set_rsx_mem_clock_975()  { apply_rsx_mem_clock(975);  }
void set_rsx_mem_clock_1000() { apply_rsx_mem_clock(1000); }
