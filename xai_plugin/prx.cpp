#include <cellstatus.h>
#include <sys/prx.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <string.h>

#include <sys/paths.h>
#include <sys/fs.h>
#include <sys/fs_external.h>
#include <cell/cell_fs.h>
#include <cell/fs/cell_fs_file_api.h>
#include <sys/timer.h>

#include "gccpch.h"
#include "xmb_plugin.h"
#include "log.h"
#include "hfw_settings.h"
#include "x3.h"
#include "xRegistry.h"
#include "download_plugin.h"



SYS_MODULE_INFO( xai_plugin, 0, 1, 1);
SYS_MODULE_START( _xai_plugin_prx_entry );
SYS_MODULE_STOP( _xai_plugin_prx_stop );
SYS_MODULE_EXIT( _xai_plugin_prx_exit );

SYS_LIB_DECLARE_WITH_STUB( LIBNAME, SYS_LIB_AUTO_EXPORT, STUBNAME );
SYS_LIB_EXPORT( _xai_plugin_export_function, LIBNAME );

// An exported function is needed to generate the project's PRX stub export library
extern "C" int _xai_plugin_export_function(void)
{
    return CELL_OK;
}

void * getNIDfunc(const char * vsh_module, uint32_t fnid)
{	
	// 0x10000 = ELF
	// 0x10080 = segment 2 start
	// 0x10200 = code start	

	uint32_t table = (*(uint32_t*)0x1008C) + 0x984; // vsh table address
	
	while(((uint32_t)*(uint32_t*)table) != 0)
	{
		uint32_t* export_stru_ptr = (uint32_t*)*(uint32_t*)table; // ptr to export stub, size 2C, "sys_io" usually... Exports:0000000000635BC0 stru_635BC0:    ExportStub_s <0x1C00, 1, 9, 0x39, 0, 0x2000000, aSys_io, ExportFNIDTable_sys_io, ExportStubTable_sys_io>
			
		const char* lib_name_ptr =  (const char*)*(uint32_t*)((char*)export_stru_ptr + 0x10);
				
		if(strncmp(vsh_module,lib_name_ptr,strlen(lib_name_ptr))==0)
		{
			//log("found module name\n");
			// we got the proper export struct
			uint32_t lib_fnid_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x14);
			uint32_t lib_func_ptr = *(uint32_t*)((char*)export_stru_ptr + 0x18);
			uint16_t count = *(uint16_t*)((char*)export_stru_ptr + 6); // amount of exports
			for(int i=0;i<count;i++)
			{
				if(fnid == *(uint32_t*)((char*)lib_fnid_ptr + i*4))
				{
					//log("found fnid func\n");
					// take adress from OPD
					return (void*&)*((uint32_t*)(lib_func_ptr) + i);
				}
			}
		}
		//log("next table struct\n");
		table=table+4;
	}
	return 0;
}

int sys_sm_shutdown(uint16_t op)
{ 	
	system_call_3(379, (uint64_t)op, 0, 0);
	return_to_user_prog(int);
}

void xmb_reboot(uint16_t op)
{
	cellFsUnlink("/dev_hdd0/tmp/turnoff");
	sys_sm_shutdown(op);
}

int console_write(const char * s)
{ 
	uint32_t len;
	system_call_4(403, 0, (uint64_t) s, std::strlen(s), (uint64_t) &len);
	return_to_user_prog(int);
}

xmb_plugin_xmm0 * xmm0_interface;
xmb_plugin_xmb2 * xmb2_interface;
xmb_plugin_mod0 * mod0_interface;


//void plugin_shutdown()
//{
//	xmm0_interface->Shutdown(xai_plugin,0,0);
//}


xsetting_AF1F161_class* (*xsetting_AF1F161)() = 0;
int GetProductCode()
{
	return xsetting_AF1F161()->GetProductCode();
}

int FindView(char * pluginname)
{
	return View_Find(pluginname);
}
int GetPluginInterface(const char * pluginname, int interface_)
{
	return plugin_GetInterface(View_Find(pluginname),interface_);
}
int LoadPlugin(char * pluginname, void * handler)
{
	log_function("xai_plugin","1",__FUNCTION__,"(%s)\n",pluginname);
	return xmm0_interface->LoadPlugin3( xmm0_interface->GetPluginIdByName(pluginname), handler,0); 
}


void wait(int sleep_time)
{
	sys_timer_sleep(sleep_time);	
}
void (*paf_55EE69A7)()=0;
void lockInputDevice() { paf_55EE69A7(); }
void (*paf_E26BBDE4)()=0;
void unlockInputDevice() { paf_E26BBDE4(); }

int load_functions()
{	
	(void*&)(View_Find) = (void*)((int)getNIDfunc("paf",0xF21655F3));
	(void*&)(plugin_GetInterface) = (void*)((int)getNIDfunc("paf",0x23AFB290));
	(void*&)(plugin_SetInterface) = (void*)((int)getNIDfunc("paf",0xA1DC401));
	(void*&)(plugin_SetInterface2) = (void*)((int)getNIDfunc("paf",0x3F7CB0BF));

	(void*&)(paf_55EE69A7) = (void*)((int)getNIDfunc("paf",0x55EE69A7)); // lockInputDevice
	(void*&)(paf_E26BBDE4) = (void*)((int)getNIDfunc("paf",0xE26BBDE4)); // unlockInputDevice
	
	(void*&)(xsetting_AF1F161) = (void*)((int)getNIDfunc("xsetting",0xAF1F161));

	load_log_functions();
	load_cfw_functions();

	xmm0_interface = (xmb_plugin_xmm0 *)GetPluginInterface("xmb_plugin",'XMM0');
	xmb2_interface = (xmb_plugin_xmb2 *)GetPluginInterface("xmb_plugin",'XMB2');

	
	setlogpath("/dev_hdd0/tmp/hfw_settings.log"); // default path

	uint8_t data;
	int ret = read_product_mode_flag(&data);
	if(ret == CELL_OK)
	{
		if(data != 0xFF)
		{
			setlogpath("/dev_usb/hfw_settings.log"); // to get output data
		}
	}
	return 0;
}

int setInterface(unsigned int view)
{	
	return plugin_SetInterface2(view, 1, xai_plugin_functions);
}

extern "C" int _xai_plugin_prx_entry(size_t args, void *argp)
{	
	load_functions();
	log_function("xai_plugin","",__FUNCTION__,"()\n",0);
	setInterface(*(unsigned int*)argp);
    return SYS_PRX_RESIDENT;
}

extern "C" int _xai_plugin_prx_stop(void)
{
	log_function("xai_plugin","",__FUNCTION__,"()\n",0);
    return SYS_PRX_STOP_OK;
}

extern "C" int _xai_plugin_prx_exit(void)
{
	log_function("xai_plugin","",__FUNCTION__,"()\n",0);
    return SYS_PRX_STOP_OK;
}


void xai_plugin_interface::xai_plugin_init(int view)
{
	log_function("xai_plugin","1",__FUNCTION__,"()\n",0);
	plugin_SetInterface(view,'ACT0', xai_plugin_action_if);
}

int xai_plugin_interface::xai_plugin_start(void * view)
{
	log_function("xai_plugin","1",__FUNCTION__,"()\n",0);
	return SYS_PRX_START_OK; 
}

int xai_plugin_interface::xai_plugin_stop(void)
{
	log_function("xai_plugin","1",__FUNCTION__,"()\n",0);
	return SYS_PRX_STOP_OK;
}

void xai_plugin_interface::xai_plugin_exit(void)
{
	log_function("xai_plugin","1",__FUNCTION__,"()\n",0);
}

void xai_plugin_interface_action::xai_plugin_action(const char * action)
{	
	log_function("xai_plugin",__VIEW__,__FUNCTION__,"(%s)\n",action);	

	// HFW Tools XML

	// Restart PS3
	if(strcmp(action,"soft_reboot_action")==0)
	{
		xmb_reboot(SYS_SOFT_REBOOT);
	}
	else if(strcmp(action,"hard_reboot_action")==0)
	{
		xmb_reboot(SYS_HARD_REBOOT);
	}
	else if(strcmp(action,"power_off_action")==0)
	{
		xmb_reboot(SYS_POWER_OFF);
	}

	// In-Game Settings
	else if (strcmp(action, "override_sfo") == 0)
	{
		override_sfo();
	}
	/*
	else if (strcmp(action, "enable_screenshot") == 0)
	{
		enable_screenshot();
	}
	*/
	/*
	else if(strcmp(action,"enable_recording")==0)
	{
	enable_recording();
	}
	*/

	// Dump Tools
	else if(strcmp(action,"clean_log")==0)
	{		
		clean_log();
	}
	else if (strcmp(action, "dump_idps") == 0)
	{
		dump_idps();
	}
	else if (strcmp(action, "dump_psid") == 0)
	{
		dump_psid();
	}
	else if(strcmp(action,"log_klic")==0)
	{
		log_klic();
	}
	else if(strcmp(action,"log_secureid")==0)
	{
		log_secureid();
	}
	else if (strcmp(action, "dump_disc_key") == 0)
	{
		dump_disc_key();
	}
	else if (strcmp(action, "backup_registry") == 0)
	{
		backup_registry();
	}

	// Service Tools
	else if (strcmp(action, "applicable_version") == 0)
	{
		applicable_version();
	}
	else if (strcmp(action, "fs_check") == 0)
	{
		//if(fs_check() == CELL_OK)
		//	xmb_reboot(SYS_SOFT_REBOOT);
		sys_sm_shutdown(SYS_SOFT_REBOOT); // no need to unlink files.
	}
	else if (strcmp(action, "rebuild_db") == 0)
	{
		rebuild_db();
		xmb_reboot(SYS_SOFT_REBOOT);
	}
	else if (strcmp(action, "recovery_mode") == 0)
	{
		recovery_mode();
		xmb_reboot(SYS_HARD_REBOOT);
	}
	/*
	else if(strcmp(action,"service_mode")==0)
	{
		if(service_mode() == true)
			xmb_reboot(SYS_HARD_REBOOT);
	}
	*/

	// NoPSN Patches
	else if (strcmp(action, "nopsn_amazon") == 0)
	{
		uint64_t patch = 0x38600001;
		poke_vsh(0x242458, (char*)&patch, 4);// Amazon vshnet_sceLoginServiceGetNpStatus
		patch = 0x4E800020;
		poke_vsh(0x24245C, (char*)&patch, 4);// Amazon vshnet_sceLoginServiceGetNpStatus
		notify("NoPSN Patch Applied For Amazon", 0, 0, 0, 0, false);
	}
	else if (strcmp(action, "nopsn_youtube") == 0)
	{
		uint32_t patch = 0x2F800001;
		poke_vsh(0x1B60A4, (char*)&patch, 4);// Youtube vshnet_sceNpGetStatus
		notify("NoPSN Patch Applied For Youtube", 0, 0, 0, 0, false);
	}
	else if (strcmp(action, "reset_psn_patches") == 0)
	{
		reset_psn_patches();
		notify("NoPSN Patches Reset", 0, 0, 0, 0, false);
	}

	// Kernel Patches
	else if (strcmp(action, "kernel_setfw_version_482") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323031372F30382FULL);
	}
	else if (strcmp(action, "kernel_setfw_version_484") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323031392F30312FULL);
	}
	else if (strcmp(action, "kernel_setfw_version_485") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323031392F30372FULL);
	}

	//

	
}


