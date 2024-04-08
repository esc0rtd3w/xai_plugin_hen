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

	unsigned int xmm0_id = ('X' << 24) | ('M' << 16) | ('M' << 8) | '0';
	unsigned int xmb2_id = ('X' << 24) | ('M' << 16) | ('B' << 8) | '2';
	//xmm0_interface = (xmb_plugin_xmm0 *)GetPluginInterface("xmb_plugin",'XMM0');
	//xmb2_interface = (xmb_plugin_xmb2 *)GetPluginInterface("xmb_plugin",'XMB2');
	xmm0_interface = (xmb_plugin_xmm0 *)GetPluginInterface("xmb_plugin", xmm0_id);
	xmb2_interface = (xmb_plugin_xmb2 *)GetPluginInterface("xmb_plugin", xmb2_id);

	
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
	unsigned int act0_id = ('A' << 24) | ('C' << 16) | ('T' << 8) | '0';
	log_function("xai_plugin","1",__FUNCTION__,"()\n",0);
	//plugin_SetInterface(view,'ACT0', xai_plugin_action_if);
	plugin_SetInterface(view, act0_id, xai_plugin_action_if);
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

	// Basic Tools
	else if(strcmp(action, "show_temp") == 0)	
	{
		check_temperature();
	}

	// QA Tools
	else if(strcmp(action, "check_qa") == 0)
	{
		read_qa_flag();
	}

	// Dump Tools
	else if(strcmp(action, "dump_lv2") == 0)	
	{
		dump_lv2();		
	}
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
	else if(strcmp(action, "toggle_hdd_space") == 0)
	{
		unlock_hdd_space();
	}
	/*
	else if(strcmp(action,"service_mode")==0)
	{
		if(service_mode() == true)
			xmb_reboot(SYS_HARD_REBOOT);
	}
	*/

	// Update Tools

	// PS3HEN Automatic Update Toggle
	else if (strcmp(action, "toggle_auto_update") == 0)
	{
		toggle_auto_update();
	}

	// PS3HEN libaudio Patch Toggle
	else if (strcmp(action, "toggle_patch_libaudio") == 0)
	{
		toggle_patch_libaudio();
	}

	// Clear Web Cache: History
	else if (strcmp(action, "toggle_clear_web_history") == 0)
	{
		toggle_clear_web_history();
	}

	// Clear Web Cache: Auth Cache
	else if (strcmp(action, "toggle_clear_web_auth_cache") == 0)
	{
		toggle_clear_web_auth_cache();
	}

	// Clear Web Cache: Cookie
	else if (strcmp(action, "toggle_clear_web_cookie") == 0)
	{
		toggle_clear_web_cookie();
	}

	// Clear PSN Cache: CI
	else if (strcmp(action, "toggle_clear_psn_ci") == 0)
	{
		toggle_clear_psn_ci();
	}

	// Clear PSN Cache: MI
	else if (strcmp(action, "toggle_clear_psn_mi") == 0)
	{
		toggle_clear_psn_mi();
	}

	// Clear PSN Cache: PTL
	else if (strcmp(action, "toggle_clear_psn_ptl") == 0)
	{
		toggle_clear_psn_ptl();
	}

	// Switch HEN Mode Release
	else if (strcmp(action, "hen_mode_release") == 0)
	{
		switch_hen_mode(0);
	}

	// Switch HEN Mode Debug
	else if (strcmp(action, "hen_mode_debug") == 0)
	{
		switch_hen_mode(1);
	}

	// Switch HEN Mode USB Release
	else if (strcmp(action, "hen_mode_usb_000") == 0)
	{
		switch_hen_mode(2);
	}

	// Switch HEN Mode USB Debug
	else if (strcmp(action, "hen_mode_usb_001") == 0)
	{
		switch_hen_mode(3);
	}

	/*
	// PS3HEN Repair Installation Files Toggle
	else if (strcmp(action, "toggle_hen_repair") == 0)
	{
		toggle_hen_repair();
	}
	*/

	// Toggle Developer Build Type
	else if (strcmp(action, "toggle_hen_dev_build") == 0)
	{
		toggle_hen_dev_build();
	}

	// Disable Remapping On Next Reboot
	else if (strcmp(action, "disable_remaps_on_next_boot") == 0)
	{
		disable_remaps_on_next_boot();
	}

	// Remove check file for HEN Install Flag
	else if (strcmp(action, "trigger_hen_install") == 0)
	{
		remove_file("/dev_rewrite/vsh/resource/explore/icon/hen_enable.png", "Reboot to re-install PS3HEN");
	}

	// Uninstall PS3HEN
	else if (strcmp(action, "uninstall_hen") == 0)
	{
		uninstall_hen();
	}

	// Toggle HotKey Polling on HEN Launch
	else if (strcmp(action, "toggle_hotkey_polling") == 0)
	{
		toggle_hotkey_polling();
	}

	// Toggle app_home support
	else if (strcmp(action, "toggle_app_home") == 0)
	{
		toggle_app_home();
	}

	// Toggle Quick Preview support
	else if (strcmp(action, "toggle_quick_preview") == 0)
	{
		toggle_quick_preview();
	}
	
	/*
	// NoPSN Patches
	else if (strcmp(action, "nopsn_amazon") == 0)
	{
		// Amazon vshnet_sceLoginServiceGetNpStatus
		uint32_t patch1 = 0x38600001;
		uint32_t patch2 = 0x4E800020;
		poke_vsh(0x242458, (char*)&patch1, 4);
		poke_vsh(0x24245C, (char*)&patch2, 4);
		notify("NoPSN Patch Applied For Amazon", 0, 0, 0, 0, false);
	}
	else if (strcmp(action, "nopsn_hulu") == 0)
	{
		// Hulu
		// 0x24557C
		uint32_t patch1 = 0x2F800001;
		//uint32_t patch2 = 0x4E800020;
		poke_vsh(0x242C10, (char*)&patch1, 4);
		//poke_vsh(0x245580, (char*)&patch2, 4);
		notify("NoPSN Patch Applied For Hulu", 0, 0, 0, 0, false);
	}
	else if (strcmp(action, "nopsn_youtube") == 0)
	{
		// Youtube vshnet_sceNpGetStatus
		uint32_t patch = 0x2F800001;
		poke_vsh(0x1B60A4, (char*)&patch, 4);
		notify("NoPSN Patch Applied For Youtube", 0, 0, 0, 0, false);
	}
	else if (strcmp(action, "nopsn_test") == 0)
	{
		// TEST ONLY


		// 001B6080 _Export_vshnet_sceNpGetStatus
		// Allows YouTube to work
		uint32_t patch1a = 0x38600001;
		uint32_t patch1b = 0x4E800020;
		uint32_t addr1a = 0x1B6080;
		uint32_t addr1b = 0x1B6084;
		poke_vsh(addr1a, (char*)&patch1a, 4);
		poke_vsh(addr1b, (char*)&patch1b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpGetStatus: 0x%08X / %08X\n_Export_vshnet_sceNpGetStatus: 0x%08X / %08X\n", addr1a, patch1a, addr1b, patch1b, false);

		// 000F54E8 UNK_MANAGER_SIGNOUT
		uint32_t patch2a = 0x38600000;
		uint32_t patch2b = 0x4E800020;
		uint32_t addr2a = 0xF54E8;
		uint32_t addr2b = 0xF54EC;
		poke_vsh(addr2a, (char*)&patch2a, 4);
		poke_vsh(addr2b, (char*)&patch2b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_MANAGER_SIGNOUT: 0x%08X / %08X\nUNK_MANAGER_SIGNOUT: 0x%08X / %08X\n", addr2a, patch2a, addr2b, patch2b, false);

		// Loop
		// 002774D8                 bne       cr7, UNK_NP_GET_STATUS
		uint32_t patch3a = 0x60000000;
		uint32_t addr3a = 0x2774D8;
		poke_vsh(addr3a, (char*)&patch3a, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nbne       cr7, UNK_NP_GET_STATUS: 0x%08X / %08X\n", addr3a, patch3a, false);

		// 001B7C18 _Export_vshnet_sceNpGetNpId
		uint32_t patch4a = 0x38600001;
		uint32_t patch4b = 0x4E800020;
		uint32_t addr4a = 0x1B7C18;
		uint32_t addr4b = 0x1B7C1C;
		poke_vsh(addr4a, (char*)&patch4a, 4);
		poke_vsh(addr4b, (char*)&patch4b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpGetNpId: 0x%08X / %08X\n_Export_vshnet_sceNpGetNpId: 0x%08X / %08X\n", addr4a, patch4a, addr4b, patch4b, false);

		// 002439BC _Export_vshnet_sceLoginServiceInit
		uint32_t patch5a = 0x38600001;
		uint32_t patch5b = 0x4E800020;
		uint32_t addr5a = 0x2439BC;
		uint32_t addr5b = 0x2439C0;
		poke_vsh(addr5a, (char*)&patch5a, 4);
		poke_vsh(addr5b, (char*)&patch5b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceInit: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceInit: 0x%08X / %08X\n", addr5a, patch5b, addr5a, patch5b, false);

		// 002438CC _Export_vshnet_sceLoginServiceLocalLogin
		uint32_t patch6a = 0x38600000;
		uint32_t patch6b = 0x4E800020;
		uint32_t addr6a = 0x2438CC;
		uint32_t addr6b = 0x2438D0;
		poke_vsh(addr6a, (char*)&patch6a, 4);
		poke_vsh(addr6b, (char*)&patch6b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceLocalLogin: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceLocalLogin: 0x%08X / %08X\n", addr6a, patch6b, addr6a, patch6b, false);

		// 00242F1C _Export_vshnet_sceLoginServiceLocalLogout
		uint32_t patch7a = 0x38600000;
		uint32_t patch7b = 0x4E800020;
		uint32_t addr7a = 0x242F1C;
		uint32_t addr7b = 0x242F20;
		poke_vsh(addr7a, (char*)&patch7a, 4);
		poke_vsh(addr7b, (char*)&patch7b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceLocalLogout: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceLocalLogout: 0x%08X / %08X\n", addr7a, patch7a, addr7b, patch7b, false);

		// 00242CC0 _Export_vshnet_sceLoginServiceNetworkLogin
		uint32_t patch8a = 0x38600001;// 0 prevents signin / 1 gives error 0x00000001, some apps load, ie Amazon
		uint32_t patch8b = 0x4E800020;
		uint32_t addr8a = 0x242CC0;
		uint32_t addr8b = 0x242CC4;
		poke_vsh(addr8a, (char*)&patch8a, 4);
		poke_vsh(addr8b, (char*)&patch8b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceNetworkLogin: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceNetworkLogin: 0x%08X / %08X\n", addr8a, patch8a, addr8b, patch8b, false);

		// 00242BF0 _Export_vshnet_sceLoginServiceNetworkLogout
		uint32_t patch9a = 0x38600000;
		uint32_t patch9b = 0x4E800020;
		uint32_t addr9a = 0x242BF0;
		uint32_t addr9b = 0x242BF4;
		poke_vsh(addr9a, (char*)&patch9a, 4);
		poke_vsh(addr9b, (char*)&patch9b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceNetworkLogout: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceNetworkLogout: 0x%08X / %08X\n", addr9a, patch9a, addr9b, patch9b, false);

		// 002438D4 _Export_vshnet_sceLoginServiceTerm
		uint32_t patch10a = 0x38600001;
		uint32_t patch10b = 0x4E800020;
		uint32_t addr10a = 0x2438D4;
		uint32_t addr10b = 0x2438D8;
		poke_vsh(addr10a, (char*)&patch10a, 4);
		poke_vsh(addr10b, (char*)&patch10b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceLoginServiceTerm: 0x%08X / %08X\n_Export_vshnet_sceLoginServiceTerm: 0x%08X / %08X\n", addr10a, patch10a, addr10b, patch10b, false);

		// 001B34DC _Export_vshnet_sceNpLogin
		uint32_t patch11a = 0x38600001;
		uint32_t patch11b = 0x4E800020;
		uint32_t addr11a = 0x1B34DC;
		uint32_t addr11b = 0x1B34E0;
		poke_vsh(addr11a, (char*)&patch11a, 4);
		poke_vsh(addr11b, (char*)&patch11b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n", addr11a, patch11a, addr11b, patch11b, false);

		// 001B44B8 _Export_vshnet_sceNpLogin2
		uint32_t patch12a = 0x38600001;
		uint32_t patch12b = 0x4E800020;
		uint32_t addr12a = 0x1B44B8;
		uint32_t addr12b = 0x1B44BC;
		poke_vsh(addr12a, (char*)&patch12a, 4);
		poke_vsh(addr12b, (char*)&patch12b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n", addr12a, patch12a, addr12b, patch12b, false);

		// 001B43BC _Export_vshnet_sceNpLogout
		uint32_t patch13a = 0x38600000;
		uint32_t patch13b = 0x4E800020;
		uint32_t addr13a = 0x1B43BC;
		uint32_t addr13b = 0x1B43C0;
		poke_vsh(addr13a, (char*)&patch13a, 4);
		poke_vsh(addr13b, (char*)&patch13b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n_Export_vshnet_sceNpLogin: 0x%08X / %08X\n", addr13a, patch13a, addr13b, patch13b, false);

		// 002452AC UNK_NP_ONLINE_0
		// Setting to return 1 in r3 breaks some shit!
		// if you sign in to psn, it forces a signin msg loop on xmb and loading friendim assets (PSN Store Icon blinks)
		uint32_t patch14a = 0x38600001;
		uint32_t patch14b = 0x4E800020;
		uint32_t addr14a = 0x2452AC;
		uint32_t addr14b = 0x2452B0;
		poke_vsh(addr14a, (char*)&patch14a, 4);
		poke_vsh(addr14b, (char*)&patch14b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_0: 0x%08X / %08X\nUNK_NP_ONLINE_0: 0x%08X / %08X\n", addr14a, patch14a, addr14b, patch14b, false);

		// 002452FC                 ble       cr7, UNK_NP_ONLINE_1
		// Original bytes:  40 9D 01 00
		// crashes ps3 when you sign in
		uint32_t patch15a = 0x4B9D0100;
		uint32_t addr15a = 0x2452FC;
		poke_vsh(addr15a, (char*)&patch15a, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_1: 0x%08X / %08X\nUNK_NP_ONLINE_1: 0x%08X / %08X\n", addr15a, patch15a, false);

		// 00244AC0 UNK_NP_ONLINE_3
		// blocks signin to psn?
		uint32_t patch16a = 0x38600001;
		uint32_t patch16b = 0x4E800020;
		uint32_t addr16a = 0x244AC0;
		uint32_t addr16b = 0x244AC0;
		poke_vsh(addr16a, (char*)&patch16a, 4);
		poke_vsh(addr16b, (char*)&patch16b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_3: 0x%08X / %08X\nUNK_NP_ONLINE_3: 0x%08X / %08X\n", addr16a, patch16a, addr16b, patch16b, false);

		// unk
		uint32_t patch17a = 0x38600001;
		uint32_t patch17b = 0x4E800020;
		uint32_t addr17a = 0x244AC0;
		uint32_t addr17b = 0x244AC0;
		poke_vsh(addr17a, (char*)&patch17a, 4);
		poke_vsh(addr17b, (char*)&patch17b, 4);
		notify("NoPSN Patch Applied For TEST ONLY\nUNK_NP_ONLINE_3: 0x%08X / %08X\nUNK_NP_ONLINE_3: 0x%08X / %08X\n", addr17a, patch17a, addr17b, patch17b, false);



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
	else if (strcmp(action, "kernel_setfw_version_486") == 0)
	{
		kpatch(0x80000000002FCB68ULL, 0x323032302F30312FULL);
	}
	*/

	//

	
}


