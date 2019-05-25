// gccpch.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently.
// gccpch.h.gch will contain the pre-compiled type information
//

#include <stdio.h>


#ifndef __GCCPCH__
#define __GCCPCH__

// TODO: reference additional headers your program requires here
int console_write(const char * s);
int sys_sm_shutdown(uint16_t op);
void xmb_reboot(uint16_t op);
void plugin_shutdown();
int GetProductCode();
void * getNIDfunc(const char * vsh_module, uint32_t fnid);
int FindView(char * pluginname);
int GetPluginInterface(const char * pluginname, int interface_);
int LoadPlugin(char * pluginname, void * handler);
static int (*plugin_SetInterface)(int view, int interface, void * Handler);
static int (*plugin_SetInterface2)(int view, int interface, void * Handler);
static int (*plugin_GetInterface)(int view,int interface);
static int (*View_Find)(const char *);
static int (*vsh_sprintf)( char*, const char*,...);

void wait(int seconds);
void lockInputDevice();
void unlockInputDevice();

static int (*vshtask_A02D46E7)(int,const char *);

#define SYS_SOFT_REBOOT 				0x0200
#define SYS_POWER_OFF					0x1100
#define SYS_HARD_REBOOT					0x1200

#define __VIEW__ "ACT0"

class xai_plugin_interface_action
{	
public:
	static void xai_plugin_action(const char * action);
};


static void * xai_plugin_action_if[3] = {(void*)xai_plugin_interface_action::xai_plugin_action,
							0,
							0};

class xai_plugin_interface
{
public:	
	static void xai_plugin_init(int view);
	static int xai_plugin_start(void * view);
	static int xai_plugin_stop(void);
	static void xai_plugin_exit(void);
};

static void * xai_plugin_functions[4] = {(void*)xai_plugin_interface::xai_plugin_init,
	(void*)xai_plugin_interface::xai_plugin_start,
	(void*)xai_plugin_interface::xai_plugin_stop,
	(void*)xai_plugin_interface::xai_plugin_exit};


#endif
