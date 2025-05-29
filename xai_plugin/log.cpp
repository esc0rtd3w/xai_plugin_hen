
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gccpch.h"
#include <cell/fs/cell_fs_file_api.h>
#include <cell/rtc.h>

void load_log_functions()
{	
	(void*&)(vsh_sprintf) = (void*)((int)getNIDfunc("stdc",0x273B9711));
}

void log_data(const void * buffer, int bufsize)
{	
	log("Dumping Data:\n");
	char tmp[0x30];
	for(int i=0;i<bufsize;i=i+0x10)
	{
		log("%08X  ", ((int)buffer)+i);
		for(int j=0;j<0x10;j++)
		{
			char * o = (char*)buffer + i + j;
			log("%02X ",(unsigned char)(*o));
		}
		for(int j=0;j<0x10;j++)
		{
			char * o = (char*)buffer + i + j;
			log("%c",(unsigned char)(*o));
		}
		//log(hex_dump(tmp,((int)buffer)+i,0x10));
		log("\n");
	}
}

int sprintf_(char * str, const char * format, int v1, int v2)
{
	return vsh_sprintf(str,format,v1,v2);
}

void log(char * format, float param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp);
}

void log(char * format, int param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp);
}

void log(const char * format, int param1, const char* param2)
{
	char tmp[0x200];
	vsh_sprintf(tmp, format, param1, param2);
	log(tmp);
}

/*void log(const char format, const char* param1)
{
	char tmp[0x250];
	vsh_sprintf(tmp, (char*)format, param1);
	log(tmp);
}*/

void log(const char * format, int param1, const char* param2, const char* param3)
{
	char tmp[0x250];
	vsh_sprintf(tmp, format, param1, param2, param3);
	log(tmp);
}

void log(char * format, const char * param1)
{
	log(format,(char*)param1);
}

void log(char * format, char * param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp);
}

void log(char * format, unsigned char param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp);
}

void log(char * format, const wchar_t * param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp,format, param1);
	log(tmp);
}

char log_path[0x100]; 
void setlogpath(char * path)
{
	strcpy(log_path,path);
}
char * getlogpath()
{
	return log_path;
}
void log(char * buffer)
{
	console_write(buffer);
	int size = strlen(buffer);
	CellFsErrno err;
	int fd;
	uint64_t nrw;
	
	if(cellFsOpen(log_path, CELL_FS_O_RDWR|CELL_FS_O_CREAT|CELL_FS_O_APPEND, &fd, NULL, 0) != CELL_OK)
	{
		//notify("unable to open.");
	}
	else
	{
		if(cellFsWrite(fd, buffer, size, &nrw) !=CELL_OK)
		{
			//notify("unable to write.");
		}
		else
		{
			//notify("data written.");
		}
	}
	err = cellFsClose(fd);
}

void log_key(char * keyname,void * key)
{
	log("%s: ",keyname);log("%08X",*(int*)key);log("%08X",*((int*)key+1));log("%08X",*((int*)key+2));log("%08X\n",*((int*)key+3));
}

void log(char * pluginname,char * view, const char * function)
{	
	CellRtcDateTime t;
	cellRtcGetCurrentClockLocalTime(&t);
	
	char buffer[0x120];

	vsh_sprintf(buffer,"%04d-%02d-%02d %02d:%02d:%02d [%s] : %s : %s",t.year,t.month,t.day,t.hour,t.minute,t.second,pluginname,view,function);

	log(buffer);
}

void log_function(char * pluginname,char * view, const char * function, char * format, int param1) 
{
	log(pluginname,view,function);
	log(format,param1);
}

void log_function(char * pluginname,char * view, const char * function, char * format, const char* param1) 
{
	log(pluginname,view,function);
	log(format,param1);
}

void notify(const char * format, int param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

/*void notify(const char* format, const char* param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}*/

void notify(const char * format, int param1, int param2)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, int param1, int param2, int param3, int param4)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3, param4);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char* format, const char* param1, uint64_t param2, uint32_t param3, uint32_t param4)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3, param4);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, char* param1, int param2)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, const char* param1, int param2)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, int param1, int param2, bool logging)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2);
	if (logging == true){ log(tmp); log("\n"); }
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, int param1, int param2, int param3, int param4, bool logging)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3, param4);
	if (logging == true){ log(tmp); log("\n"); }
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, int param1, int param2, int param3, int param4, int param5, int param6, bool logging)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3, param4, param5, param6);
	if (logging == true){ log(tmp); log("\n"); }
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(const char * format, int param1, char * param2, int param3, int param4, bool logging)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3, param4);
	if (logging == true){ log(tmp); log("\n"); }
	vshtask_A02D46E7(0, tmp);
}

void notify(char * format, char * param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, tmp);
}

void notify(char * param)
{
	log(param);	log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7)); // notification message func
	vshtask_A02D46E7(0, param);
}

void notify64(const char* format, uint64_t param1)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param1);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));
	vshtask_A02D46E7(0, tmp);
}

void notify64(const char * format, uint64_t param1, uint64_t param2)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));
	vshtask_A02D46E7(0, tmp);
}

void notify64(const char * format, uint64_t param1, uint64_t param2, uint64_t param3)
{
	char tmp[0x100];
	vsh_sprintf(tmp, format, param1, param2, param3);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));
	vshtask_A02D46E7(0, tmp);
}

void notify64(const char * format, char* param1, uint64_t param2, uint64_t param3)
{
	char tmp[0x100];
	vsh_sprintf(tmp, (char*)format, param1, param2, param3);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));
	vshtask_A02D46E7(0, tmp);
}

void notify64(const char * format, char* param1, uint64_t param2, uint64_t param3, uint64_t param4)
{
	char tmp[0x100];
	vsh_sprintf(tmp, (char*)format, param1, param2, param3, param4);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));
	vshtask_A02D46E7(0, tmp);
}

void notify64(const char * format, uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4, uint64_t param5, uint64_t param6, uint64_t param7, uint64_t param8)
{
	char tmp[0x100];
	vsh_sprintf(tmp, (char*)format, param1, param2, param3, param4, param5, param6, param7, param8);
	log(tmp); log("\n");
	(void*&)(vshtask_A02D46E7) = (void*)((int)getNIDfunc("vshtask", 0xA02D46E7));
	vshtask_A02D46E7(0, tmp);
}


void dump_file(const char * path, void * buffer, int size)
{
	CellFsErrno err;
	int fd;
	uint64_t nrw;
					
	if(cellFsOpen(path, CELL_FS_O_RDWR|CELL_FS_O_CREAT, &fd, NULL, 0) != CELL_OK)
	{
		notify("unable to open.");
	}
	else
	{
		if(cellFsWrite(fd, buffer, size, &nrw) !=CELL_OK)
		{
			notify("unable to write.");
		}
		else
		{
			notify("data written.");
		}
	}
	err = cellFsClose(fd);
}