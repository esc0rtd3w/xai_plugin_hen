
#include "rebug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gccpch.h"
#include <cell/fs/cell_fs_file_api.h>
#include "log.h"
#include "hfw_settings.h"


void toggle_cobra_enable()
{	
	cellFsRename (stage2cexbak,stage2cex );
	cellFsRename (stage2dexbak,stage2dex );
}

void toggle_cobra_disable()
{
	cellFsRename(stage2cex, stage2cexbak);
	cellFsRename(stage2dex, stage2dexbak);
}

int cobra_mode()
{
	int ret;
	CellFsStat statinfo;
	ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1","CELL_FS_FAT","/dev_rebug",0,0,0,0);
	log_function("xai_plugin",__VIEW__,"cellFsUtilMount","(/dev_rebug) = %x\n",ret);
	if(ret == CELL_OK)
	{
		if(GetProductCode() == 0x82)
		{
			ret = cellFsStat(stage2dex, &statinfo);
			if(ret == CELL_OK)
			{
				toggle_cobra_disable();
				notify("COBRA Mode disabled.");
			}	
			else  
			{
				ret = cellFsStat(stage2dexbak, &statinfo);
				if(ret == CELL_OK)		
				{
					toggle_cobra_enable();
					notify("COBRA Mode enabled.");
				}
				else
				{
					notify("No Cobra found.");
				}
			}
		}
		else
		{	
			ret = cellFsStat(stage2cex, &statinfo);
			if(ret == CELL_OK)
			{
				toggle_cobra_disable();
				notify("COBRA Mode disabled.");
			}
			else  
			{
				ret = cellFsStat(stage2cexbak, &statinfo);
				if(ret == CELL_OK)		
				{
					toggle_cobra_enable();
					notify("COBRA Mode enabled.");
				}
				else
				{
					notify("No Cobra found.");
				}
			}
		}
		log_function("xai_plugin",__VIEW__,"cellFsUtilUnMount","(/dev_rebug) = %x\n",cellFsUtilUnMount("/dev_rebug",0));
		wait(2);
		return ret;
	}
	else
	{
		notify("Unable to mount dev_flash: %x",ret);
		return ret;
	}
}

void normal_mode_to_rebug_mode()
{
	cellFsRename(vshself,vshnrm);
	cellFsRename(vshswp,vshself);

	cellFsRename(idxdat,idxnrm);
	cellFsRename(idxswp,idxdat);

	cellFsRename(vertxt,vernrm);
	cellFsRename(verswp,vertxt);
}
void rebug_mode_to_normal_mode()
{
	cellFsRename(vshself,vshswp);
	cellFsRename(vshnrm,vshself);
	
	cellFsRename(idxdat,idxswp);
	cellFsRename(idxnrm,idxdat);
	
	cellFsRename(vertxt,verswp);
	cellFsRename(vernrm,vertxt);
}
int rebug_mode()
{	
	int ret;
	CellFsStat statinfo;
	ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1","CELL_FS_FAT","/dev_rebug",0,0,0,0);
	log_function("xai_plugin",__VIEW__,"cellFsUtilMount","(/dev_rebug) = %x\n",ret);
	if(ret == CELL_OK)
	{
		ret = cellFsStat(vshswp, &statinfo); // "/dev_rebug/vsh/module/vsh.self.swp";
		if(ret!=CELL_OK){log("cellFsStat(vshswp) = %x\n",ret);}
		ret |= cellFsStat(idxswp,&statinfo); // "/dev_rebug/vsh/etc/index.dat.swp";
		if(ret!=CELL_OK){log("cellFsStat(idxswp) = %x\n",ret);}
		ret |= cellFsStat(verswp,&statinfo); // "/dev_rebug/vsh/etc/version.txt.swp";
		if(ret!=CELL_OK){log("cellFsStat(verswp) = %x\n",ret);}
		if(ret == CELL_OK)
		{
			normal_mode_to_rebug_mode();
		}
		else
		{
			ret = cellFsStat(vshnrm, &statinfo); // "/dev_rebug/vsh/module/vsh.self.nrm";
			if(ret!=CELL_OK){log("cellFsStat(vshnrm) = %x\n",ret);}
			ret |= cellFsStat(idxnrm,&statinfo); // "/dev_rebug/vsh/etc/index.dat.nrm";
			if(ret!=CELL_OK){log("cellFsStat(idxnrm) = %x\n",ret);}
			ret |= cellFsStat(vernrm,&statinfo); // "/dev_rebug/vsh/etc/version.txt.nrm";
			if(ret!=CELL_OK){log("cellFsStat(vernrm) = %x\n",ret);}
			if(ret == CELL_OK)
			{				
				rebug_mode_to_normal_mode();
			}
			else
			{
				notify("Unable to switch mode");
			}
		}
		log_function("xai_plugin",__VIEW__,"cellFsUtilUnMount","(/dev_rebug) = %x\n",cellFsUtilUnMount("/dev_rebug",0));
		wait(2);
		return ret;
	}
	else
	{
		notify("Unable to mount dev_flash: %x",ret);
		return ret;
	}
}

void debugsettings_mode()
{
	int ret;
	CellFsStat statinfo;
	ret = cellFsUtilMount("CELL_FS_IOS:BUILTIN_FLSH1","CELL_FS_FAT","/dev_rebug",0,0,0,0);
	log_function("xai_plugin",__VIEW__,"cellFsUtilMount","(/dev_rebug) = %x\n",ret);
	if(ret == CELL_OK)
	{		
		ret = cellFsStat(sysconfcex, &statinfo); // "/dev_rebug/vsh/module/sysconf_plugin.sprx.cex";
		if(ret == CELL_OK)
		{
			ret = cellFsStat(sysconfprx, &statinfo); // "/dev_rebug/vsh/module/sysconf_plugin.sprx";
			if(ret == CELL_OK)
			{
				cellFsRename(sysconfprx,sysconfdex);
				cellFsRename(sysconfcex,sysconfprx);
				notify("[DEBUG SETTINGS: MENU CEX QA] is now active.");
			}
			else
			{
				notify("Beware: No sysconf_plugin.sprx found!");
			}
		}
		else
		{
			ret = cellFsStat(sysconfdex, &statinfo); // "/dev_rebug/vsh/module/sysconf_plugin.sprx.dex";
			if(ret == CELL_OK)
			{
				ret = cellFsStat(sysconfprx, &statinfo); // "/dev_rebug/vsh/module/sysconf_plugin.sprx";
				if(ret == CELL_OK)
				{
					cellFsRename(sysconfprx,sysconfcex);
					cellFsRename(sysconfdex,sysconfprx);
					notify("[DEBUG SETTINGS: MENU DEBUG] is now active.");
				}
				else
				{
					notify("Beware: No sysconf_plugin.sprx found!");
				}
			}
			else
			{
				notify("Nothing changed.");
			}
		}

		log_function("xai_plugin",__VIEW__,"cellFsUtilUnMount","(/dev_rebug) = %x\n",cellFsUtilUnMount("/dev_rebug",0));
		wait(2);
		return;
	}
	else
	{
		notify("Unable to mount dev_flash: %x",ret);
		return;
	}
}


void download_toolbox()
{
	notify("Downloading Toolbox...");
	downloadPKG(L"http://rebug.me/?wpfb_dl=142");
}

void install_toolbox()
{
	char pkgpath[255];
	memset(pkgpath,0,255);
	searchDirectory("/dev_hdd0/tmp/downloader/","REBUG_TOOLBOX_",pkgpath);

	if(pkgpath[0] != 0)
	{
		notify("Installing Toolbox...");
		log("installPKG(%s)\n",pkgpath); 
		installPKG(pkgpath);
		while(FindView("nas_plugin") != 0)
		{
			wait(2);
		}
		cellFsUnlink(pkgpath);
	}
	else
	{
		notify("No Toolbox PKG found");
	}
}