xai_plugin by mysis - Release 0.1

Happy New Year Everyone! 

Features:

 * XMB Icons for nice cfw tasks, nicely listed in network column
 * XMB-Actions without the need for webbrowser for each step
 * Simply select and its executed!
 * No Thread waiting for controller input! 
 * No additional CPU time stolen!
 * BD Remarry without downgrading!
 * Enter Factory Service Mode up to latest Firmware without Dongle!


=CFW-Settings=

Clean Log File                    - Gives you the option to delete the Log-File
Dump Disc Hash Key                - This Option will write retrieve disc hash key
                                    from an ORIGINAL game disc and save it to log file
                                    This works without running the actual game!
Log Klicense usage                - Games that use klicense for accessing edat-files
                                    this option will save filename and klicensee to log
                                    file.
Log Secure File ID usage          - This will log save data name and file id key
Enable In-Game Screenshot         - This will only Enable for current system runtime.
Override Disc SFO                 - Will apply SFO Attribute (0xA5) Remoteplay and
                                    SystemBGM to Disc Games. It will prolly not work with
                                    its Updates.
Display applicable version        - Tells you the minimum downgrade version of your system 
Dump IDPS                         - Prints your IDPS in cfw-settings.log
Set dev_flash from USB            - Jailcrab code for writing Lv2Kernel redirecting
                                    /dev_flash/ access to a mounted /dev_usb/
Remarry Bluray Drive              - Remarries the bd drive to the System
Re-Initialize VTRM-Region         - Aka RSOD-Fix if VTRM not a hw problem
Toggle DLNA                       - Turns DLNA Media Server On/Off, usefull for DEX
Rebulid Database                  - Reboots with Database rebuilding flag set
Check Filesystem                  - Reboots and allows you to check and repair filesystem
Toggle Recovery Mode              - Reboots into Recovery Mode
Toggle Factory Service Mode       - Reboots into Factory Service Mode without Dongle


=REBUG-Settings=

Toggle Cobra Mode                 - Enables or if active disables Cobra Mode
Toggle Rebug Mode                 - Enables or if active disables Rebug Mode
Toggle Debug Settings Menu        - Switches between "CEX QA" and "DEX" Debug Settings
Download latest Rebug Toolbox
Install downloaded Rebug Toolbox


=Note=
 * should not be fw dependant, tested on 4.46 and 4.7x and does not use hardcoded offset patches
 * requires peek+poke (sc6+7+8+9) for few options
 * Log File path: /dev_hdd0/tmp/cfw-settings.log     
   (Note: in FSM its /dev_usb/cfw-settings.log + hidden + system file flagged)

 * if you are using another xai_plugin for ex. rebooting, it can lead to incompatibility
   to prevent that, change the actual module action in (probably) category_user.xml (?) to:

    "<Pair key="module_name"><String>xai_plugin</String></Pair>"
    "<Pair key="module_action"><String>soft_reboot_action</String></Pair>"          // soft reboot

    or

    "<Pair key="module_name"><String>xai_plugin</String></Pair>"
    "<Pair key="module_action"><String>hard_reboot_action</String></Pair>"          // hard reboot


=Installation=

copy "xai_plugin.sprx" AND              
     "videorec.sprx"                    
to "/dev_blind/vsh/module/"

copy "xai_plugin.rco" 
to "/dev_blind/vsh/resource/"

copy "category_network.xml",            (cfw-settings added for CEX xmb)
     "category_network_tool2.xml" and   (cfw-settings added for DEX xmb)
     "cfw_settings_en.xml"              (contains cfw-settings and rebug-settings xmb-folders)
to -> "/dev_blind/vsh/resource/explore/xmb/"






=BD Remarry=

1) Toggle Factory Service Mode (should be easy now)
2) Put "eid_root_key" that belongs to the console to /dev_usb/
3) Select Remarry Bluray Drive in Network->cfw-settings->Remarry Bluray Drive
4) If everything went fine it should have notified: "CEX_drive_init() succeeded"
5) Dont forget to repair CRL/DRL if you need to fix it

Successfully remarried /dev_usb/cfw-settings.log should look like:

2011-12-31 19:00:24 [xai_plugin] :  : _xai_plugin_prx_entry()
2011-12-31 19:00:24 [xai_plugin] : 1 : xai_plugin_init()
2011-12-31 19:00:24 [xai_plugin] : 1 : xai_plugin_start()
2011-12-31 19:00:24 [xai_plugin] : ACT0 : xai_plugin_action(remarry_bd)
Looking for lv1 offset
Found lv1 code @0xac574
EID2 P-Block decrypted
EID2 S-Block decrypted
sys_storage_open(bdvd) = 0
stg BDVD Auto Request Sense OFF success = 0
Identified Drive = SONY    PS-SYSTEM   302R4154                   
ps3rom_lv2_mode_select(2) = 0
ps3rom_lv2_write_buffer(2,60) = 0
ps3rom_lv2_mode_select(3) = 0
ps3rom_lv2_write_buffer(3,670) = 0
ps3rom_lv2_mode_select(4) = 0
ps3rom_lv2_write_buffer(4,8000) = 0
CEX_drive_init() succeeded
2011-12-31 19:01:20 [xai_plugin] : ACT0 : xai_plugin_action(service_mode)
Product Mode Disabled





= Thanks =

Sandungas - for the xml adding and rco
Joonie    
