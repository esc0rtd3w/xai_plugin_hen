//#include <sysutil\sysutil_msgdialog.h>
//#include <sysutil\sysutil_oskdialog.h>
//#include <sysutil\sysutil_oskdialog_ext.h>

#define PRODUCT_MODE_FLAG_OFFSET  0x48C07
#define RECOVERY_MODE_FLAG_OFFSET 0x48C61

#define VSH_PROCESS_NAME	"_main_vsh.self"
//#define INLINE inline __attribute__((always_inline))
//#define MAKE_KERNEL_ADDRESS(addr) (0x8000000000000000ULL | ((uint32_t)addr))
//#define MKA MAKE_KERNEL_ADDRESS

//#define TOC 0x34FBB0// CEX 4.82/4.84/4.85
//#define process_rtoc_entry_1 -0x7800

#define LV2						0
#define LV1						1
#define RAM						2

#define LV2_DUMP				"LV2-FW%X.%X%X.bin"
#define LV1_DUMP				"LV1-FW%X.%X%X.bin"
#define RAM_DUMP				"RAM-FW%X.%X%X.bin"
#define TMP_FOLDER				"/dev_hdd0/tmp"

#define SINGLE_BEEP 			0x6
#define DOUBLE_BEEP 			0x36
#define TRIPLE_BEEP 			0x1B6
#define CONTINUOUS_BEEP			0xFFFF

#define process_id_t uint32_t
#define SYSCALL8_OPCODE_PS3MAPI			 		0x7777
#define PS3MAPI_OPCODE_GET_ALL_PROC_PID			0x0021
#define PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID		0x0022
#define PS3MAPI_OPCODE_GET_PROC_MEM				0x0031
#define PS3MAPI_OPCODE_SET_PROC_MEM				0x0032
#define MAX_PROCESS 16

#define QA_FLAG_OFFSET 		0x48C0A

#define printf(...)
//#define DPRINTF(...)
#define DPRINTF		printf

int poke_vsh(uint64_t address, char *buf, int size);
int read_vsh(uint64_t address, char *buf, int size);

void kpatch(uint64_t kaddr, uint64_t kbytes);
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset);
void reset_psn_patches();

uint64_t lv1_peek(uint64_t addr);
uint8_t lv1_peek8(uint64_t addr);
uint16_t lv1_peek16(uint64_t addr) ;
uint32_t lv1_peek32(uint64_t addr);
void lv1_poke( uint64_t addr, uint64_t val);
void lv1_poke32(uint64_t addr, uint32_t value);

void hook_func(void * original,void * backup, void * hook_function);
void load_cfw_functions();

/*void convert_utf16_to_ascii(const uint16_t *utf16, char *ascii, size_t maxLen);
void ascii_to_utf16(const char *ascii, uint16_t *utf16, size_t maxLen);
int getHexInput(const char *prompt, uint64_t *outValue);
int lv1_peek_keyboard();
int lv1_poke_keyboard();*/

//static int extract_field(const char *json, const char *key, char *dest, size_t dest_size);
//void process_json_command(const char *json);
//void process_json_file(const char *filepath);
//void scan_usb_for_json(void);



// HV dump region functions
int dump_lv0_code();
int dump_lv1_code();
int dump_lv2_region();
//int dump_spe_mmio(int idx);
int dump_spe0_mmio();
int dump_spe1_mmio();
int dump_spe2_mmio();
int dump_spe3_mmio();
int dump_spe4_mmio();
int dump_spe5_mmio();
int dump_spe6_mmio();
int dump_pervasive_mem();
//int dump_spe_shadow(int idx);
int dump_spe1_shadow();
int dump_spe2_shadow();
int dump_spe3_shadow();
int dump_spe4_shadow();
int dump_spe5_shadow();
int dump_spe6_shadow();
int dump_xdr_ch1_size();
int dump_xdr_ch0_size();
int dump_xdr_type();

int dump_sb_bus_base();
int dump_sata1_regs();
int dump_sata2_regs();
int dump_usb1_regs();
int dump_usb2_regs();
int dump_gelic_regs();
int dump_encdec_regs();
int dump_sb_ext_intc();
int dump_sb_int_hdl1();
int dump_sb_int_hdl2();
int dump_sb_status();

int dump_syscon_pkt_hdr();
int dump_syscon_pkt_bdy();
int dump_syscon_recv1();
int dump_syscon_recv2();
int dump_syscon_send_hdr();
int dump_syscon_send_bdy();
int dump_syscon_send1();
int dump_syscon_send2();
int dump_syscon_rcv3();
int dump_syscon_testbit();
int dump_syscon_notify();

int dump_sata1_bar();
int dump_sata2_bar();
int dump_gelic_bar();
int dump_encdec_bar();
int dump_encdec_test();
int dump_encdec_cmd();
int dump_usb1_bar();
int dump_usb2_bar();

int dump_sata1_bar2();
int dump_sata2_bar2();
int dump_sata1_bar3();
int dump_sata2_bar3();
int dump_usb1_bar2();
int dump_usb2_bar2();

int dump_nor_flash();
int dump_sys_rom();

int dump_avmngr_regs1();
int dump_avmngr_regs2();
int dump_av_outctrl();
int dump_av_pllctrl();
int dump_av_misc1();
int dump_av_misc2();
int dump_av_misc3();
int dump_av_misc4();
int dump_av_misc5();

int dump_gpu_mem1();
int dump_gpu_mem2();
int dump_gpu_mem3();
int dump_gpu_mem4();
int dump_gpu_mem5();

int dump_rsx_intstate();
int dump_ramin_all();
int dump_ramin_hash();
int dump_ramin_fifo();
int dump_dma_objs();
int dump_graph_objs();
int dump_graph_ctx();

int dump_gameos0();
int dump_gameos1();
int dump_gameos2();
int dump_gameos_htab();

// Dump all regions at once
int dump_all_regions();



// RSX Overclocking

void log_to_usb(const char *message);
void TestRsxClockSettings();
void TestRsxClockSettingsSafe();

void OverclockGpuCoreTest();
void OverclockGpuMemTest();

// Matched Speeds
void set_rsx_clock_100_100();
void set_rsx_clock_150_150();
void set_rsx_clock_200_200();
void set_rsx_clock_250_250();
void set_rsx_clock_300_300();
void set_rsx_clock_350_350();
void set_rsx_clock_400_400();
void set_rsx_clock_450_450();
void set_rsx_clock_500_500();
void set_rsx_clock_550_550();
void set_rsx_clock_600_600();
void set_rsx_clock_650_650();
void set_rsx_clock_700_700();
void set_rsx_clock_750_750();
void set_rsx_clock_800_800();
void set_rsx_clock_850_850();
void set_rsx_clock_900_900();
void set_rsx_clock_950_950();
void set_rsx_clock_1000_1000();

// Core-Only Speeds
void set_rsx_clock_100_650();
void set_rsx_clock_150_650();
void set_rsx_clock_200_650();
void set_rsx_clock_250_650();
void set_rsx_clock_300_650();
void set_rsx_clock_350_650();
void set_rsx_clock_400_650();
void set_rsx_clock_450_650();
void set_rsx_clock_500_650();
void set_rsx_clock_550_650();
void set_rsx_clock_600_650();
//void set_rsx_clock_650_650();// Duplicate
void set_rsx_clock_700_650();
void set_rsx_clock_750_650();
void set_rsx_clock_800_650();
void set_rsx_clock_850_650();
void set_rsx_clock_900_650();
void set_rsx_clock_950_650();
void set_rsx_clock_1000_650();

// Memory Only Speeds
void set_rsx_clock_500_100();
void set_rsx_clock_500_150();
void set_rsx_clock_500_200();
void set_rsx_clock_500_250();
void set_rsx_clock_500_300();
void set_rsx_clock_500_350();
void set_rsx_clock_500_400();
void set_rsx_clock_500_450();
//void set_rsx_clock_500_500();// Duplicate
void set_rsx_clock_500_550();
void set_rsx_clock_500_600();
//void set_rsx_clock_500_650();// Duplicate
void set_rsx_clock_500_700();
void set_rsx_clock_500_750();
void set_rsx_clock_500_800();
void set_rsx_clock_500_850();
void set_rsx_clock_500_900();
void set_rsx_clock_500_950();
void set_rsx_clock_500_1000();

void set_rsx_core_clock_100(void);
void set_rsx_core_clock_150(void);
void set_rsx_core_clock_200(void);
void set_rsx_core_clock_250(void);
void set_rsx_core_clock_300(void);
void set_rsx_core_clock_350(void);
void set_rsx_core_clock_400(void);
void set_rsx_core_clock_450(void);
void set_rsx_core_clock_500(void);
void set_rsx_core_clock_550(void);
void set_rsx_core_clock_600(void);
void set_rsx_core_clock_650(void);
void set_rsx_core_clock_700(void);
void set_rsx_core_clock_750(void);
void set_rsx_core_clock_800(void);
void set_rsx_core_clock_850(void);
void set_rsx_core_clock_900(void);
void set_rsx_core_clock_950(void);
void set_rsx_core_clock_1000(void);

void set_rsx_mem_clock_100(void);
void set_rsx_mem_clock_125(void);
void set_rsx_mem_clock_150(void);
void set_rsx_mem_clock_175(void);
void set_rsx_mem_clock_200(void);
void set_rsx_mem_clock_225(void);
void set_rsx_mem_clock_250(void);
void set_rsx_mem_clock_275(void);
void set_rsx_mem_clock_300(void);
void set_rsx_mem_clock_325(void);
void set_rsx_mem_clock_350(void);
void set_rsx_mem_clock_375(void);
void set_rsx_mem_clock_400(void);
void set_rsx_mem_clock_425(void);
void set_rsx_mem_clock_450(void);
void set_rsx_mem_clock_475(void);
void set_rsx_mem_clock_500(void);
void set_rsx_mem_clock_525(void);
void set_rsx_mem_clock_550(void);
void set_rsx_mem_clock_575(void);
void set_rsx_mem_clock_600(void);
void set_rsx_mem_clock_625(void);
void set_rsx_mem_clock_650(void);
void set_rsx_mem_clock_675(void);
void set_rsx_mem_clock_700(void);
void set_rsx_mem_clock_725(void);
void set_rsx_mem_clock_750(void);
void set_rsx_mem_clock_775(void);
void set_rsx_mem_clock_800(void);
void set_rsx_mem_clock_825(void);
void set_rsx_mem_clock_850(void);
void set_rsx_mem_clock_875(void);
void set_rsx_mem_clock_900(void);
void set_rsx_mem_clock_925(void);
void set_rsx_mem_clock_950(void);
void set_rsx_mem_clock_975(void);
void set_rsx_mem_clock_1000(void);

int sys_ss_get_console_id(void * idps);
int sys_ss_get_open_psid(void * psid);
int cellSsAimGetDeviceId(void * idps);
void clean_log();
void log_klic();
void log_secureid();
void enable_recording();
void enable_screenshot();
bool rsod_fix();
void remarry_bd();
void check_temperature();
int dump_lv2();
void unlock_hdd_space();
void control_led(const char * action);
void override_sfo();
bool enable_hvdbg();
void backup_registry();
void usb_firm_loader();
void dump_disc_key();
void dump_idps();
void dump_psid();
void applicable_version();
void toggle_dlna();
void rebuild_db();
int fs_check();
void recovery_mode();
bool service_mode(); 
void read_qa_flag();
void toggle_generic(char* path_to_file, char* name);
void toggle_auto_update();
void toggle_hen_repair();
void toggle_patch_libaudio();
void toggle_hotkey_polling();
void toggle_app_home();
void toggle_quick_preview();
void toggle_hen_dev_build(); 
void uninstall_hen();
int switch_hen_mode(int mode);// Used for switching from release to debug
void disable_remaps_on_next_boot();
void toggle_rap_bin();

// Clear Web Cache Functions (History, Auth Cache, Cookie)
void toggle_clear_web_history();
void toggle_clear_web_auth_cache();
void toggle_clear_web_cookie();

// Clear PSN Cache Functions (CI, MI, PTL)
void toggle_clear_psn_ci();
void toggle_clear_psn_mi();
void toggle_clear_psn_ptl();

// BadHTAB Testing
int dump_full_ram();
int dump_lv1();
bool test_lv1_peek();
bool test_lv1_peek32();
bool test_lv1_poke();
bool test_lv1_poke32();
void badhtab_copy_log();
void badhtab_toggle_glitcher_test();
void badhtab_toggle_skip_stage1();
//void badhtab_toggle_skip_stage_cfw();
void badhtab_toggle_skip_stage2();
void badhtab_toggle_skip_patch_more_lv1();
void badhtab_toggle_lv1_dump();
void badhtab_toggle_lv1_dump_240m();
void badhtab_toggle_otheros();
void badhtab_toggle_lv2_kernel_self();
void badhtab_toggle_lv2_kernel_fself();

// LV1 Patches
int toggle_lv1_patch(const char* name, uint64_t addr, uint64_t ovalue, uint64_t pvalue);
int toggle_lv1_patch32(const char* name, uint64_t addr, uint32_t ovalue, uint32_t pvalue);
int unmask_bootldr();

void toggle_lv1_patch_unmask_bootldr();
void toggle_lv1_patch_test1();
void toggle_lv1_patch_test2();

union clock_s {
public:
    struct {
    public:
        uint8_t junk1;
        uint8_t junk2;
        uint8_t mul;
        uint8_t junk3;
    };
    uint32_t value;
};
void lv1_read(uint64_t addr, uint64_t size, void *out_Buf);
void lv1_write(uint64_t addr, uint64_t size, const void *in_Buf);

void read_write_generic(const char* src, const char* dest);
void read_write_generic_notify(const char* src, const char* dest);
void read_write_generic2(const char* src, const char* dest, CellFsMode chmod);
void remove_file(char* path_to_file, char* message);
void write_toggle(char* path_to_file, char* message);

void installPKG(char * path);
int download_status();
void downloadPKG(wchar_t * url);

int checkDirectory(char * pDirectoryPath);
void searchDirectory(char * pDirectoryPath, char * fileformat, char * fileout );

int read_recovery_mode_flag(void * data);
int set_recovery_mode_flag(uint8_t value);
int read_product_mode_flag(void * data);
int set_product_mode_flag(uint8_t value);

static int (*update_mgr_read_eprom)(int offset, void * buffer);      
static int (*update_mgr_write_eprom)(int offset, int value);

static int (*xBDVDGetInstance)();

static int (*vsh_2B58A92C)(void*);
static int (*vsh_E20104BE)();
static void *(*allocator_759E0635)(size_t);
static void (*allocator_77A602DD)(void *);

int cellFsUtilMount(const char * device_name, const char * device_fs, const char * device_path, int r6, int write_prot, int r8, int * r9);
int cellFsUtilUnMount(const char * device_path, int r4);

int* load_module(char * path);
int AesCbcCfbEncrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv);
int AesCbcCfbDecrypt(void *out, void *in, uint32_t length, void *user_key, int bits, void *iv);



static uint8_t eid2_indiv_seed_[0x40] = {0x74, 0x92, 0xE5, 0x7C, 0x2C, 0x7C, 0x63, 0xF4, 0x49, 0x42, 0x26, 0x8F, 0xB4, 0x1C, 0x58, 0xED, 
        0x66, 0x83, 0x41, 0xF9, 0xC9, 0x7B, 0x29, 0x83, 0x96, 0xFA, 0x9D, 0x82, 0x07, 0x51, 0x99, 0xD8, 
        0xBC, 0x1A, 0x93, 0x4B, 0x37, 0x4F, 0xA3, 0x8D, 0x46, 0xAF, 0x94, 0xC7, 0xC3, 0x33, 0x73, 0xB3, 
        0x09, 0x57, 0x20, 0x84, 0xFE, 0x2D, 0xE3, 0x44, 0x57, 0xE0, 0xF8, 0x52, 0x7A, 0x34, 0x75, 0x3D};

struct pblock_aes_struct
{
	uint8_t pblock_hdr[0x10];
	uint8_t pblock_des[0x60];
	uint8_t pblock_hash[0x10];
};
struct sblock_aes_struct
{
	uint8_t sblock_hdr[0x10];
	uint8_t sblock_des[0x670];
	uint8_t sblock_hash[0x10];
};
struct eid2_struct
{
	unsigned short pblock_size;
	unsigned short sblock_size;
	uint8_t padding[0x1C]; // 00.... 00 00 / 00 03
	pblock_aes_struct pblock_aes;
	sblock_aes_struct sblock_aes;
};

struct inquiry_block {
    uint8_t pkt[0x20]; /* packet command block           */ 
    uint32_t pktlen;  
    uint32_t blocks;					
    uint32_t block_size;				
    uint32_t proto; /* transfer mode                  */ 
    uint32_t in_out; /* transfer direction             */ 
    uint32_t unknown;
};

enum lv2_atapi_proto {
    NON_DATA_PROTO = 0,
    PIO_DATA_IN_PROTO = 1,
    PIO_DATA_OUT_PROTO = 2,
    DMA_PROTO = 3
};
enum lv2_atapi_in_out {
    DIR_WRITE = 0, /* memory -> device */
    DIR_READ = 1 /* device -> memory */
};
struct lv2_atapi_cmnd_block {
    uint8_t pkt[0x20]; /* packet command block           */ 
    uint32_t pktlen;  
    uint32_t blocks;					
    uint32_t block_size;				
    uint32_t proto; /* transfer mode                  */ 
    uint32_t in_out; /* transfer direction             */ 
    uint32_t unknown;
} __attribute__((packed));

typedef struct
{
	void *unk_00; // 0
	char name[24]; // 8
	// ...
} __attribute__((packed)) UnkProcessStruct;

typedef struct _process_t
{
	void *syscall_table; 				// 0
	uint64_t unk_8[4]; 					// 8
	uint32_t pid; 						// 0x28
	int status; 						// 0x2C
	void *mem_object; 					// 0x30
	UnkProcessStruct *unk_38; 			// 0x38
	uint64_t unk_40; 					// 0x40
	void *first_thread; 				// 0x48 
	uint64_t unk_50; 					// 0x50
	uint64_t unk_58; 					// 0x58
	void *unk_60; 						// 0x60
	void *unk_68; 						// 0x68 vshprocess -> mios2_SPU_Service.elf
	void *unk_70; 						// 0x70 vshprocess -> mios2_SPU_Service.elf
	uint64_t unk_78; 					// 0x78
	uint64_t unk_80; 					// 0x80
	uint64_t unk_88[4]; 				// 0x88
	uint64_t unk_A8; 					// 0xA8  user address?
	struct _process_t *parent;  		// 0xB0
	struct _process_t *first_child;  	// 0xB8  
	struct _process_t *next_sibling; 	// 0xC0
	uint64_t num_children; 				// 0xC8
	void *unk_D0; 	 					// 0xD0
	uint64_t unk_D8; 					// 0xD8
	uint64_t unk_E0; 					// 0xE0
	uint64_t unk_E8; 					// 0xE8
	uint64_t unk_F0[2]; 				// 0xF0
	uint64_t unk_100; 					// 0x100
	uint64_t unk_108; 					// 0x108
	void *unk_110; 						// 0x110
	void *unk_118; 						// 0x118  vshprocess -> pointer to unk_D0
	uint64_t unk_120; 					// 0x120
	void *unk_128; 						// 0x128  only on vshprocess -> same as first_thread
	void *unk_130; 						// 0x130 only on vsh process -> same as first thread
	uint64_t unk_138;	 				// 0x138
	uint64_t unk_140[4]; 				// 0x140
	char *process_image; 				// 0x160
	void *unk_168; 						// 0x168
	uint64_t unk_170; 					// 0x170
	uint64_t unk_178; 					// 0x178
	uint64_t unk_180; 					// 0x180
	uint64_t unk_188[4]; 				// 0x188
	uint64_t unk_1A8; 					// 0x1A8
	uint64_t unk_1B0; 					// 0x1B0
	uint64_t unk_1B8; 					// 0x1B8
	uint64_t unk_1C0; 					// 0x1C0
	uint64_t unk_1C8; 					// 0x1C8
	uint64_t unk_1D0; 					// 0x1D0
	uint64_t unk_1D8; 					// 0x1D8
	uint64_t unk_1E0; 					// 0x1E0
	uint64_t unk_1E8[4]; 				// 0x1E8
	void *object_table; 				// 0x208 waiting for a better name...
	// ...?
	// 0x26C -> sdk version 32bits
} __attribute__((packed)) *process_t;
