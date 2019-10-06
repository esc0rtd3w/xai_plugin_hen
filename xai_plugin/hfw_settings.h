
#define PRODUCT_MODE_FLAG_OFFSET 0x48C07
#define RECOVERY_MODE_FLAG_OFFSET 0x48C61

uint64_t lv1_peek(uint64_t addr);
void lv1_poke( uint64_t addr, uint64_t val);

void hook_func(void * original,void * backup, void * hook_function);
void load_cfw_functions();

int sys_ss_get_console_id(void * idps);
int cellSsAimGetDeviceId(void * idps);
void clean_log();
void log_klic();
void log_secureid();
void enable_recording();
void enable_screenshot();
bool rsod_fix();
void remarry_bd();
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

