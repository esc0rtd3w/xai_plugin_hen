
#define PRODUCT_MODE_FLAG_OFFSET  0x48C07
#define RECOVERY_MODE_FLAG_OFFSET 0x48C61

#define VSH_PROCESS_NAME	"_main_vsh.self"
//#define INLINE inline __attribute__((always_inline))
//#define MAKE_KERNEL_ADDRESS(addr) (0x8000000000000000ULL | ((uint32_t)addr))
//#define MKA MAKE_KERNEL_ADDRESS

//#define TOC 0x34FBB0// CEX 4.82/4.84/4.85
//#define process_rtoc_entry_1 -0x7800

#define HPTE_V_BOLTED			0x0000000000000010ULL
#define HPTE_V_VALID			0x0000000000000001ULL
#define HPTE_R_PROT_MASK		0x0000000000000003ULL
#define MM_EA2VA(ea)			((ea) & ~0x8000000000000000ULL)

#define process_id_t uint32_t
#define SYSCALL8_OPCODE_PS3MAPI			 		0x7777
#define PS3MAPI_OPCODE_GET_ALL_PROC_PID			0x0021
#define PS3MAPI_OPCODE_GET_PROC_NAME_BY_PID		0x0022
#define PS3MAPI_OPCODE_GET_PROC_MEM				0x0031
#define PS3MAPI_OPCODE_SET_PROC_MEM				0x0032
#define MAX_PROCESS 16

#define printf(...)
//#define DPRINTF(...)
#define DPRINTF		printf

#define SHA_BLOCKSIZE		(64)
#define SHA_DIGEST_LENGTH	(20)

#define PS3DM_PID(fid, id)	((fid) | (id))
#define PS3DM_FID(pid)		((pid) & ~0xffful)

// These may change on each firmware version
// ----------------------------------------------
#define IDPS_LV1 			0x8000000000064E80ULL
#define UM_PATCH_OFFSET		0x80000000000FEBD4ULL
#define DM_PATCH1_OFFSET	0x800000000016FA64ULL
#define DM_PATCH2_OFFSET	0x800000000016FA88ULL
#define DM_PATCH3_OFFSET	0x800000000016FB00ULL
#define DM_PATCH4_OFFSET	0x800000000016FB08ULL

#define UM_PATCH_ORI	 	0xE8180008
#define DM_PATCH1_ORI	 	0xF8010098
#define DM_PATCH2_ORI	 	0x4BFFF0E5
#define DM_PATCH3_ORI	 	0x38A10070
#define DM_PATCH4_ORI	 	0x48006065
// ----------------------------------------------

#define HV_BASE				0x8000000014000000ULL

#define HV_SIZE 			0x001000	
#define HV_PAGE_SIZE		0x0C	

#define IDPS_SIZE			0x10
#define TOKEN_SIZE			0x50

#define QA_FLAG_OFFSET 		0x48C0A

#define ENABLE				1
#define DISABLE				0

#define FLASH_DEVICE_NAND	0x0100000000000001ULL
#define FLASH_DEVICE_NOR	0x0100000000000004ULL
#define FLASH_FLAGS			0x22ULL

typedef struct
{
    uint8_t     name[7];
    uint8_t     unknown01;
    uint32_t    unknown02; // random nr?
    uint32_t    zero01;
    uint32_t    unknown03; // 0x28?
    uint32_t    unknown04; // 0xd000e990?
    uint8_t     zero02[16];
    uint64_t    total_sectors;
    uint32_t    sector_size;
    uint32_t    unknown05;
    uint8_t     writable;
    uint8_t     unknown06[3];
    uint32_t    unknown07;
} __attribute__((__packed__)) device_info_t;

enum ps3dm_function_packet 
{
	/* SC manager */
	PS3DM_FID_SCM					= 0x00009000,
	PS3DM_PID_SCM_GET_REGION_DATA	= PS3DM_PID(PS3DM_FID_SCM, 6),
	PS3DM_PID_SCM_READ_EEPROM		= PS3DM_PID(PS3DM_FID_SCM, 0xB),
	PS3DM_PID_SCM_WRITE_EEPROM		= PS3DM_PID(PS3DM_FID_SCM, 0xC),
};

struct ps3dm_header 
{
	uint32_t tag;
	uint32_t fid;			/* enum ps3dm_function_packet */
	uint32_t payload_length;
	uint32_t reply_length;
};

struct ps3dm_ss_header 
{
	uint64_t pid;			/* enum ps3dm_function_packet */
	uint64_t fid;			/* enum ps3dm_function_packet */
	uint32_t status;
	uint8_t res[4];
	uint64_t laid;
	uint64_t paid;
};

struct ps3dm_scm_write_eeprom 
{
	struct ps3dm_header dm_hdr;
	struct ps3dm_ss_header ss_hdr;
	uint32_t offset;
	uint8_t res1[4];
	uint32_t nwrite;
	uint8_t res2[4];
	uint64_t buf_size;
	uint8_t buf[0x50];
};

static inline void ps3dm_init_header(struct ps3dm_header *hdr, uint32_t tag, uint32_t fid, uint32_t payload_length, uint32_t reply_length)
{
	hdr->tag = tag;
	hdr->fid = fid;
	hdr->payload_length = payload_length;
	hdr->reply_length = reply_length;
}

static inline void ps3dm_init_ss_header( struct ps3dm_ss_header *hdr, uint64_t pid, uint64_t laid, uint64_t paid)
{
	hdr->pid = pid;
	hdr->fid = PS3DM_FID(pid);
	hdr->laid = laid;
	hdr->paid = paid;
}

int poke_vsh(uint64_t address, char *buf, int size);
int read_vsh(uint64_t address, char *buf, int size);

void kpatch(uint64_t kaddr, uint64_t kbytes);
void psn_patch(uint32_t paddr, uint32_t pbytes, bool reset);
void reset_psn_patches();

uint64_t lv1_peek(uint64_t addr);
void lv1_poke( uint64_t addr, uint64_t val);
void lv1_poke32(uint64_t addr, uint32_t value);

void hook_func(void * original,void * backup, void * hook_function);
void load_cfw_functions();

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
int set_qa_flag(uint8_t value);
void toggle_generic(char* path_to_file, char* name);
void toggle_auto_update();
void toggle_hen_repair();
void toggle_patch_libaudio();
void toggle_hen_dev_build();
void uninstall_hen();
int switch_hen_mode(int mode);// Used for switching from release to debug
void read_write_generic(const char* src, const char* dest);

void lv1_patches();
void restore_patches();

// Clear Web Cache Functions (History, Auth Cache, Cookie)
void toggle_clear_web_history();
void toggle_clear_web_auth_cache();
void toggle_clear_web_cookie();

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

static int (*cellCryptoPuSha1Hmac)(uint8_t *hmac_hash, uint8_t *data_in, int32_t data_length, uint8_t *key, int32_t key_length) = 0;

static int (*xBDVDGetInstance)();

static int (*vsh_2B58A92C)(void*);
static int (*vsh_E20104BE)();
static void *(*allocator_759E0635)(size_t);
static void (*allocator_77A602DD)(void *);
static void *(*allocator_6137D196)(size_t boundary, size_t size_arg);

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
