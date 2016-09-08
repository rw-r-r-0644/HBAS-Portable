#include <gctypes.h>
#include "elf_abi.h"
#include "../../src/common/common.h"
#include "../../src/common/os_defs.h"

#define CODE_RW_BASE_OFFSET                             0
#define DATA_RW_BASE_OFFSET                             0

#define EXPORT_DECL(res, func, ...)                     res (* func)(__VA_ARGS__);

#define OS_FIND_EXPORT(handle, funcName, func)                    OSDynLoad_FindExport(handle, 0, funcName, &func)

typedef struct _private_data_t
{
    unsigned char *dlf;
    unsigned int len;

    EXPORT_DECL(void *, MEMAllocFromDefaultHeapEx,int size, int align);
    EXPORT_DECL(void *, MEMAllocFromDefaultHeap,int size);
    EXPORT_DECL(void, MEMFreeToDefaultHeap,void *ptr);

    EXPORT_DECL(void*, memcpy, void *p1, const void *p2, unsigned int s);
    EXPORT_DECL(void*, memset, void *p1, int val, unsigned int s);
    EXPORT_DECL(void, OSFatal, const char* msg);
    EXPORT_DECL(void, DCFlushRange, const void *addr, u32 length);
    EXPORT_DECL(void, ICInvalidateRange, const void *addr, u32 length);
    EXPORT_DECL(int, __os_snprintf, char* s, int n, const char * format, ...);
    EXPORT_DECL(void, exit, void);

	EXPORT_DECL(int, ACInitialize, void);
	EXPORT_DECL(int, ACGetStartupId, uint32_t *id);
	EXPORT_DECL(int, ACConnectWithConfigId, uint32_t id);
	EXPORT_DECL(int, socket_lib_init, void);
	EXPORT_DECL(int, curl_global_init, int opts);
	EXPORT_DECL(void*, curl_easy_init, void);
	EXPORT_DECL(void, curl_easy_cleanup, void *handle);
	EXPORT_DECL(void, curl_easy_setopt, void *handle, uint32_t param, void *op);
	EXPORT_DECL(int, curl_easy_perform, void *handle);
	EXPORT_DECL(void, curl_easy_getinfo, void *handle, uint32_t param, void *info);
	
    EXPORT_DECL(int, SYSRelaunchTitle, int argc, char* argv);
} private_data_t;

typedef struct _cfile
{
	unsigned char dlf[0x801304]; //Max file size
	unsigned int len;
} cfile;

static int curl_write_data_callback(void *ptr, uint32_t size, uint32_t nmemb, private_data_t *private_data)
{
  uint32_t new_len = private_data->len + size*nmemb;
  
  //"reallaoc" (sort of)
  unsigned char *d_tmp;
  d_tmp=(unsigned char*)private_data->MEMAllocFromDefaultHeap(private_data->len+1);
  private_data->memcpy(d_tmp,private_data->dlf,private_data->len+1);
  private_data->MEMFreeToDefaultHeap(private_data->dlf);
  private_data->dlf=(unsigned char *)private_data->MEMAllocFromDefaultHeap(new_len+1);
  private_data->memcpy(private_data->dlf,d_tmp,private_data->len+1);
  private_data->MEMFreeToDefaultHeap(d_tmp);

  private_data->memcpy(private_data->dlf+private_data->len, ptr, size*nmemb);
  private_data->dlf[new_len] = '\0';
  private_data->len = new_len;
  return size*nmemb;
}

static int LoadFileToMem(private_data_t *private_data, unsigned char **fileOut, unsigned int *sizeOut)
{
	private_data->len=0;
	private_data->dlf=(unsigned char *)private_data->MEMAllocFromDefaultHeap(private_data->len+1);
	private_data->dlf[0] = '\0';
	uint32_t nn_startupid;
	private_data->ACInitialize();
	private_data->ACGetStartupId(&nn_startupid);
	private_data->ACConnectWithConfigId(nn_startupid);
	private_data->socket_lib_init();
	private_data->curl_global_init(((1<<0)|(1<<1))); 
	
	void *curl_handle = private_data->curl_easy_init();
	if(!curl_handle) private_data->OSFatal("cURL not initialized");
	
	private_data->curl_easy_setopt(curl_handle, 10002, "http://www.wiiubru.com/appstore/apps/appstore/hbas.elf");
	private_data->curl_easy_setopt(curl_handle, 20011, curl_write_data_callback);
	private_data->curl_easy_setopt(curl_handle, 10001, private_data);

	int ret = private_data->curl_easy_perform(curl_handle); //Actually download the file
	if(ret) private_data->OSFatal("curl_easy_perform returned an error");

	int resp = 404;
	private_data->curl_easy_getinfo(curl_handle, 0x200002, &resp);
	if(resp != 200) private_data->OSFatal("curl_easy_getinfo returned an HTTP error");
	private_data->curl_easy_cleanup(curl_handle);
	
	*fileOut = private_data->dlf;
	*sizeOut = private_data->len;
	return 1;
}

static unsigned int load_elf_image (private_data_t *private_data, unsigned char *elfstart)
{
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdrs;
	unsigned char *image;
	int i;

	ehdr = (Elf32_Ehdr *) elfstart;

	if(ehdr->e_phoff == 0 || ehdr->e_phnum == 0)
		return 0;

	if(ehdr->e_phentsize != sizeof(Elf32_Phdr))
		return 0;

	phdrs = (Elf32_Phdr*)(elfstart + ehdr->e_phoff);

	for(i = 0; i < ehdr->e_phnum; i++)
    {
		if(phdrs[i].p_type != PT_LOAD)
			continue;

		if(phdrs[i].p_filesz > phdrs[i].p_memsz)
			return 0;

		if(!phdrs[i].p_filesz)
			continue;

        unsigned int p_paddr = phdrs[i].p_paddr;

        // use correct offset address for executables and data access
		if(phdrs[i].p_flags & PF_X)
			p_paddr += CODE_RW_BASE_OFFSET;
        else
			p_paddr += DATA_RW_BASE_OFFSET;

		image = (unsigned char *) (elfstart + phdrs[i].p_offset);
		private_data->memcpy ((void *) p_paddr, image, phdrs[i].p_filesz);
        private_data->DCFlushRange((void*)p_paddr, phdrs[i].p_filesz);

		if(phdrs[i].p_flags & PF_X)
			private_data->ICInvalidateRange ((void *) phdrs[i].p_paddr, phdrs[i].p_memsz);
	}

    //! clear BSS
    Elf32_Shdr *shdr = (Elf32_Shdr *) (elfstart + ehdr->e_shoff);
    for(i = 0; i < ehdr->e_shnum; i++)
    {
        const char *section_name = ((const char*)elfstart) + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name;
        if(section_name[0] == '.' && section_name[1] == 'b' && section_name[2] == 's' && section_name[3] == 's')
        {
            private_data->memset((void*)shdr[i].sh_addr, 0, shdr[i].sh_size);
            private_data->DCFlushRange((void*)shdr[i].sh_addr, shdr[i].sh_size);
        }
        else if(section_name[0] == '.' && section_name[1] == 's' && section_name[2] == 'b' && section_name[3] == 's' && section_name[4] == 's')
        {
            private_data->memset((void*)shdr[i].sh_addr, 0, shdr[i].sh_size);
            private_data->DCFlushRange((void*)shdr[i].sh_addr, shdr[i].sh_size);
        }
    }

	return ehdr->e_entry;
}

static void loadFunctionPointers(private_data_t * private_data)
{
    unsigned int coreinit_handle,sysapp_handle,nn_ac_handle, nsysnet_handle, libcurl_handle;

    EXPORT_DECL(int, OSDynLoad_Acquire, const char* rpl, u32 *handle);
    EXPORT_DECL(int, OSDynLoad_FindExport, u32 handle, int isdata, const char *symbol, void *address);

    OSDynLoad_Acquire = (int (*)(const char*, u32 *))OS_SPECIFICS->addr_OSDynLoad_Acquire;
    OSDynLoad_FindExport = (int (*)(u32, int, const char *, void *))OS_SPECIFICS->addr_OSDynLoad_FindExport;

    OSDynLoad_Acquire("coreinit.rpl", &coreinit_handle);
	OSDynLoad_Acquire("sysapp.rpl", &sysapp_handle);
	OSDynLoad_Acquire("nn_ac.rpl", &nn_ac_handle);
	OSDynLoad_Acquire("nsysnet.rpl", &nsysnet_handle);
	OSDynLoad_Acquire("nlibcurl.rpl", &libcurl_handle);

    unsigned int *functionPtr = 0;

    OSDynLoad_FindExport(coreinit_handle, 1, "MEMAllocFromDefaultHeapEx", &functionPtr);
    private_data->MEMAllocFromDefaultHeapEx = (void * (*)(int, int))*functionPtr;
    OSDynLoad_FindExport(coreinit_handle, 1, "MEMAllocFromDefaultHeap", &functionPtr);
    private_data->MEMAllocFromDefaultHeap = (void * (*)(int))*functionPtr;
    OSDynLoad_FindExport(coreinit_handle, 1, "MEMFreeToDefaultHeap", &functionPtr);
    private_data->MEMFreeToDefaultHeap = (void (*)(void *))*functionPtr;

    OS_FIND_EXPORT(coreinit_handle, "memcpy", private_data->memcpy);
    OS_FIND_EXPORT(coreinit_handle, "memset", private_data->memset);
    OS_FIND_EXPORT(coreinit_handle, "OSFatal", private_data->OSFatal);
    OS_FIND_EXPORT(coreinit_handle, "DCFlushRange", private_data->DCFlushRange);
    OS_FIND_EXPORT(coreinit_handle, "ICInvalidateRange", private_data->ICInvalidateRange);
    OS_FIND_EXPORT(coreinit_handle, "__os_snprintf", private_data->__os_snprintf);
    OS_FIND_EXPORT(coreinit_handle, "exit", private_data->exit);

    OS_FIND_EXPORT(nn_ac_handle, "ACInitialize", private_data->ACInitialize);
	OS_FIND_EXPORT(nn_ac_handle, "ACGetStartupId", private_data->ACGetStartupId);
	OS_FIND_EXPORT(nn_ac_handle, "ACConnectWithConfigId", private_data->ACConnectWithConfigId);
	
	OS_FIND_EXPORT(nsysnet_handle, "socket_lib_init", private_data->socket_lib_init);

	OS_FIND_EXPORT(libcurl_handle, "curl_global_init", private_data->curl_global_init);
	OS_FIND_EXPORT(libcurl_handle, "curl_easy_init", private_data->curl_easy_init);
	OS_FIND_EXPORT(libcurl_handle, "curl_easy_cleanup", private_data->curl_easy_cleanup);
    OS_FIND_EXPORT(libcurl_handle, "curl_easy_setopt", private_data->curl_easy_setopt);
	OS_FIND_EXPORT(libcurl_handle, "curl_easy_perform", private_data->curl_easy_perform);
	OS_FIND_EXPORT(libcurl_handle, "curl_easy_getinfo", private_data->curl_easy_getinfo);
	
	
    OS_FIND_EXPORT(sysapp_handle, "SYSRelaunchTitle", private_data->SYSRelaunchTitle);
}

int _start(int argc, char **argv)
{
    {
        private_data_t private_data;
        loadFunctionPointers(&private_data);

        while(1)
        {
            if(ELF_DATA_ADDR != 0xDEADC0DE && ELF_DATA_SIZE > 0)
            {
                //! copy data to safe area before processing it
                unsigned char * pElfBuffer = (unsigned char *)private_data.MEMAllocFromDefaultHeapEx(ELF_DATA_SIZE, 4);
                if(pElfBuffer)
                {
                    private_data.memcpy(pElfBuffer, (unsigned char*)ELF_DATA_ADDR, ELF_DATA_SIZE);
                    MAIN_ENTRY_ADDR = load_elf_image(&private_data, pElfBuffer);
                    private_data.MEMFreeToDefaultHeap(pElfBuffer);
                }
                ELF_DATA_ADDR = 0xDEADC0DE;
                ELF_DATA_SIZE = 0;
            }

            if(MAIN_ENTRY_ADDR == 0xDEADC0DE || MAIN_ENTRY_ADDR == 0)
            {
                unsigned char *pElfBuffer = NULL;
                unsigned int uiElfSize = 0;

                LoadFileToMem(&private_data, &pElfBuffer, &uiElfSize);

                if(!pElfBuffer)
                {
                    private_data.OSFatal("Could not load hbas.elf");
                }
                else
                {
                    MAIN_ENTRY_ADDR = load_elf_image(&private_data, pElfBuffer);
                    private_data.MEMFreeToDefaultHeap(pElfBuffer);

                    if(MAIN_ENTRY_ADDR == 0)
                    {
                        private_data.OSFatal("Failed to load ELF");
                    }
                }
            }
            else
            {
                int returnVal = ((int (*)(int, char **))MAIN_ENTRY_ADDR)(argc, argv);

                //! exit to miimaker and restart application on re-enter of another application
                if(returnVal == (int)EXIT_RELAUNCH_ON_LOAD)
                {
                    break;
                }
                //! exit to homebrew launcher in all other cases
                else
                {
                    //MAIN_ENTRY_ADDR = 0xDEADC0DE;
                    //private_data.SYSRelaunchTitle(0, 0);
                    //private_data.exit();
                    break;
                }
            }
        }
    }

    return ( (int (*)(int, char **))(*(unsigned int*)OS_SPECIFICS->addr_OSTitle_main_entry) )(argc, argv);
}
