#include <sys/integertypes.h>

void load_log_functions();
char * getlogpath();
void setlogpath(char * path);

int sprintf_(char *str, const char *format, int v1);
int sprintf_(char *str, const char *format, int v1, int v2);
int sprintf_(char *str, const char *format, int v1, int v2, int v3);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4);
int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5);
//int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8);
//int sprintf_(char *str, const char *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15, int v16);

/*int swprintf_(wchar_t *str, size_t size, const wchar_t *format);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8);
int swprintf_(wchar_t *str, size_t size, const wchar_t *format, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9);*/

void log(char * buffer);
void log(char * format, char * param1);
void log(char * format, const char * param1);
void log(char * format, const wchar_t * param1);
void log(char * format, char param1);
void log(char * format, int param1);
void log(const char * format, int param1, const char* param2);
void log(const char * format, int param1, const char* param2, const char* param3);
void log(char * format, float param1);
void log(char * pluginname,char * view, const char * function);

void log_key(char * keyname,void * key);
void log_data(const void * buffer, int bufsize);

void log_function(char * pluginname,char * view, const char * function, char * format, int param1);
void log_function(char * pluginname,char * view, const char * function, char * format, const char* param1);

void notify(char * param);
void notify(char * format, char * param1);
void notify(const char * format, int param1);
void notify(const char * format, int param1, int param2);
void notify(const char * format, int param1, int param2, int param3, int param4);
void notify(const char* format, const char* param1, uint64_t param2, uint32_t param3, uint32_t param4);
void notify(const char * format, char* param1, int param2);
void notify(const char * format, const char* param1, int param2);
//void notify(const char * format, int param1, int param2, int param3);
void notify(const char * format, int param1, int param2, bool logging);
void notify(const char * format, int param1, int param2, int param3, int param4, bool logging);
void notify(const char * format, int param1, char * param2, int param3, int param4, bool logging);
void notify(const char * format, int param1, int param2, int param3, int param4, int param5, int param6, bool logging);
void notify64(const char * format, uint64_t param1, uint64_t param2);
void notify64(const char * format, uint64_t param1, uint64_t param2, uint64_t param3);
void notify64(const char * format, char* param1, uint64_t param2, uint64_t param3);
void notify64(const char * format, char* param1, uint64_t param2, uint64_t param3, uint64_t param4);

void dump_file(const char * path, void * buffer, int size);