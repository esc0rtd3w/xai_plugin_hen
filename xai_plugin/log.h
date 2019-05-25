void load_log_functions();
char * getlogpath();
void setlogpath(char * path);

int sprintf_(char * str, const char * format, int v1, int v2);
void log(char * buffer);
void log(char * format, char * param1);
void log(char * format, const char * param1);
void log(char * format, const wchar_t * param1);
void log(char * format, char param1);
void log(char * format, int param1);
void log(char * format, float param1);
void log_key(char * keyname,void * key);
void log_data(const void * buffer, int bufsize);
void log(char * pluginname,char * view, const char * function);

void log_function(char * pluginname,char * view, const char * function, char * format, int param1);
void log_function(char * pluginname,char * view, const char * function, char * format, const char* param1);

void notify(char * param);
void notify(const char * format, int param1);

void dump_file(const char * path, void * buffer, int size);