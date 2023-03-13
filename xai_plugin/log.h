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
void log(const char * format, int param1, const char* param2);
void log(const char * format, int param1, const char* param2, const char* param3);
void log(char * format, float param1);
void log_key(char * keyname,void * key);
void log_data(const void * buffer, int bufsize);
void log(char * pluginname,char * view, const char * function);

void log_function(char * pluginname,char * view, const char * function, char * format, int param1);
void log_function(char * pluginname,char * view, const char * function, char * format, const char* param1);

void notify(char * param);
void notify(char * format, char * param1);
void notify(const char * format, int param1);
void notify(const char * format, int param1, int param2, int param3, int param4);
void notify(const char * format, char* param1, int param2);
void notify(const char * format, const char* param1, int param2);
void notify(const char * format, int param1, int param2, bool logging);
void notify(const char * format, int param1, int param2, int param3, int param4, bool logging);
void notify(const char * format, int param1, char * param2, int param3, int param4, bool logging);
void notify(const char * format, int param1, int param2, int param3, int param4, int param5, int param6, bool logging);

void dump_file(const char * path, void * buffer, int size);