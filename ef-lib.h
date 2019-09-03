void ef_init();
void ef_init(const char* ca_file);
void ef_cleanup();

struct ef_return {
    int res;
    char* err_msg;
    const char* curl_err_msg;
    char* ip;
    char* name;
};

struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key);
struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key, bool print_json);
struct ef_return* ef_unregister(const char* mac, const char* key);
struct ef_return* ef_unregister(const char* mac, const char* key, bool print_json);
struct ef_return* ef_update(const char* mac, const char* key);
struct ef_return* ef_update(const char* mac, const char* key, bool print_json);
char* get_ip();
