
void ef_init();
void ef_cleanup();

struct ef_return {
    int res;
    char* err_msg;
    const char* curl_err_msg;
    char* ip;
};

struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key);
struct ef_return* ef_unregister(const char* mac, const char* key);
