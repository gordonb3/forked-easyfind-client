#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include "ef-lib.h"

#define IP_URL "http://ef.excito.org/ip.json"
#define EF_URL "https://easyfind.excito.org/"
#define EXCITO_CA "/usr/share/excito/excito-ca.crt"

const char* return_codes[] = {
    "DBCONNECT", "UPDATE", "SETNAME", NULL,
    "CHECKNAME", NULL, NULL, NULL, "DISABLE",
    NULL, "VALIDATE", "CHANGENAME", "GETRECORD"
};

CURL *curl;
CURLcode res;

/* holder for curl write */
struct curl_data_st {
    char *req;
    char *payload;
    size_t size;
};

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct curl_data_st *data = (struct curl_data_st*)userdata;
    data->payload = realloc(data->payload, data->size + realsize + 1);
    if (data->payload == NULL)
        return 0;
    memcpy(&(data->payload[data->size]), ptr, realsize);
    data->size += realsize;
    data->payload[data->size] = '\0';
    return realsize;
}

void ef_init() {
    curl_global_init(CURL_GLOBAL_SSL);
    curl = curl_easy_init();
    if ( ! curl ) {
        fprintf(stderr, "Unable to initiate libcurl !");
        exit(1);
    }
    curl_version_info_data* info = curl_version_info(CURLVERSION_NOW);
    char* ua = malloc(15 + strlen(info->version));
    sprintf(ua, "libcurl-agent/%s", info->version);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_CAINFO, EXCITO_CA);
    free(ua);
}

void ef_cleanup() {
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

char* error_desc(int err_code) {
    return NULL;
}

char* get_ip() {
    struct curl_data_st data;
    data.payload = malloc(1);
    data.size = 0;
    curl_easy_setopt(curl, CURLOPT_URL, IP_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

    res = curl_easy_perform(curl);
    if ( res == CURLE_OK ) {
        json_object* jip = json_tokener_parse(data.payload);
        free(data.payload);
        char *r_ip = NULL;
        json_object_object_foreach(jip, key, val) {
            if (strcmp(key, "ip_address") == 0) {
                const char* ip = json_object_get_string(val);
                r_ip = malloc(strlen(ip)+1);
                strcpy(r_ip, ip);
            }
        }
        json_object_put(jip);
        return r_ip;
    } else {
        free(data.payload);
        return NULL;
    }
}

struct curl_data_st* prep_query(const char* fqdn, const char* mac, const char* key) {
    struct curl_data_st* data = malloc(sizeof(struct curl_data_st));
    curl_easy_setopt(curl, CURLOPT_URL, EF_URL);
    char* esc_key = curl_easy_escape(curl, key, 0);
    char* esc_mac = curl_easy_escape(curl, mac, 0);
    if (fqdn != NULL) {
        data->req = malloc(29 + strlen(esc_key) + strlen(esc_mac) + strlen(fqdn));
        sprintf(data->req, "mac0=%s&key=%s&newname=%s&oldname=", esc_mac, esc_key, fqdn);
    } else {
        data->req = malloc(11 + strlen(esc_key) + strlen(esc_mac));
        sprintf(data->req, "mac0=%s&key=%s", esc_mac, esc_key);
    }
    curl_free(esc_key);
    curl_free(esc_mac);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data->req);
    data->payload = malloc(1);
    data->size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data);
    return data;
}

void parse_response(struct curl_data_st* data, struct ef_return* ret) {
    json_object* jun = json_tokener_parse(data->payload);
    const char* r_msg;
    const char* r_err;
    const char* r_ip;
    const char* r_name;

    json_object_object_foreach(jun, key, val) {
        if (strcmp(key, "error") == 0) {
            r_err = json_object_get_string(val);
        } else if (strcmp(key, "msg") == 0) {
            r_msg = json_object_get_string(val);
        } else if (strcmp(key, "record") == 0) {
            json_object_object_foreach(val, key2, val2) {
                if (strcmp(key2, "content") == 0)
                    r_ip = json_object_get_string(val2);
                else if (strcmp(key2, "name") == 0)
                    r_name = json_object_get_string(val2); 
            }
        }
    }
    if (strcmp(r_err, "true") == 0) {
        ret->res = 1;
        ret->err_msg = malloc(strlen(r_msg)+1);
        strcpy(ret->err_msg, r_msg);
    } else {
        ret->res = 0;
        ret->ip = malloc(strlen(r_ip)+1);
        strcpy(ret->ip, r_ip);
        ret->name = malloc(strlen(r_name)+1);
        strcpy(ret->name, r_name);
    }
    json_object_put(jun);
}

struct ef_return* ef_unregister(const char* mac, const char* key) {
    struct ef_return* ret = malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;
    struct curl_data_st* data = prep_query("", mac, key);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        parse_response(data, ret);
    } else {
        ret->res = 2;
        ret->curl_err_msg = curl_easy_strerror(res);
    }

    free(data->req);
    free(data->payload);
    free(data);
    return ret;
}

struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key) {
    struct ef_return* ret = malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;
    struct curl_data_st* data = prep_query(fqdn, mac, key);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        parse_response(data, ret);
    } else {
        ret->res = 2;
        ret->curl_err_msg = curl_easy_strerror(res);
    }
    free(data->req);
    free(data->payload);
    free(data);
    return ret;
}

struct ef_return* ef_update(const char* mac, const char* key) {
    struct ef_return* ret = malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;
    struct curl_data_st* data = prep_query(NULL, mac, key);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        parse_response(data, ret);
    } else {
        ret->res = 2;
        ret->curl_err_msg = curl_easy_strerror(res);
    }
    free(data->req);
    free(data->payload);
    free(data);
    return ret;
}
