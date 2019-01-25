#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <curl/curl.h>
#include <jsoncpp/json.h>

#include "ef-lib.h"

#define IP_URL "http://ef.excito.org/ip.json"
#define EF_URL "https://easyfind.excito.org/"
#if !defined EXCITO_CA
    #define EXCITO_CA "/usr/share/excito/excito-ca.crt"
#endif

using namespace std;

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
    data->payload = (char*)realloc(data->payload, data->size + realsize + 1);
    if (data->payload == NULL)
        return 0;
    memcpy(&(data->payload[data->size]), ptr, realsize);
    data->size += realsize;
    data->payload[data->size] = '\0';
    return realsize;
}

void ef_init() {
    ef_init(EXCITO_CA);
}

void ef_init(const char* ca_file) {
    curl_global_init(CURL_GLOBAL_SSL);
    curl = curl_easy_init();
    if ( ! curl ) {
        fprintf(stderr, "Unable to initiate libcurl !");
        exit(1);
    }
    curl_version_info_data* info = curl_version_info(CURLVERSION_NOW);
    char* ua = (char*)malloc(15 + strlen(info->version));
    sprintf(ua, "libcurl-agent/%s", info->version);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    if (strcmp(ca_file,"None") == 0) {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    } else {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file);
    }
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
    data.payload = (char*)malloc(1);
    data.size = 0;
    curl_easy_setopt(curl, CURLOPT_URL, IP_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&data);

    res = curl_easy_perform(curl);
    if ( res == CURLE_OK ) {
	Json::Value j_result;
	Json::Reader j_reader;
	bool ret = j_reader.parse(data.payload, j_result);
        free(data.payload);
	if ((ret) && j_result.isMember("ip_address"))
	{
                char *r_ip = NULL;
                strcpy(r_ip, j_result["ip_address"].asCString());
		return r_ip;
	}
    } else {
        free(data.payload);
    }
    return NULL;
}

struct curl_data_st* prep_query(const char* fqdn, const char* mac, const char* key) {
    struct curl_data_st* data = (curl_data_st*)malloc(sizeof(struct curl_data_st));
    curl_easy_setopt(curl, CURLOPT_URL, EF_URL);
    char* esc_key = curl_easy_escape(curl, key, 0);
    char* esc_mac = curl_easy_escape(curl, mac, 0);
    stringstream ssreq;
    ssreq << "mac0=" << esc_mac << "&key=" << esc_key;
    if (fqdn != NULL) {
        ssreq << "&newname=" << fqdn << "&oldname=";
    }
    std::string reqstr = ssreq.str();
    data->req = (char*)malloc(reqstr.length());
    strcpy(data->req,reqstr.c_str());
    curl_free(esc_key);
    curl_free(esc_mac);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data->req);
    data->payload = (char*)malloc(1);
    data->size = 0;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data);
    return data;
}

void parse_response(struct curl_data_st* data, struct ef_return* ret) {
    parse_response(data, ret, false);
}

void parse_response(struct curl_data_st* data, struct ef_return* ret, bool print_json) {
    const char* r_msg = NULL;
    const char* r_ip = NULL;
    const char* r_name = NULL;

    Json::Value j_result;
    Json::Reader j_reader;
    bool res = j_reader.parse(data->payload, j_result);
    if (!res)
    {
        ret->res = 1;
        strcpy(ret->err_msg, "json parser error");
        if (print_json)
        {
            std::cout << "{\"error\":true,\"msg\":\"invalid json data\"}\n";
        }
    }

    if (j_result.isMember("error"))
	ret->res = (j_result["error"].asString() == "true") ? 1 : 0;
    if (j_result.isMember("msg"))
        r_msg = j_result["msg"].asCString();
    if (j_result.isMember("record"))
    {
        if (j_result["record"].isMember("content"))
            r_ip = j_result["record"]["content"].asCString();
        if (j_result["record"].isMember("name"))
            r_name = j_result["record"]["name"].asCString();
    }

    if (print_json)
    {
        Json::FastWriter fastWriter;
        std::cout << fastWriter.write(j_result) << "\n";
    }

    if (r_msg != NULL) {
        ret->err_msg = (char*)malloc(strlen(r_msg)+1);
        strcpy(ret->err_msg, r_msg);
    }
    if (r_ip != NULL) {
        ret->ip = (char*)malloc(strlen(r_ip)+1);
        strcpy(ret->ip, r_ip);
    }
    if (r_name != NULL) {
        ret->name = (char*)malloc(strlen(r_name)+1);
        strcpy(ret->name, r_name);
    }
}

struct ef_return* ef_unregister(const char* mac, const char* key) {
    return ef_unregister(mac, key, false);
}

struct ef_return* ef_unregister(const char* mac, const char* key, bool print_json) {
    struct ef_return* ret = (ef_return*)malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;
    struct curl_data_st* data = prep_query("", mac, key);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        parse_response(data, ret, print_json);
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
    return ef_register_new(fqdn, mac, key, false);
}

struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key, bool print_json) {
    struct ef_return* ret = (ef_return*)malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;
    struct curl_data_st* data = prep_query(fqdn, mac, key);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        parse_response(data, ret, print_json);
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
    return ef_update(mac, key, false);
}

struct ef_return* ef_update(const char* mac, const char* key, bool print_json) {
    struct ef_return* ret = (ef_return*)malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;
    struct curl_data_st* data = prep_query(NULL, mac, key);
    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        parse_response(data, ret, print_json);
    } else {
        ret->res = 2;
        ret->curl_err_msg = curl_easy_strerror(res);
    }
    free(data->req);
    free(data->payload);
    free(data);
    return ret;
}
