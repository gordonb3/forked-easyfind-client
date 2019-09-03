#include <vector>
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

CURL *curl;
CURLcode res;

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    std::vector<unsigned char>* vHTTPResponse = (std::vector<unsigned char>*)userdata;
    vHTTPResponse->insert(vHTTPResponse->end(), (unsigned char*)ptr, (unsigned char*)ptr + realsize);
    return realsize;
}

void ef_init()
{
    ef_init(EXCITO_CA);
}

void ef_init(const char* ca_file)
{
    curl_global_init(CURL_GLOBAL_SSL);
    curl = curl_easy_init();
    if (!curl)
    {
        fprintf(stderr, "Unable to initiate libcurl !");
        exit(1);
    }
    curl_version_info_data* info = curl_version_info(CURLVERSION_NOW);
    char* ua = (char*)malloc(15 + strlen(info->version));
    sprintf(ua, "libcurl-agent/%s", info->version);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, ua);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    if (strcmp(ca_file,"None") == 0)
    {
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    }
    else
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file);
    free(ua);
}

void ef_cleanup()
{
    curl_easy_cleanup(curl);
    curl_global_cleanup();
}

char* error_desc(int err_code)
{
    return NULL;
}

char* get_ip()
{
    std::vector<unsigned char> v_response;
    curl_easy_setopt(curl, CURLOPT_URL, IP_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&v_response);

    res = curl_easy_perform(curl);
    if ( res == CURLE_OK )
    {
        std::string sz_response;
        sz_response.insert(sz_response.begin(), v_response.begin(), v_response.end());
        Json::Value j_result;
        Json::Reader j_reader;
        bool ret = j_reader.parse(sz_response.c_str(), j_result);
        if ((ret) && j_result.isMember("ip_address"))
            return (char*)j_result["ip_address"].asCString();
    }
    return NULL;
}

std::string prep_postdata(const char* fqdn, const char* mac, const char* key)
{
    curl_easy_setopt(curl, CURLOPT_URL, EF_URL);
    char* esc_key = curl_easy_escape(curl, key, 0);
    char* esc_mac = curl_easy_escape(curl, mac, 0);
    std::stringstream ssreq;
    ssreq << "mac0=" << esc_mac << "&key=" << esc_key;
    if (fqdn != NULL)
        ssreq << "&newname=" << fqdn << "&oldname=";
    curl_free(esc_key);
    curl_free(esc_mac);
    return ssreq.str();
}


/*
void parse_response(std::vector<unsigned char> &v_response, struct ef_return* ret) {
    parse_response(v_response, ret, false);
}
*/

void parse_response(std::vector<unsigned char> &v_response, struct ef_return* ret, bool print_json=false) {
    const char* r_msg = NULL;
    const char* r_ip = NULL;
    const char* r_name = NULL;

    std::string sz_response;
    sz_response.insert(sz_response.begin(), v_response.begin(), v_response.end());
    Json::Value j_result;
    Json::Reader j_reader;
    bool res = j_reader.parse(sz_response.c_str(), j_result);
    if (!res)
    {
        ret->res = 1;
        strcpy(ret->err_msg, "json parser error");
        if (print_json)
            std::cout << "{\"error\":true,\"msg\":\"invalid json data\"}\n";
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

    if (r_msg != NULL)
    {
        ret->err_msg = (char*)malloc(strlen(r_msg)+1);
        strcpy(ret->err_msg, r_msg);
    }
    if (r_ip != NULL)
    {
        ret->ip = (char*)malloc(strlen(r_ip)+1);
        strcpy(ret->ip, r_ip);
    }
    if (r_name != NULL)
    {
        ret->name = (char*)malloc(strlen(r_name)+1);
        strcpy(ret->name, r_name);
    }
}


struct ef_return* ef_runquery(const std::string &postdata, const bool print_json)
{
    struct ef_return* ret = (ef_return*)malloc(sizeof(struct ef_return));
    ret->ip = NULL;
    ret->name = NULL;

    std::vector<unsigned char> v_response;
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&v_response);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str());

    res = curl_easy_perform(curl);
    if (res == CURLE_OK)
        parse_response(v_response, ret, print_json);
    else
    {
        ret->res = 2;
        ret->curl_err_msg = curl_easy_strerror(res);
    }
    return ret;
}


struct ef_return* ef_unregister(const char* mac, const char* key)
{
    return ef_unregister(mac, key, false);
}

struct ef_return* ef_unregister(const char* mac, const char* key, bool print_json)
{
    std::string postdata = prep_postdata("", mac, key);
    return ef_runquery(postdata, print_json);
}


struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key)
{
    return ef_register_new(fqdn, mac, key, false);
}

struct ef_return* ef_register_new(const char* fqdn, const char* mac, const char* key, bool print_json)
{
    std::string postdata = prep_postdata(fqdn, mac, key);
    return ef_runquery(postdata, print_json);
}


struct ef_return* ef_update(const char* mac, const char* key)
{
    return ef_update(mac, key, false);
}

struct ef_return* ef_update(const char* mac, const char* key, bool print_json)
{
    std::string postdata = prep_postdata(NULL, mac, key);
    return ef_runquery(postdata, print_json);
}
