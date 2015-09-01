#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>
#include <pcre.h>

#include "ef-lib.h"

#define STATE_FILE "/var/lib/easyfind/state"
#define WAN_IF "eth0"
#define MAX_LINE_LEN 1024
#define DEFAULT_IP 127.0.0.1

#define WAN_MAC_FILE "/sys/class/net/" WAN_IF "/address"

char* key = NULL;
char* mac = NULL;
char* ip = NULL;
char* name = NULL;
char* last_name = NULL;
char* last_ip = NULL;

/* State file opening/creation attempt */
void check_state_perms() {
    int fd = open(STATE_FILE, O_CREAT | O_RDWR, 0644);
    if ( fd == -1 ) {
        fprintf(stderr, "Unable to create/read/write state file %s: %s\n", STATE_FILE, strerror(errno));
        exit(1);
    } else {
        close(fd);
    }
}

/* Reads key value from boot command line */
void read_cmdline() {
    FILE* cmdline_f = fopen("/proc/cmdline", "r");
    if (cmdline_f == NULL) {
        fprintf(stderr, "Unable to open /proc/cmdline file !\n");
        exit(1);
    }
    char buf[MAX_LINE_LEN];
    char* res = fgets(buf, MAX_LINE_LEN, cmdline_f);
    fclose(cmdline_f);

    if (res == NULL) {
        fprintf(stderr, "Unable to read /proc/cmdline file !\n");
        exit(1);
    }

    const char* delim = " ";
    char* token = strtok(res, delim);
    while (token != NULL) {
        if (strncmp(token, "key=", 4) == 0) {
            break;
        }
        token = strtok(NULL, delim);
    }

    if ( token == NULL ) {
        fprintf(stderr, "Unable to read key from boot command line; are you running on a B2/B3 ?\n");
        exit(1);
    }

    key = malloc(strlen(token)-3);
    strcpy(key, token+4);
    key[strlen(token)-4] = '\0';
}

/* Try to load last known state */
void read_state() {
    FILE* st_file = fopen(STATE_FILE, "r");
    char* res;
    if (st_file != NULL) {
        char buf[MAX_LINE_LEN];
        while (1) {
            res = fgets(buf, MAX_LINE_LEN, st_file);
            if (res == NULL) {
                break;
            }
            if ( last_name == NULL ) {
                int sz = strlen(buf);
                last_name = malloc(sz);
                strncpy(last_name, buf, sz-1);
                last_name[sz-1] = '\0';
            } else if ( last_ip == NULL ) {
                int sz = strlen(buf);
                last_ip = malloc(sz);
                strncpy(last_ip, buf, sz-1);
                last_ip[sz-1] = '\0';
            } else {
                break;
            }
        }
        if (last_name == NULL || last_ip == NULL) {
            if (last_name != NULL)
                free(last_name);
            if (last_ip != NULL)
                free(last_ip);
        }
        fclose(st_file);
    }
}

/* Write state file */
void write_state() {

}

/* Read MAC address from sysfs */
void read_mac() {
    FILE* ad_file = fopen(WAN_MAC_FILE, "r");
    if (ad_file != NULL) {
        mac = malloc(18);
        fscanf(ad_file, "%17s", mac);
        mac[17] = '\0';
        fclose(ad_file);
    } else {
        fprintf(stderr, "Unable to open WAN interface mac address file %s !\n", WAN_MAC_FILE);
        exit(1);
    }
}

void usage() {
    printf("usage: ef [-d|<name>.<domain>]\n");
}

/* Main non-daemonic function */
int ef(int argc, char** argv) {

    if (argc != 2) {
        usage();
        exit(0);
    } else if ( strcmp(argv[1], "-d") == 0 ) {
        printf("Unregistering easyfind ... ");
        fflush(stdout);
        struct ef_return* ret;
        ef_init();
        ret = ef_unregister(mac, key);
        if (ret->res != 0) {
            printf("KO\n");
            fprintf(stderr, "ERROR: %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
        } else {
            printf("OK\n");
            // TODO remove state file
        }

        if (ret->res == 1) {
            free(ret->err_msg);
        }
        free(ret);
        ef_cleanup();
    } else {
        const char* pcreError;
        int pcreErrorOffset;
        const char* fqdn_regex = "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.){2}[a-zA-Z]{2,63}$)";
        pcre* r = pcre_compile(fqdn_regex, 0, &pcreError, &pcreErrorOffset, NULL);
        if (r == NULL) {
            fprintf(stderr, "Unable to compile fqdn regex: %s\n", pcreError);
            return 1;
        }
        int ovector[12];
        int res = pcre_exec(r, NULL, argv[1], strlen(argv[1]), 0, 0, ovector, 12);
        if (res < 0) {
            if (res == PCRE_ERROR_NOMATCH) {
                fprintf(stderr, "The requested domain %s in invalid\n", argv[1]);
                return 1;
            } else {
                fprintf(stderr, "There was an error while trying to check domain regex.\n");
                return 1;
            }
        }
        name = argv[1];
        if ( last_name == NULL ) {
            printf("Registering new record '%s'... ", name);
            fflush(stdout);
            struct ef_return* ret;
            ef_init();
            ret = ef_register_new(name, mac, key);
            if (ret->res != 0) {
                printf("KO\n");
                fprintf(stderr, "ERROR: %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            } else {
                printf("OK (IP:%s)\n", ret->ip);
                printf("Setting up state file ... ");
                fflush(stdout);
                // TODO create/update state file

                free(ret->ip);
            }
            if (ret->res == 1)
                free(ret->err_msg);
            free(ret);
            ef_cleanup();
        } else if (strcmp(last_name, name) != 0 ) {
            printf("Replacing record '%s' with '%s'...\n", last_name, name);
            ef_init();
            ef_cleanup();
        } else {
            printf("This system has already registered record '%s'; Run easyfind service to do update the record\n", name);
        }
    }

    return 0;
}

/* Main daemonic function */
int efd(int argc, char** argv) {
    printf("efd\n");
    return 0;
}

int main(int argc, char** argv) {
    check_state_perms();
    read_cmdline();
    read_mac();
    read_state();
    char* last_slash = strrchr(argv[0], (int)'/');
    const char* p_name = (last_slash == NULL) ? argv[0] : last_slash+1;
    if (strcmp(p_name, "efd") == 0) {
        return efd(argc, argv);
    } else {
        return ef(argc, argv);
    }
}
