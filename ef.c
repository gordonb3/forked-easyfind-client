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

#define STATE_DIR "/var/lib/easyfind"
#define STATE_FILE "/var/lib/easyfind/state"
#define PID_DIR "/var/run/easyfind"
#define PID_FILE "/var/run/easyfind/efd.pid"
#define WAN_IF "eth0"
#define MAX_LINE_LEN 1024
#define DEFAULT_IP 127.0.0.1

#define WAN_MAC_FILE "/sys/class/net/" WAN_IF "/address"

#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define YEL  "\x1B[33m"
#define RESET "\033[0m"

char* key = NULL;
char* mac = NULL;
char* ip = NULL;
char* name = NULL;
char* last_name = NULL;
char* last_ip = NULL;

/* State file opening/creation attempt */
void check_state_perms() {
    if ( access(STATE_FILE, F_OK ) != -1 ) {
        if ( access(STATE_FILE, R_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State file '%s' is not readable: %s\n", STATE_FILE, strerror(errno));
            exit(1);
        } else if ( access(STATE_FILE, W_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET  ": State file '%s' is not writeable: %s\n", STATE_FILE, strerror(errno));
            exit(1);
        }
    } else {
        if ( access(STATE_DIR, F_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' does not exist (%s).\n", STATE_DIR, strerror(errno));
            exit(1);
        } else if ( access(STATE_DIR, R_OK | X_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not readable: %s\n", STATE_DIR, strerror(errno));
            exit(1);
        } else if ( access(STATE_DIR, W_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not writeable: %s\n", STATE_DIR, strerror(errno));
            exit(1);
        }
    }
}

/* Reads key value from boot command line */
void read_cmdline() {
    FILE* cmdline_f = fopen("/proc/cmdline", "r");
    if (cmdline_f == NULL) {
        fprintf(stderr, RED "ERROR" RESET ": Unable to open /proc/cmdline file !\n");
        exit(1);
    }
    char buf[MAX_LINE_LEN];
    char* res = fgets(buf, MAX_LINE_LEN, cmdline_f);
    fclose(cmdline_f);

    if (res == NULL) {
        fprintf(stderr, RED "ERROR" RESET ": Unable to read /proc/cmdline file !\n");
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
        fprintf(stderr, RED "ERROR" RESET ": Unable to read key from boot command line; are you running on a B2/B3 ?\n");
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
        printf("Reading state file ... ");
        fflush(stdout);
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
        fclose(st_file);
        if (last_name == NULL || last_ip == NULL) {
            if (last_name != NULL)
                free(last_name);
            if (last_ip != NULL)
                free(last_ip);
            printf(RED "KO" RESET "\n");
        } else {
            printf(GRN "OK" RESET "\n");
        }
    }
}

/* Write state file */
char* write_state() {
    FILE* st_file = fopen(STATE_FILE, "w");
    if (st_file == NULL) {
        return strerror(errno);
    } else {
        fprintf(st_file, "%s\n%s", last_name, last_ip);
        fclose(st_file);
        return NULL;
    }
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
        fprintf(stderr, RED "ERROR" RESET ": Unable to open WAN interface mac address file %s !\n", WAN_MAC_FILE);
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
    } else if ( access(PID_FILE, F_OK) != -1 ) {
        fprintf(stderr, "easyfind daemon is running; stop it before running the `ef` command\n");
        exit(1);
    } else if ( strcmp(argv[1], "-d") == 0 ) {
        printf("\nUnregistering easyfind ... ");
        fflush(stdout);
        struct ef_return* ret;
        ef_init();
        ret = ef_unregister(mac, key);
        if (ret->res != 0) {
            printf(RED "KO" RESET "\n");
            fprintf(stderr, RED "ERROR" RESET ": %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
        } else {
            printf(GRN "OK" RESET "\n");
            if (last_name != NULL) {
                printf("Removing state file ... ");
                if (unlink(STATE_FILE) == -1) {
                    printf(RED "KO" RESET "\n");   
                    fprintf(stderr, YEL "WARNING" RESET ": unable to remove state file (%s)\n",  strerror(errno));
                } else {
                    printf(GRN "OK" RESET "\n");
                }
            }
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
            fprintf(stderr, RED "ERROR" RESET ": Unable to compile fqdn regex: %s\n", pcreError);
            return 1;
        }
        int ovector[12];
        int res = pcre_exec(r, NULL, argv[1], strlen(argv[1]), 0, 0, ovector, 12);
        if (res < 0) {
            if (res == PCRE_ERROR_NOMATCH) {
                fprintf(stderr,  RED "ERROR" RESET ": The requested domain %s in invalid\n", argv[1]);
                return 1;
            } else {
                fprintf(stderr,  RED "ERROR" RESET ": There was an error while trying to check domain regex.\n");
                return 1;
            }
        }
        name = argv[1];
        if ( last_name == NULL || strcmp(last_name, name) != 0 ) {
            if (last_name == NULL)
                printf("Registering new record '%s'... ", name);
            else
                printf("Replacing record '%s' with '%s'... ", last_name, name);
            fflush(stdout);
            struct ef_return* ret;
            ef_init();
            ret = ef_register_new(name, mac, key);
            if (ret->res != 0) {
                printf(RED "KO" RESET "\n");
                fprintf(stderr, RED "ERROR" RESET ": %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            } else {
                printf(GRN "OK" RESET "\n");
                if (last_name != NULL)
                    free(last_name);
                if (last_ip != NULL)
                    free(last_ip);
                last_name = ret->name;
                last_ip = ret->ip;
                printf("Writing state file ... ");
                fflush(stdout);
                char* res_w = write_state();
                if (res_w != NULL) {
                    printf(RED "KO" RESET "\n");
                    fprintf(stderr, RED "ERROR" RESET ": unable to write state file (%s)\n", res_w);
                } else {
                    printf(GRN "OK" RESET "\n");
                    printf("\nAll done ; you may now enable the easyfind client daemon efd\nto periodically verify and update your easyfind name.\n\n");
                }
            }
            if (ret->res == 1)
                free(ret->err_msg);
            free(ret);
            ef_cleanup();
        } else {
            printf("This system has already registered record '%s';\nRun easyfind service to do update the record.\n", name);
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
