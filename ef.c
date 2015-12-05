#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>
#include <syslog.h>
#include <signal.h>

#include "ef-lib.h"

#define STATE_DIR "/var/lib/easyfind"
#define STATE_FILE "/var/lib/easyfind/state"
#define PID_FILE "/var/run/easyfind/efd.pid"
#define WAN_IF "eth0"
#define MAX_LINE_LEN 1024
#define UPDATE_INTERVAL 60
#define USER "excito"
#define GROUP "excito"

#define WAN_MAC_FILE "/sys/class/net/" WAN_IF "/address"

#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define YEL  "\x1B[33m"
#define RESET "\033[0m"

char* key = NULL;
char* mac = NULL;
char* last_name = NULL;
char* last_ip = NULL;

/* State file opening/creation attempt */
void check_state_perms() {
    const char* root_msg = "You should probably run as root (ef) or " USER " (efd)";
    if ( access(STATE_FILE, F_OK ) != -1 ) {
        if ( access(STATE_FILE, R_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State file '%s' is not readable: %s\n%s\n", STATE_FILE, strerror(errno), root_msg);
            exit(1);
        } else if ( access(STATE_FILE, W_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET  ": State file '%s' is not writeable: %s\n%s\n", STATE_FILE, strerror(errno), root_msg);
            exit(1);
        }
    } else {
        if ( access(STATE_DIR, F_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' does not exist (%s).\n", STATE_DIR, strerror(errno));
            exit(1);
        } else if ( access(STATE_DIR, R_OK | X_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not readable: %s\n%s\n", STATE_DIR, strerror(errno), root_msg);
            exit(1);
        } else if ( access(STATE_DIR, W_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not writeable: %s\n%s\n", STATE_DIR, strerror(errno), root_msg);
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

    res[strlen(res)-1] = '\0';
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
void read_state(int r) {
    FILE* st_file = fopen(STATE_FILE, "r");
    char* res;
    if (st_file != NULL) {
        if (r == 0)
            printf("\nReading state file ... ");
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
            if (r == 0)
                printf(RED "KO" RESET "\n");
        } else if ( r == 0 ) {
            printf(GRN "OK" RESET "\n");
        }
    } else if (r == 0) {
        printf("\n");
    }
}

int state_file_ok = 1;

/* Write state file */
char* write_state() {
    FILE* st_file = fopen(STATE_FILE, "w");
    if (st_file == NULL) {
        return strerror(errno);
    } else {
        fprintf(st_file, "%s\n%s\n", last_name, last_ip);
        fclose(st_file);
        if (state_file_ok == 1) {
            struct passwd *u_pwd = getpwnam(USER);
            if ( u_pwd == NULL ) {
                unlink(STATE_FILE);
                return "Unable to get " USER " passwd information";
            }
            struct stat st_info;
            stat(STATE_FILE, &st_info);
            int chg_u = ( u_pwd->pw_uid != st_info.st_uid ) ? u_pwd->pw_uid : -1;
            int chg_g = ( u_pwd->pw_gid != st_info.st_gid ) ? u_pwd->pw_gid : -1;
            if (chg_u != -1 || chg_g != -1) {
                int r = chown(STATE_FILE, chg_u, chg_g);
                if ( r == -1 ) {
                    unlink(STATE_FILE);
                    return strerror(errno);
                }
            }

            state_file_ok = 0;
        }
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
        read_state(0);
        printf("Unregistering easyfind ... ");
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
                    printf("\nEasyfind succesfully unconfigured.\n\n");
                }
            } else {
                printf("\nEasyfind succesfully unconfigured.\n\n");
            }
        }

        if (ret->err_msg != NULL) {
            free(ret->err_msg);
        }
        free(ret);
        ef_cleanup();
    } else {
        read_state(0);
        const char* fqdn_regex = "^([a-z0-9-]{1,63}\\.){2}[a-z]{2,63}$";
        regex_t regex;
        int r = regcomp(&regex, fqdn_regex, REG_EXTENDED | REG_ICASE | REG_NOSUB);
        if (r != 0) {
            size_t l = regerror(r, &regex, NULL, 0);
            char* r_err = malloc(l);
            regerror(r, &regex, r_err, l);
            fprintf(stderr, RED "ERROR" RESET ": Unable to compile fqdn regex: %s\n", r_err);
            free(r_err);
            regfree(&regex);
            return 1;
        }
        r = regexec(&regex, argv[1], 0, NULL, 0);
        regfree(&regex);
        if (r != 0) {
            if (r == REG_NOMATCH) {
                fprintf(stderr,  RED "ERROR" RESET ": The requested domain %s in not valid\n", argv[1]);
                return 1;
            } else {
                fprintf(stderr,  RED "ERROR" RESET ": There was an error while trying to check domain regex.\n");
                return 1;
            }
        }
        
        if ( last_name == NULL || strcmp(last_name, argv[1]) != 0 ) {
            if (last_name == NULL)
                printf("Registering new record '%s'... ", argv[1]);
            else
                printf("Replacing record '%s' with '%s'... ", last_name, argv[1]);
            fflush(stdout);
            struct ef_return* ret;
            ef_init();
            ret = ef_register_new(argv[1], mac, key);
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
                free(ret->name);
                free(ret->ip);
            }
            if (ret->res == 1)
                free(ret->err_msg);
            free(ret);
            ef_cleanup();
        } else {
            printf("\nThis system has already registered record '%s';\nRun easyfind service to do update the record.\n\n", argv[1]);
        }
    }

    return 0;
}

int running = 1;

void check_and_update() {
    char* ip = get_ip();
    if (ip == NULL) {
        syslog(LOG_ERR, "Unable to get external ip from easyfind !");
        return;
    } else if (strcmp(ip, last_ip) != 0) {
        syslog(LOG_INFO, "new IP detected (%s); updating easyfind...", ip);
        struct ef_return* ret = ef_update(mac, key);
        if (ret->res != 0) {
            syslog(LOG_ERR, "Error while trying to update easyfind: %s", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            running = 0;
        } else {
            if (strcmp(last_name, ret->name) != 0) {
                syslog(LOG_ERR, "Easyfind reported name '%s' whereas '%s' is configured ... cannot continue", ret->name, last_name);
                free(ret->name);
                free(ret->ip);
                running = 0;
            } else {
                free(last_name);
                free(last_ip);
                last_name = ret->name;
                last_ip = ret->ip;
                char* res_w = write_state();
                if (res_w != NULL) {
                    syslog(LOG_ERR, "Unable to update state file: %s", res_w);
                    running = 0;
                } else {
                    syslog(LOG_INFO, "Easyfind and state file successfully updated with new IP");
                }
            }
        }

        if (ret->res == 1)
            free(ret->err_msg);
        free(ret);
    }
    free(ip);
}

void handle_term(int signum) {
    syslog(LOG_INFO, "SIGTERM received, exiting daemon ...");
    running = 0;
}

/* Main daemonic function */
int efd(int argc, char** argv) {

    read_state(1);

    if (last_name == NULL || last_ip == NULL) {
        fprintf(stderr, "Unable to read data from state file ; Configure with `ef` before running this daemon.\n");
        exit(1);
    }

    state_file_ok = 0;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Unable to fork easyfind daemon: %s\n", strerror(errno));
        exit(1);
    } else if (pid > 0) {
        exit(0);
    }

    openlog("efd", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "Starting easyfind update daemon");

    pid_t sid = setsid();
    if (sid < 0) {
        syslog(LOG_ERR, "Unable to create a new session for the daemon process: %s", strerror(errno));
        closelog();
        exit(1);
    }

    if (chdir("/") < 0) {
        syslog(LOG_ERR, "Unable to change process directory: %s", strerror(errno));
        closelog();
        exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    umask(027);

    int pid_fd = open(PID_FILE, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (pid_fd == -1) {
        syslog(LOG_ERR, "Unable to create PID file: %s", strerror(errno));
        closelog();
        exit(1);
    }

    if (lockf(pid_fd, F_TLOCK, 0) == -1) {
        syslog(LOG_ERR, "Unable to lock PID file (%s); the daemon is likely already running ...", strerror(errno));
        closelog();
        exit(1);
    }

    char pid_s[10];
    sprintf(pid_s, "%d\n", getpid());
    write(pid_fd, pid_s, strlen(pid_s));
    signal(SIGCHLD,SIG_IGN);
    signal(SIGTSTP,SIG_IGN); 
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM,handle_term);
    
    ef_init();
    int r = 0;
    while(running) {
        check_and_update();
        r = UPDATE_INTERVAL;
        while(running && r > 0)
            r = sleep(r);
    }

    free(last_name);
    free(last_ip);
    ef_cleanup();
    unlink(PID_FILE);
    syslog(LOG_INFO, "Easyfind daemon stopped");
    closelog();
    return 0;
}

int main(int argc, char** argv) {
    check_state_perms();
    read_cmdline();
    read_mac();
    char* last_slash = strrchr(argv[0], (int)'/');
    const char* p_name = (last_slash == NULL) ? argv[0] : last_slash+1;
    if (strcmp(p_name, "efd") == 0) {
        return efd(argc, argv);
    } else {
        return ef(argc, argv);
    }
}
