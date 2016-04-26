#include <iostream>
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

#include "ef.h"
#include "ef-lib.h"

#if !defined STATE_DIR
    #define STATE_DIR "/var/lib/easyfind"
#endif
#if !defined STATE_FILE
    #define STATE_FILE STATE_DIR "/easyfind.conf"
#endif
#if !defined PID_FILE
    #define PID_FILE "/var/run/easyfind/efd.pid"
#endif
#define WAN_IF "eth0"
#define MAX_LINE_LEN 1024
#define UPDATE_INTERVAL 60
#if defined (NOPRIV) && !defined (USER)
    #define USER "easyfind"
#endif
#if defined (USER) && !defined (GROUP)
    #define GROUP USER
#endif

#define WAN_MAC_FILE "/sys/class/net/" WAN_IF "/address"

#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define YEL  "\x1B[33m"
#define RESET "\033[0m"

using namespace std;

char* key = NULL;
char* mac = NULL;
char* last_name = NULL;
char* last_ip = NULL;
char enabled[4] = "no";
command_array cmd_array;


/* State file opening/creation attempt */
void check_state_perms() {
#if defined (USER)
    const char* root_msg = "You should probably run as root (ef) or " USER " (efd)";
#else
    const char* root_msg = "You should probably run as root";
#endif
    if ( access(cmd_array.st_file.c_str(), F_OK ) != -1 ) {
        if ( access(cmd_array.st_file.c_str(), R_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State file '%s' is not readable: %s\n%s\n", cmd_array.st_file.c_str(), strerror(errno), root_msg);
            exit(1);
        } else if ( access(cmd_array.st_file.c_str(), W_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State file '%s' is not writeable: %s\n%s\n", cmd_array.st_file.c_str(), strerror(errno), root_msg);
            exit(1);
        }
    } else {
        if ( access(cmd_array.st_dir.c_str(), F_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' does not exist (%s).\n", cmd_array.st_dir.c_str(), strerror(errno));
            exit(1);
        } else if ( access(cmd_array.st_dir.c_str(), R_OK | X_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not readable: %s\n%s\n", cmd_array.st_dir.c_str(), strerror(errno), root_msg);
            exit(1);
        } else if ( access(cmd_array.st_dir.c_str(), W_OK) == -1 ) {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not writeable: %s\n%s\n", cmd_array.st_dir.c_str(), strerror(errno), root_msg);
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

    if ( token != NULL ) {
        key = (char*)malloc(strlen(token)-3);
        strcpy(key, token+4);
        key[strlen(token)-4] = '\0';
    }
}

/* Reads key value from u-boot environment in flash */
void read_flash() {

#if defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
    // Bubba|2
    char env[8192];
    int fd = open("/dev/mtd0", O_RDONLY);
    if (fd == -1)
        return;
    lseek(fd, 0x50000, SEEK_SET);
    read(fd, env, 8192);
    if ( env[4] == 0x0 ) {
        lseek(fd, 0x60000, SEEK_SET);
        read(fd, env, 8192);
    }
    char *pos = &env[5];
#else
    // B3
    char env[65536];
    int fd = open("/dev/mtd1", O_RDONLY);
    if ( fd == -1 )
        return;
    read(fd, env, 65536);
    char *pos = &env[4];
#endif
    close(fd);

    int l = strlen(pos);
    while ( l > 0 ) {
        if ( strncmp(pos, "key=", 4) == 0) {
            key = (char*)malloc(l - 3);
            strcpy(key, pos + 4);
            break;
        }
        pos += l+1;
        l = strlen(pos);
    }
}

/* Try to load last known state */
void read_state(int r) {
    FILE* st_file = fopen(cmd_array.st_file.c_str(), "r");
    if (st_file != NULL) {
        if (r == 0)
            printf("\nReading state file ... ");
        fflush(stdout);
        char* line = NULL;
        size_t bufsize=MAX_LINE_LEN;
        ssize_t len;
        while ((len = getline(&line, &bufsize, st_file)) != -1){
            ssize_t c;
            for (c=0;c<len;c++) {
                if (line[c] == '#' || line[c] == ';' || line[c] == '\r' || line[c] == '\n'){
                    len = c;
                    break;
                } else if (line[c] > 0x40){
                    line[c] = (line[c] | 0x60);
                }
            }
            char strtokbuf[MAX_LINE_LEN];
            strncpy(strtokbuf,line,len);
            strtokbuf[len]=' ';
            strtokbuf[len+1]='Z';
            if (len > 0){
                char* varname = strtok(strtokbuf," \t=\r\n");
                char* value = strtok(NULL," \t=\r\n");
                int sz = strlen(value);
                if (sz > 0 && value[0] != 'Z') {
                    if (strcmp(varname,"name") == 0){
                        last_name = (char*)malloc(sz+1);
                        strncpy(last_name,value, sz);
                        last_name[sz] = '\0';
                    }
                    else if (strcmp(varname,"ip") == 0){
                        last_ip = (char*)malloc(sz+1);
                        strncpy(last_ip,value, sz);
                        last_ip[sz] = '\0';
                    }
                    else if (strcmp(varname,"enable") == 0){
                            if (sz < 4)
                            strcpy(enabled,value);
                        else
                            strcpy(enabled,"no");
                    }
                }
            }
        }
        fclose(st_file);
        if (line != NULL)
            free(line);
        if (last_name == NULL || last_ip == NULL || strcmp(enabled,"yes")!=0) {
            if (last_name != NULL)
                free(last_name);
            if (last_ip != NULL)
                free(last_ip);
            last_name = NULL;
            last_ip = NULL;
            if (r == 0)
                printf(RED "KO" RESET "\n");
        } else if ( r == 0 ) {
            printf(GRN "OK" RESET "\n");
        }
    } else if (r == 0) {
        printf("\n");
    }
}

#if defined (USER)
int state_file_ok = 1;
#endif

/* Write state file */
char* write_state() {
    FILE* st_file = fopen(cmd_array.st_file.c_str(), "w");
    if (st_file == NULL) {
        return strerror(errno);
    } else {
        fprintf(st_file, "enable = %s\nip = %s\nname = %s\n", enabled, last_ip, last_name);
        fclose(st_file);
#if defined (USER)
        if (state_file_ok == 1) {
            struct passwd *u_pwd = getpwnam(USER);
            if ( u_pwd == NULL ) {
                unlink(cmd_array.st_file);
                return "Unable to get " USER " passwd information";
            }
            struct stat st_info;
            stat(cmd_array.st_file, &st_info);
            int chg_u = ( u_pwd->pw_uid != st_info.st_uid ) ? u_pwd->pw_uid : -1;
            int chg_g = ( u_pwd->pw_gid != st_info.st_gid ) ? u_pwd->pw_gid : -1;
            if (chg_u != -1 || chg_g != -1) {
                int r = chown(cmd_array.st_file, chg_u, chg_g);
                if ( r == -1 ) {
                    unlink(cmd_array.st_file.c_str());
                    return strerror(errno);
                }
            }

            state_file_ok = 0;
        }
#endif
        return NULL;
    }
}

/* Read MAC address from sysfs */
void read_mac() {
    FILE* ad_file = fopen(WAN_MAC_FILE, "r");
    if (ad_file != NULL) {
        mac = (char*)malloc(18);
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

/* Test domain name for FQDN compliancy */
int fqdn_test(const char *domain) {
    const char* fqdn_regex = "^([a-z0-9-]{1,63}\\.){2}[a-z]{2,63}$";
    regex_t regex;
    int r = regcomp(&regex, fqdn_regex, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    if (r != 0) {
        size_t l = regerror(r, &regex, NULL, 0);
        char* r_err = (char*)malloc(l);
        regerror(r, &regex, r_err, l);
        fprintf(stderr, RED "ERROR" RESET ": Unable to compile fqdn regex: %s\n", r_err);
        free(r_err);
        regfree(&regex);
        exit(1);
    }
    r = regexec(&regex, domain, 0, NULL, 0);
    regfree(&regex);
    return r;
}

/* Main non-daemonic function */
int ef(int argc, char** argv) {
    if ( access(PID_FILE, F_OK) != -1 ) {
        fprintf(stderr, "easyfind daemon is running; stop it before running the `ef` command\n");
        exit(1);
    } else if ( cmd_array.action == "disable" ) {
        read_state(0);
        printf("Unregistering easyfind ... ");
        fflush(stdout);
        struct ef_return* ret;
        if (cmd_array.ca_file.empty())
            ef_init();
        else
            ef_init(cmd_array.ca_file.c_str());
        ret = ef_unregister(mac, key);
        if (ret->res != 0) {
            printf(RED "KO" RESET "\n");
            fprintf(stderr, RED "ERROR" RESET ": %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
        } else {
            printf(GRN "OK" RESET "\n");
            if (last_name != NULL) {
                printf("Removing state file ... ");
                if (unlink(cmd_array.st_file.c_str()) == -1) {
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
    } else if (cmd_array.action == "setname") {
        read_state(0);
        int r = fqdn_test(cmd_array.ef_name.c_str());
        if (r != 0) {
            if (r == REG_NOMATCH) {
                fprintf(stderr,  RED "ERROR" RESET ": The requested domain %s is not valid\n", cmd_array.ef_name.c_str());
                return 1;
            } else {
                fprintf(stderr,  RED "ERROR" RESET ": There was an error while trying to check domain regex.\n");
                return 1;
            }
        }
        
        if ( last_name == NULL || strcmp(last_name, cmd_array.ef_name.c_str()) != 0 ) {
            if (last_name == NULL)
                printf("Registering new record '%s'... ", cmd_array.ef_name.c_str());
            else
                printf("Replacing record '%s' with '%s'... ", last_name, cmd_array.ef_name.c_str());
            fflush(stdout);
            struct ef_return* ret;
            ef_init();
            ret = ef_register_new(cmd_array.ef_name.c_str(), mac, key);
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
                strcpy(enabled,"yes");
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
            printf("\nThis system has already registered record '%s';\nRun easyfind service to do update the record.\n\n", cmd_array.ef_name.c_str());
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
    } else if (last_ip == NULL || strcmp(ip, last_ip) != 0) {
        syslog(LOG_INFO, "new IP detected (%s); updating easyfind...", ip);
        struct ef_return* ret = ef_update(mac, key);
        if (ret->res != 0) {
            syslog(LOG_ERR, "Error while trying to update easyfind: %s", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            running = 0;
        } else {
            if (last_name != NULL || strcmp(last_name, ret->name) != 0) {
                syslog(LOG_ERR, "Easyfind reported name '%s' whereas '%s' is configured ... cannot continue", ret->name, last_name);
                free(ret->name);
                free(ret->ip);
                running = 0;
            } else {
                if (last_name != NULL) free(last_name);
                if (last_ip != NULL) free(last_ip);
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

    if (last_name == NULL || last_ip == NULL || strcmp(enabled,"yes")!=0) {
        fprintf(stderr, "Unable to read data from state file ; Configure with `ef` before running this daemon.\n");
        exit(1);
    }

#if defined (USER)
    state_file_ok = 0;
#endif

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
    
    if (cmd_array.ca_file.empty())
        ef_init();
    else
        ef_init(cmd_array.ca_file.c_str());
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

/* Json displaying function */
int ef_json() {
    read_state(1);
    if (last_name != NULL && strcmp(last_name, cmd_array.ef_name.c_str()) == 0 )  // manual refresh
        cmd_array.action = "getname";
    else if (cmd_array.action != "getname" && access(PID_FILE, F_OK) != -1)       // efd will stop itself after name is changed
        fprintf(stderr, YEL "WARNING" RESET ": easyfind daemon will be stopped.\n");

    if (last_name == NULL && cmd_array.action != "setname" && cmd_array.action != "getname") {
        cout << "{\"error\":\"true\",\"msg\":\"Easyfind not enabled.\"" << endl;
    } else if (cmd_array.action == "getname" && last_name != NULL && last_ip != NULL) {
        cout << "{\"error\":\"false\",\"ip\":\"" << last_ip << "\",\"name\":\"" << last_name << "\"}" << endl;
    } else {
        struct ef_return* ret;
        if (cmd_array.ca_file.empty())
            ef_init();
        else
            ef_init(cmd_array.ca_file.c_str());

        if (cmd_array.action == "disable") {
            ret = ef_unregister(mac, key, true);
            if (ret->res == 0) {
                if (unlink(cmd_array.st_file.c_str()) == -1)
                    fprintf(stderr, YEL "WARNING" RESET ": unable to remove state file (%s)\n",  strerror(errno));
            }
        } else {
            if (cmd_array.action == "setname") {
                ret = ef_register_new(cmd_array.ef_name.c_str(), mac, key, true);
            } else {
                ret = ef_update(mac, key, true);
            }
            if (ret->res == 0) {
                if (last_name != NULL) free(last_name);
                if (last_ip != NULL) free(last_ip);
                last_name = ret->name;
                last_ip = ret->ip;
                strcpy(enabled,"yes");
                char* res_w = write_state();
                if (res_w != NULL) {
                    fprintf(stderr, RED "ERROR" RESET "Unable to update state file: %s", res_w);
                }
            }
        }
        if (ret->res != 0) {
            cout << "{\"error\":\"true\",\"msg\":\""<< ret->curl_err_msg << ".\"" << endl;
        }

        if (ret->err_msg != NULL)
            free(ret->err_msg);
        free(ret);
        ef_cleanup();
    }
    if (last_name != NULL) free(last_name);
    if (last_ip != NULL) free(last_ip);
    return 0;
}

void usage(const char* format) {
    if ( strcmp(format, "badparm") == 0 ) {
        cout << "Bad parameter" << endl;
        cout << "Usage: ef [-nh] [-D|j] [-d|-q] [-s file] [-c file] [name]" << endl;
    } else if ( strcmp(format, "short") == 0 ) {
        cout << "Usage: ef [-nh] [-D|-j] [-d|-q] [-s file] [-c file] [name]" << endl;
        cout << "Type \"ef --help\" for more help" << endl;
    } else {
        cout << "Usage: ef [OPTIONS] [name]" << endl;
        cout << endl;
        cout << "  -d, --disable           disable easyfind (deletes registered name)" << endl;
        cout << "  -q, --query             query easyfind name" << endl;
        cout << "  -D, --daemon            daemonize easyfind client" << endl;
        cout << "  -j, --json              return json response" << endl;
        cout << "  -n, --nosslverify       don't verify easyfind server certificate" << endl;
        cout << "  -c, --cafile=FILE       use FILE to verify easyfind server certificate" << endl;
        cout << "  -s, --store=FILE        use FILE to store easyfind name and last known ip" << endl;
        cout << "  -h, --help              display this help and exit" << endl;
        cout << "  " << endl;
    }
}

void parse_parms(int argc, char** argv) {
    int i=1;
    std::string word;
    while (i < argc) {
        word = argv[i];
        if (word.length() > 1 && word[0] == '-' && word[1] != '-') {
            for (size_t j=1;j<word.length();j++) {
                if (word[j] == 'h') {
                    usage("short");
                    exit(0);
                } else if (word[j] == 'D' && cmd_array.entry_point == "ef") {
                    cmd_array.entry_point = "efd";
                } else if (word[j] == 'j' && cmd_array.entry_point == "ef") {
                    cmd_array.entry_point = "ef_json";
                } else if (word[j] == 'd' && cmd_array.action.empty()) {
                    cmd_array.action = "disable";
                } else if (word[j] == 'q' && cmd_array.action.empty()) {
                    cmd_array.action = "getname";
                } else if (word[j] == 'n') {
                    cmd_array.ca_file = "None";
                } else if (word[j] == 'c' && j==(word.length()-1)) {
                    i++;
                    cmd_array.ca_file = argv[i];
                } else if (word[j] == 's' && j==(word.length()-1)) {
                    i++;
                    cmd_array.st_file = argv[i];
                } else {
                    usage("badparm");
                    exit(1);
                }
            }
        } else if (word == "--help") {
            usage("long");
            exit(0);
        } else if (word == "--daemon" && cmd_array.entry_point == "ef") {
             cmd_array.entry_point = "efd";
        } else if (word == "--json" && cmd_array.entry_point == "ef") {
            cmd_array.entry_point = "ef_json";
        } else if (word == "--disable" && cmd_array.action.empty()) {
             cmd_array.action = "disable";
        } else if (word == "--query" && cmd_array.action.empty()) {
             cmd_array.action = "getname";
        } else if (word == "--nosslverify") {
             cmd_array.ca_file = "None";
        } else if (word.substr(0,9) == "--cafile=") {
             cmd_array.ca_file = word.substr(9);
        } else if (word.substr(0,8) == "--store=") {
             cmd_array.st_file = word.substr(8);
        } else if (word == "getname" && cmd_array.entry_point == "ef_json") {
            cmd_array.action = "getname";
        } else if (word == "setname" && cmd_array.entry_point == "ef_json") {
            cmd_array.action = "setname";
        } else if (word == "disable" && cmd_array.entry_point == "ef_json") {
            cmd_array.action = "disable";
        } else if (word[0] == '-') {
            usage("badparm");
            exit(1);
        } else if (cmd_array.ef_name.empty()) {
            cmd_array.ef_name = word;
        } else {
            usage("badparm");
            exit(1);
        }
        i++;
    }
    if (cmd_array.entry_point == "efd" && !cmd_array.action.empty() && !cmd_array.ef_name.empty()) {
        usage("badparm");
        exit(1);
    }
    if (cmd_array.entry_point == "ef" && cmd_array.action.empty() && cmd_array.ef_name.empty()) {
        usage("badparm");
        exit(1);
    }
    if (cmd_array.entry_point == "ef" && cmd_array.action.empty() && !cmd_array.ef_name.empty()) {
        cmd_array.action = "setname";
    } else if (cmd_array.action != "setname" && !cmd_array.ef_name.empty()) {
        usage("badparm");
        exit(1);
    }
    if (cmd_array.st_file.empty()) {
        cmd_array.st_file = STATE_FILE;
        cmd_array.st_dir  = STATE_DIR;
    } else {
        size_t last_slash = cmd_array.st_file.find_last_of("/");
        cmd_array.st_dir = cmd_array.st_file.substr(0,last_slash);
    }
}

int main(int argc, char** argv) {
    char* last_slash = strrchr(argv[0], (int)'/');
    const char* p_name = (last_slash == NULL) ? argv[0] : last_slash+1;
    if (strcmp(p_name, "ef") == 0) 
        cmd_array.entry_point = "ef";
    else if (strcmp(p_name, "efd") == 0)
        cmd_array.entry_point = "efd";
    else
        cmd_array.entry_point = "ef_json";

    parse_parms(argc,argv);
    check_state_perms();
    read_cmdline();
    if ( key == NULL )
        read_flash();
    if (key == NULL) {
        fprintf(stderr, RED "ERROR" RESET ": Unable to read key from either boot command line or flash; are you running on a B2/B3 ?\n");
        exit(1);
    }
    read_mac();
    if (cmd_array.entry_point == "efd") {
        return efd(argc, argv);
    } else if (cmd_array.entry_point == "ef") {
        return ef(argc, argv);
    } else {
        return ef_json();
    }
}
