#include <iostream>
#include <fstream>
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

command_array cmd_array;


std::string szHardwareKey;
std::string szMacAddress;
std::string szLastIP;
std::string szLastName;
std::string szEnabled;



/* State file opening/creation attempt */
void check_state_perms()
{
#if defined (USER)
    const char* root_msg = "You should probably run as root (ef) or " USER " (efd)";
#else
    const char* root_msg = "You should probably run as root";
#endif
    if (access(cmd_array.st_file.c_str(), F_OK) != -1)
    {
        if (access(cmd_array.st_file.c_str(), R_OK) == -1)
        {
            fprintf(stderr, RED "ERROR" RESET ": State file '%s' is not readable: %s\n%s\n", cmd_array.st_file.c_str(), strerror(errno), root_msg);
            exit(1);
        }
        if (access(cmd_array.st_file.c_str(), W_OK) == -1)
        {
            fprintf(stderr, RED "ERROR" RESET ": State file '%s' is not writeable: %s\n%s\n", cmd_array.st_file.c_str(), strerror(errno), root_msg);
            exit(1);
        }
    }
    else
    {
        if (access(cmd_array.st_dir.c_str(), F_OK) == -1)
        {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' does not exist (%s).\n", cmd_array.st_dir.c_str(), strerror(errno));
            exit(1);
        }
        if (access(cmd_array.st_dir.c_str(), R_OK | X_OK) == -1)
        {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not readable: %s\n%s\n", cmd_array.st_dir.c_str(), strerror(errno), root_msg);
            exit(1);
        }
        if (access(cmd_array.st_dir.c_str(), W_OK) == -1)
        {
            fprintf(stderr, RED "ERROR" RESET ": State directory '%s' is not writeable: %s\n%s\n", cmd_array.st_dir.c_str(), strerror(errno), root_msg);
            exit(1);
        }
    }
}

/* Reads key value from boot command line */
void read_kernel_cmdline()
{
    std::ifstream cmdline ("/proc/cmdline");
    if ( cmdline.is_open() )
    {
        std::string line;
        getline(cmdline,line);
        cmdline.close();
        size_t pos = line.find("key=");
        if (pos == std::string::npos)
            return;
        pos += 4;
        line.append(" ");
        size_t end = line.find(" ", pos);
        szHardwareKey = line.substr(pos, end - pos);
    }
    else
    {
        fprintf(stderr, YEL "WARNING" RESET ": Unable to open /proc/cmdline file !\n");
    }
}


/* Reads key value from u-boot environment in flash */
void read_flash()
{
#if defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)
    // Bubba|2
    char env[8192];
    ifstream fd ("/dev/mtd0", ios::in|ios::binary|ios::ate);
    if (!fd.is_open())
        return;
    fd.seekg (0x50000, ios::beg);
    fd.read (env, 8192);
    if (env[4] == 0x0)
    {
        fd.seekg (0x60000, ios::beg);
        fd.read (env, 8192);
    }
    char *pos = &env[5];
#else
    // B3
    char env[65536];
    std::ifstream fd ("/dev/mtd1", std::ios::in|std::ios::binary|std::ios::ate);
    if (!fd.is_open())
        return;
    fd.seekg (0, std::ios::beg);
    fd.read (env, 65536);
    char *pos = &env[4];
#endif
    fd.close();

    int l = strlen(pos);
    while (l > 0)
    {
        if (strncmp(pos, "key=", 4) == 0)
        {
            szHardwareKey.append(pos + 4, l - 3);
            break;
        }
        pos += l + 1;
        l = strlen(pos);
    }
}


/* Try to load last known state */
void read_statefile(bool verbose)
{
    std::ifstream statefile (cmd_array.st_file.c_str());
    if ( statefile.is_open() )
    {
        if (verbose)
            printf("\nReading state file ... ");
        std::string szKey,szValue;
        bool isKey = true;
        std::string line;
        unsigned int i;
        while ( getline(statefile,line) )
        {
            if ( (line[0] == '#') || (line[0] == ';') )
                continue;
            isKey = true;
            szKey = "";
            szValue = "";
            for (i = 0; i < line.length(); i++)
            {
                if (line[i] == '\r')
                    continue;
                if (line[i] == ' ')
                    continue;
                if (line[i] == '=')
                {
                    isKey = false;
                    continue;
                }
                if (isKey)
                    szKey.insert(szKey.end(),1,line[i]);
                else
                    szValue.insert(szValue.end(),1,line[i]);
            }
            if ( ! isKey )
            {
                if (szKey == "ip")
                    szLastIP = szValue;
                if (szKey == "name")
                    szLastName = szValue;
                if (szKey == "enable")
                    szEnabled = szValue;
            }
        }
        statefile.close();
        if ( szLastName.empty() || szLastIP.empty() || (szEnabled != "yes") )
        {
            szLastName = "";
            szLastIP = "";
            if (verbose)
                printf(RED "KO" RESET "\n");
        }
        else if (verbose)
            printf(GRN "OK" RESET "\n");
    }
    else if (verbose)
        printf("\n");
}

#if defined (USER)
int state_file_ok = 1;
#endif

/* Write state file */
char* write_state()
{
    FILE* st_file = fopen(cmd_array.st_file.c_str(), "w");
    if (st_file == NULL)
        return strerror(errno);

    fprintf(st_file, "enable = %s\nip = %s\nname = %s\n", szEnabled.c_str(), szLastIP.c_str(), szLastName.c_str());
    fclose(st_file);
#if defined (USER)
    if (state_file_ok == 1)
    {
        struct passwd *u_pwd = getpwnam(USER);
        if (u_pwd == NULL)
        {
            unlink(cmd_array.st_file);
            return "Unable to get " USER " passwd information";
        }
        struct stat st_info;
        stat(cmd_array.st_file, &st_info);
        int chg_u = (u_pwd->pw_uid != st_info.st_uid) ? u_pwd->pw_uid : -1;
        int chg_g = (u_pwd->pw_gid != st_info.st_gid) ? u_pwd->pw_gid : -1;
        if ((chg_u != -1) || (chg_g != -1))
        {
            int r = chown(cmd_array.st_file, chg_u, chg_g);
            if (r == -1)
            {
                unlink(cmd_array.st_file.c_str());
                return strerror(errno);
            }
        }
        state_file_ok = 0;
    }
#endif
    return NULL;
}

/* Read MAC address from sysfs */
void read_mac()
{
    std::ifstream cmdline (WAN_MAC_FILE);
    if ( cmdline.is_open() )
    {
        getline(cmdline,szMacAddress);
        cmdline.close();
    }
    else
    {
        fprintf(stderr, RED "ERROR" RESET ": Unable to open WAN interface mac address file %s !\n", WAN_MAC_FILE);
        exit(1);
    }
}


/* Test domain name for FQDN compliancy */
int fqdn_test(const char *domain)
{
    const char* fqdn_regex = "^([a-z0-9-]{1,63}\\.){2}[a-z]{2,63}$";
    regex_t regex;
    int r = regcomp(&regex, fqdn_regex, REG_EXTENDED | REG_ICASE | REG_NOSUB);
    if (r != 0)
    {
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
int ef(int argc, char** argv)
{
    if (access(PID_FILE, F_OK) != -1)
    {
        fprintf(stderr, "easyfind daemon is running; stop it before running the `ef` command\n");
        exit(1);
    }

    struct ef_return* ret;
    if (cmd_array.ca_file.empty())
        ef_init();
    else
        ef_init(cmd_array.ca_file.c_str());

    if (cmd_array.action == "disable")
    {
        read_statefile(true);
        printf("Unregistering easyfind ... ");
        fflush(stdout);
        ret = ef_unregister(szMacAddress.c_str(), szHardwareKey.c_str());
        if (ret->res != 0)
        {
            printf(RED "KO" RESET "\n");
            fprintf(stderr, RED "ERROR" RESET ": %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
        }
        else
        {
            printf(GRN "OK" RESET "\n");
            if (!szLastName.empty())
            {
                printf("Removing state file ... ");
                if (unlink(cmd_array.st_file.c_str()) == -1)
                {
                    printf(RED "KO" RESET "\n");
                    fprintf(stderr, YEL "WARNING" RESET ": unable to remove state file (%s)\n",  strerror(errno));
                }
                else
                {
                    printf(GRN "OK" RESET "\n");
                    printf("\nEasyfind succesfully unconfigured.\n\n");
                }
            }
            else
                printf("\nEasyfind succesfully unconfigured.\n\n");
        }
    }
    else if (cmd_array.action == "setname")
    {
        read_statefile(true);
        int r = fqdn_test(cmd_array.ef_name.c_str());
        if (r != 0)
        {
            if (r == REG_NOMATCH)
            {
                fprintf(stderr,  RED "ERROR" RESET ": The requested domain %s is not valid\n", cmd_array.ef_name.c_str());
                return 1;
            }
            else
            {
                fprintf(stderr,  RED "ERROR" RESET ": There was an error while trying to check domain regex.\n");
                return 1;
            }
        }

        if (szLastName.empty() || (szLastName != cmd_array.ef_name) )
        {
            if (szLastName.empty())
                printf("Registering new record '%s'... ", cmd_array.ef_name.c_str());
            else
                printf("Replacing record '%s' with '%s'... ", szLastName.c_str() , cmd_array.ef_name.c_str());
            fflush(stdout);
            ret = ef_register_new(cmd_array.ef_name.c_str(), szMacAddress.c_str(), szHardwareKey.c_str());
            if (ret->res != 0)
            {
                printf(RED "KO" RESET "\n");
                fprintf(stderr, RED "ERROR" RESET ": %s\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            }
            else
            {
                printf(GRN "OK" RESET "\n");
                szLastName = ret->name;
                szLastIP = ret->ip;
                printf("Writing state file ... ");
                fflush(stdout);
                szEnabled = "yes";
                char* res_w = write_state();
                if (res_w != NULL)
                {
                    printf(RED "KO" RESET "\n");
                    fprintf(stderr, RED "ERROR" RESET ": unable to write state file (%s)\n", res_w);
                }
                else
                {
                    printf(GRN "OK" RESET "\n");
                    printf("\nAll done ; you may now enable the easyfind client daemon efd\nto periodically verify and update your easyfind name.\n\n");
                }
                free(ret->name);
                free(ret->ip);
            }
        }
        else
            printf("\nThis system has already registered record '%s';\nRun easyfind service to update the record.\n\n", cmd_array.ef_name.c_str());
    }
    else if (cmd_array.action == "getname")
    {
        ret = ef_update(szMacAddress.c_str(), szHardwareKey.c_str());
        if (ret->res == 0)
        {
            szLastName = ret->name;
            printf("%s\n",szLastName.c_str());
            free(ret->name);
            free(ret->ip);
        }
    }

    if (ret->res == 1)
        free(ret->err_msg);
    free(ret);
    ef_cleanup();

    return 0;
}

int running = 1;


void check_and_update()
{
    std::string szCurrentIP = get_ip();
    if (szCurrentIP.empty())
    {
        syslog(LOG_ERR, "Unable to get external ip from easyfind !");
        return;
    }
    else if (szLastIP.empty() || (szCurrentIP != szLastIP))
    {
        syslog(LOG_INFO, "new IP detected (%s); updating easyfind...", szCurrentIP.c_str());
        struct ef_return* ret = ef_update(szMacAddress.c_str(), szHardwareKey.c_str());
        if (ret->res != 0)
        {
            syslog(LOG_ERR, "Error while trying to update easyfind: %s", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            running = 0;
        }
        else
        {
            if (szLastName.empty() || (szLastName != ret->name))
            {
                szLastName = ret->name;
                szLastIP = ret->ip;
                char* res_w = write_state();
                if (res_w != NULL)
                {
                    syslog(LOG_ERR, "Unable to update state file: %s", res_w);
                    running = 0;
                }
                else
                    syslog(LOG_INFO, "Easyfind and state file successfully updated with new IP");
            }
            else
            {
                syslog(LOG_ERR, "Easyfind reported name '%s' whereas '%s' is configured ... cannot continue", ret->name, szLastName.c_str());
                free(ret->name);
                free(ret->ip);
                running = 0;
            }
        }

        if (ret->res == 1)
            free(ret->err_msg);
        free(ret);
    }
}


void handle_term(int signum)
{
    syslog(LOG_INFO, "SIGTERM received, exiting daemon ...");
    running = 0;
}


/* Main daemonic function */
int efd(int argc, char** argv)
{
    read_statefile(false);

    if (szLastName.empty() || szLastIP.empty() || (szEnabled != "yes"))
    {
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
    }
    else if (pid > 0)
        exit(0);

    openlog("efd", LOG_PID, LOG_DAEMON);
    syslog(LOG_INFO, "Starting easyfind update daemon");

    pid_t sid = setsid();
    if (sid < 0)
    {
        syslog(LOG_ERR, "Unable to create a new session for the daemon process: %s", strerror(errno));
        closelog();
        exit(1);
    }

    if (chdir("/") < 0)
    {
        syslog(LOG_ERR, "Unable to change process directory: %s", strerror(errno));
        closelog();
        exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    umask(027);

    int pid_fd = open(PID_FILE, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (pid_fd == -1)
    {
        syslog(LOG_ERR, "Unable to create PID file: %s", strerror(errno));
        closelog();
        exit(1);
    }

    if (lockf(pid_fd, F_TLOCK, 0) == -1)
    {
        syslog(LOG_ERR, "Unable to lock PID file (%s); the daemon is likely already running ...", strerror(errno));
        closelog();
        exit(1);
    }

    char pid_s[10];
    sprintf(pid_s, "%d\n", getpid());
    if (write(pid_fd, pid_s, strlen(pid_s)) != 1)
        return 1;
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
    while(running)
    {
        check_and_update();
        r = UPDATE_INTERVAL;
        while(running && (r > 0))
            r = sleep(r);
    }

    ef_cleanup();
    unlink(PID_FILE);
    syslog(LOG_INFO, "Easyfind daemon stopped");
    closelog();
    return 0;
}

/* Json displaying function */
int ef_json()
{
    read_statefile(false);
    if (!szLastName.empty() && (szLastName == cmd_array.ef_name))  // manual refresh
        cmd_array.action = "getname";
    else if ((cmd_array.action != "getname") && (access(PID_FILE, F_OK) != -1))       // efd will stop itself after name is changed
        fprintf(stderr, YEL "WARNING" RESET ": easyfind daemon will be stopped.\n");

    if (szLastName.empty() && (cmd_array.action != "setname") && (cmd_array.action != "getname"))
        std::cout << "{\"error\":\"true\",\"msg\":\"Easyfind not enabled.\"}\n";
    else if ((cmd_array.action == "getname") && !szLastName.empty() && !szLastIP.empty())
        std::cout << "{\"error\":\"false\",\"ip\":\"" << szLastIP << "\",\"name\":\"" << szLastName << "\"}\n";
    else
    {
        struct ef_return* ret;
        if (cmd_array.ca_file.empty())
            ef_init();
        else
            ef_init(cmd_array.ca_file.c_str());

        if (cmd_array.action == "disable")
        {
            ret = ef_unregister(szMacAddress.c_str(), szHardwareKey.c_str(), true);
            if (ret->res == 0)
            {
                if (unlink(cmd_array.st_file.c_str()) == -1)
                    fprintf(stderr, YEL "WARNING" RESET ": unable to remove state file (%s)\n",  strerror(errno));
            }
        }
        else
        {
            if (cmd_array.action == "setname")
            {
                ret = ef_register_new(cmd_array.ef_name.c_str(), szMacAddress.c_str(), szHardwareKey.c_str(), true);
            }
            else
            {
                ret = ef_update(szMacAddress.c_str(), szHardwareKey.c_str(), true);
            }
            if (ret->res == 0)
            {
                szLastName = ret->name;
                szLastIP = ret->ip;
                szEnabled = "yes";
                if (ret->name != NULL)
                    free(ret->name);
                if (ret->ip != NULL)
                    free(ret->ip);
                char* res_w = write_state();
                if (res_w != NULL)
                {
                    fprintf(stderr, RED "ERROR" RESET "Unable to update state file: %s", res_w);
                }
            }
        }
        if (ret->res != 0)
            printf("{\"error\":\"true\",\"msg\":\"%s.\"\n", (ret->res == 1) ? ret->err_msg : ret->curl_err_msg);
            
        if (ret->res == 1)
            free(ret->err_msg);
        free(ret);
        ef_cleanup();
    }
    return 0;
}

void usage(const char* format)
{
    if (strcmp(format, "badparm") == 0)
    {
        std::cout << "Bad parameter\n";
        std::cout << "Usage: ef [-nh] [-D|j] [-d|-q] [-s file] [-c file] [json command] [name]\n";
    }
    else if (strcmp(format, "short") == 0)
    {
        std::cout << "Usage: ef [-nh] [-D|-j] [-d|-q] [-s file] [-c file] [json command] [name]\n";
        std::cout << "Type \"ef --help\" for more help\n";
    }
    else
    {
        std::cout << "Usage: ef [OPTIONS] [name]\n]\n";

        std::cout << "  -d, --disable           disable easyfind (deletes registered name)\n";
        std::cout << "  -q, --query             query easyfind name\n";
        std::cout << "  -D, --daemon            daemonize easyfind client\n";
        std::cout << "  -j, --json              return json response\n";
        std::cout << "  -n, --nosslverify       don't verify easyfind server certificate\n";
        std::cout << "  -c, --cafile=FILE       use FILE to verify easyfind server certificate\n";
        std::cout << "  -s, --store=FILE        use FILE to store easyfind name and last known ip\n";
        std::cout << "  -h, --help              display this help and exit\n\n";

        std::cout << "Json mode also accepts the following command input:\n";
        std::cout << "  <none>                  update easyfind server with current IP\n";
        std::cout << "  getname                 recreate state file with info from easyfind server\n";
        std::cout << "  setname <name>          enable easyfind\n";
        std::cout << "  disable                 disable easyfind\n\n";
    }
}

void parse_parms(int argc, char** argv)
{
    int i=1;
    std::string word;
    while (i < argc)
    {
        word = argv[i];
        if ((word.length() > 1) && (word[0] == '-') && (word[1] != '-'))
        {
            for (size_t j=1;j<word.length();j++)
            {
                if (word[j] == 'h')
                {
                    usage("short");
                    exit(0);
                }
                else if ((word[j] == 'D') && (cmd_array.entry_point == "ef"))
                    cmd_array.entry_point = "efd";
                else if ((word[j] == 'j') && (cmd_array.entry_point == "ef"))
                    cmd_array.entry_point = "ef_json";
                else if ((word[j] == 'd') && (cmd_array.action.empty()))
                    cmd_array.action = "disable";
                else if ((word[j] == 'q') && (cmd_array.action.empty()))
                    cmd_array.action = "getname";
                else if (word[j] == 'n')
                    cmd_array.ca_file = "None";
                else if ((word[j] == 'c') && (j == (word.length()-1)))
                {
                    i++;
                    cmd_array.ca_file = argv[i];
                }
                else if ((word[j] == 's') && (j == (word.length()-1)))
                {
                    i++;
                    cmd_array.st_file = argv[i];
                }
                else
                {
                    usage("badparm");
                    exit(1);
                }
            }
        }
        else if (word == "--help")
        {
            usage("long");
            exit(0);
        }
        else if ((word == "--daemon") && cmd_array.entry_point == "ef")
            cmd_array.entry_point = "efd";
        else if ((word == "--json") && cmd_array.entry_point == "ef")
            cmd_array.entry_point = "ef_json";

        else if ((word == "--disable") && (cmd_array.action.empty()))
            cmd_array.action = "disable";
        else if ((word == "--query") && (cmd_array.action.empty()))
            cmd_array.action = "getname";

        else if (word == "--nosslverify")
            cmd_array.ca_file = "None";
        else if (word.substr(0,9) == "--cafile=")
            cmd_array.ca_file = word.substr(9);
        else if (word.substr(0,8) == "--store=")
            cmd_array.st_file = word.substr(8);

        else if ((cmd_array.entry_point == "ef_json") && (cmd_array.action.empty()))
        {
            if ((word == "getname") || (word == "setname") || (word == "disable"))
                cmd_array.action = word;
        }
        else if (word[0] == '-')
        {
            usage("badparm");
            exit(1);
        }
        else if (cmd_array.ef_name.empty())
            cmd_array.ef_name = word;
        else
        {
            usage("badparm");
            exit(1);
        }
        i++;
    }
    if (i == 1) // default action
        cmd_array.action = "getname";

    if ((cmd_array.entry_point == "efd") && (!cmd_array.action.empty()) && (!cmd_array.ef_name.empty()))
    {
        usage("badparm");
        exit(1);
    }
    if ((cmd_array.entry_point == "ef") && (cmd_array.action.empty()) && (cmd_array.ef_name.empty()))
    {
        usage("badparm");
        exit(1);
    }
    if ((cmd_array.entry_point == "ef") && (cmd_array.action.empty()) && (!cmd_array.ef_name.empty()))
    {
        cmd_array.action = "setname";
    }
    else if ((cmd_array.action != "setname") && (!cmd_array.ef_name.empty()))
    {
        usage("badparm");
        exit(1);
    }
    if (cmd_array.st_file.empty())
    {
        cmd_array.st_file = STATE_FILE;
        cmd_array.st_dir  = STATE_DIR;
    }
    else
    {
        size_t last_slash = cmd_array.st_file.find_last_of("/");
        cmd_array.st_dir = cmd_array.st_file.substr(0,last_slash);
    }
}

int main(int argc, char** argv)
{
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
    read_kernel_cmdline();
    if (szHardwareKey.empty())
        read_flash();
    if (szHardwareKey.empty())
    {
        fprintf(stderr, RED "ERROR" RESET ": Unable to read key from either boot command line or flash; are you running on a B2/B3 ?\n");
        exit(1);
    }
    read_mac();
    if (cmd_array.entry_point == "efd")
        return efd(argc, argv);
    else if (cmd_array.entry_point == "ef")
        return ef(argc, argv);
    else
        return ef_json();
}
