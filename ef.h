struct command_array {
    std::string entry_point;
    std::string action;
    std::string ef_name;
    std::string ca_file;
    std::string st_file;
    std::string st_dir;
};


void check_state_perms ();
void read_kernel_cmdline ();
void read_flash ();
void read_mac ();

void read_state (bool verbose);
char* write_state ();
void read_statefile(bool verbose);

void check_and_update ();
void handle_term (int signum);

int ef  (int argc, char** argv);
int efd (int argc, char** argv);
int ef_json ();

void usage (const char* format);
void parse_parms (int argc, char** argv);
int fqdn_test(const char *domain);
