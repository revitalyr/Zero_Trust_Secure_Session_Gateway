module;

#include <memory>
#include <vector>
#include <functional>

export module zerossg.cli.cli_interface;

export import zerossg.common;
export import zerossg.types;
export namespace zerossg {

struct CLICommand {
    CommandName name;
    CommandDescription description;
    CommandUsage usage;
    std::function<int(const CommandLineArgs&)> handler;
    Vector<String> required_args;
    Vector<String> optional_args;
};

// CLI interface class
export class CLIInterface {
public:
    CLIInterface();
    virtual ~CLIInterface() = default;
    Result<int> run(int argc, char* argv[]);

    // Public methods used by main or other components
    void show_status();
    void show_sessions();
    void show_users();
    void show_version();
    void export_audit_logs(const String& output_file);
    
    // Parsing helper
    CommandLineArgs parse_input(const RawInputString& input);

private:
    void register_builtin_commands();
    void register_command(const CLICommand& command);
    void register_command(const CommandName& name, const CommandDescription& description, const CommandUsage& usage,
                          std::function<int(const CommandLineArgs&)> handler);
    
    void show_help();
    void show_command_help(const CLICommand& command);
    void show_prompt();
    
    CommandLineArgs parse_command_line(int argc, char* argv[]);
    CLICommand* find_command(const CommandName& name);
    bool validate_arguments(const CLICommand& command, const CommandLineArgs& args);
    
    // Command handlers
    int start_server(const CommandLineArgs& args);
    int stop_server(const CommandLineArgs& args);
    int handle_start_command(const CommandLineArgs& args);
    int handle_stop_command(const CommandLineArgs& args);
    int handle_status_command(const CommandLineArgs& args);
    int handle_users_command(const CommandLineArgs& args);
    int handle_sessions_command(const CommandLineArgs& args);
    int handle_security_command(const CommandLineArgs& args);
    int handle_logs_command(const CommandLineArgs& args);
    int handle_user_add_command(const CommandLineArgs& args);
    int handle_user_remove_command(const CommandLineArgs& args);
    int handle_config_command(const CommandLineArgs& args);
    int handle_test_command(const CommandLineArgs& args);
    
    void run_interactive_mode();
    
    // Printing helpers
    void print_error(const String& error);
    void print_info(const String& message);
    void print_success(const String& message);
    void print_warning(const String& message);
    void print_table(const TableData& data, const TableHeaders& headers);
    
    Vector<CLICommand> m_commands;
    String m_config_file = "config.json";
    std::unique_ptr<class GatewayServer> m_server;
};

} // namespace zerossg
