#pragma once

#include "zerossg/interfaces.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace zerossg {

struct CLICommand {
    string name;
    string description;
    string usage;
    std::function<int(const std::vector<string>&)> handler;
    std::vector<string> required_args;
    std::vector<string> optional_args;
};

class CLIInterface : public ICLI {
public:
    CLIInterface();
    ~CLIInterface() override = default;
    
    // ICLI interface
    Result<int> run(int argc, char* argv[]) override;
    void show_help() override;
    void show_active_sessions() override;
    void export_audit_logs(const string& output_file) override;
    
    // Command registration
    void register_command(const CLICommand& command);
    void register_command(const string& name, const string& description, const string& usage,
                         std::function<int(const std::vector<string>&)> handler);
    
    // Built-in commands
    int start_server(const std::vector<string>& args);
    int stop_server(const std::vector<string>& args);
    int show_status(const std::vector<string>& args);
    int list_users(const std::vector<string>& args);
    int list_sessions(const std::vector<string>& args);
    int show_security_stats(const std::vector<string>& args);
    int export_logs(const std::vector<string>& args);
    int add_user(const std::vector<string>& args);
    int remove_user(const std::vector<string>& args);
    int show_config(const std::vector<string>& args);
    int test_connection(const std::vector<string>& args);
    
    // Interactive mode
    void run_interactive_mode();
    void show_prompt();
    std::vector<string> parse_input(const string& input);
    
    // Output formatting
    void print_table(const std::vector<std::vector<string>>& data, const std::vector<string>& headers);
    void print_error(const string& error);
    void print_success(const string& message);
    void print_info(const string& message);
    void print_warning(const string& message);
    
    // Configuration
    void set_config_file(const string& config_file) { m_config_file = config_file; }
    void set_output_format(const string& format) { m_output_format = format; }
    
private:
    std::vector<CLICommand> m_commands;
    string m_config_file{"config.json"};
    string m_output_format{"table"}; // table, json, csv
    
    // Server management (simplified - in production, would use IPC)
    std::unique_ptr<GatewayServer> m_server;
    
    // Helper methods
    void register_builtin_commands();
    CLICommand* find_command(const string& name);
    std::vector<string> parse_command_line(int argc, char* argv[]);
    bool validate_arguments(const CLICommand& command, const std::vector<string>& args);
    void show_command_help(const CLICommand& command);
    
    // Output formatting helpers
    string format_user_table(const vector<User>& users);
    string format_session_table(const vector<Session>& sessions);
    string format_security_stats();
    string format_json_output(const nlohmann::json& data);
    string format_csv_output(const std::vector<std::vector<string>>& data, const std::vector<string>& headers);
    
    // Server interaction (simplified)
    bool is_server_running();
    Result<void> connect_to_server();
    void disconnect_from_server();
    
    // Command-specific implementations
    int handle_start_command(const std::vector<string>& args);
    int handle_stop_command(const std::vector<string>& args);
    int handle_status_command(const std::vector<string>& args);
    int handle_users_command(const std::vector<string>& args);
    int handle_sessions_command(const std::vector<string>& args);
    int handle_security_command(const std::vector<string>& args);
    int handle_logs_command(const std::vector<string>& args);
    int handle_user_add_command(const std::vector<string>& args);
    int handle_user_remove_command(const std::vector<string>& args);
    int handle_config_command(const std::vector<string>& args);
    int handle_test_command(const std::vector<string>& args);
};

// CLI utilities
class CLIUtils {
public:
    // Input validation
    static bool is_valid_username(const string& username);
    static bool is_valid_email(const string& email);
    static bool is_valid_role(const string& role);
    static bool is_valid_port(const string& port);
    static bool is_valid_file_path(const string& path);
    
    // String utilities
    static string trim(const string& str);
    static std::vector<string> split(const string& str, char delimiter);
    static string to_lower(const string& str);
    static string to_upper(const string& str);
    
    // Color output (if supported)
    static string color_red(const string& text);
    static string color_green(const string& text);
    static string color_yellow(const string& text);
    static string color_blue(const string& text);
    static string color_reset();
    static bool supports_color();
    
    // Progress indicators
    static void show_progress(const string& message, int current, int total);
    static void show_spinner(const string& message);
    
    // Password input
    static string get_password_input(const string& prompt);
    static string get_hidden_input(const string& prompt);
};

// Interactive shell features
class InteractiveShell {
public:
    explicit InteractiveShell(CLIInterface& cli);
    void run();
    
    // Command history
    void add_to_history(const string& command);
    std::vector<string> get_history();
    void clear_history();
    
    // Auto-completion
    std::vector<string> get_completions(const string& partial_command);
    void enable_auto_completion(bool enable = true);
    
private:
    CLIInterface& m_cli;
    std::vector<string> m_command_history;
    bool m_auto_completion_enabled{true};
    
    // Shell state
    bool m_running{true};
    
    // Command processing
    void process_command(const string& command);
    bool should_exit(const string& command);
    
    // History management
    static constexpr size_t MAX_HISTORY_SIZE = 1000;
    void trim_history();
    
    // Auto-completion helpers
    std::vector<string> get_command_names();
    std::vector<string> get_argument_completions(const string& command, const string& partial_arg);
};

} // namespace zerossg
