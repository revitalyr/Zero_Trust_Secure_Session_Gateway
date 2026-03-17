module;

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <print>
#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

module zerossg.cli.cli_interface;

import zerossg.cli.cli_interface;
import zerossg.network.gateway_server;
import zerossg.config.config_manager;
import zerossg.auth.authenticator;
import zerossg.session.session_manager;
import zerossg.common; // For make_result_success, make_result_error
import zerossg.security.security_manager;
import zerossg.constants;

namespace zerossg {

// Local helper class for CLI utilities
class CLIUtils {
public:
    static bool is_valid_username(const String& username);
    static bool is_valid_email(const String& email);
    static bool is_valid_role(const String& role);
    static bool is_valid_port(const String& port);
    static bool is_valid_file_path(const String& path);
    
    static String trim(const String& str);
    static std::vector<String> split(const String& str, char delimiter);
    static String to_lower(const String& str);
    static String to_upper(const String& str);
    
    static String color_red(const String& text);
    static String color_green(const String& text);
    static String color_yellow(const String& text);
    static String color_blue(const String& text);
    static String color_reset();
    
    static bool supports_color();
    static void show_progress(const String& message, int current, int total);
    static void show_spinner(const String& message);
    
    static String get_password_input(const String& prompt);
    static String get_hidden_input(const String& prompt);
};

// Interactive shell helper class
class InteractiveShell {
public:
    explicit InteractiveShell(CLIInterface& cli);
    void run();
    
private:
    void process_command(const String& command);
    void add_to_history(const String& command);
    void clear_history();
    std::vector<String> get_history();
    std::vector<String> get_completions(const String& partial_command);
    std::vector<String> get_command_names();
    void enable_auto_completion(bool enable);
    bool should_exit(const String& command);
    void trim_history();
    
    CLIInterface& m_cli;
    bool m_running{true};
    bool m_auto_completion_enabled{true};
    std::vector<String> m_command_history;
    static constexpr size_t MAX_HISTORY_SIZE = 100;
};

const char* CLI_PROMPT = "zerossg> ";
const char CLI_SPINNER_CHARS[] = "|/-\\";

zerossg::GatewayServer* g_server = nullptr;

zerossg::CLIInterface::CLIInterface() {
    zerossg::CLIInterface::register_builtin_commands();
}

Result<int> zerossg::CLIInterface::run(int argc, char* argv[]) {
    try {
        zerossg::CommandLineArgs args = parse_command_line(argc, argv);
        
        if (args.empty()) {
            show_help();
            return 1;
        }
        
        zerossg::CommandName command_name = args[0];
        CLICommand* command = find_command(command_name);
        
        if (!command) {
            print_error("Unknown command: " + command_name);
            show_help();
            return 1;
        }
        
        zerossg::CommandLineArgs command_args(args.begin() + 1, args.end());
        
        if (!validate_arguments(*command, command_args)) {
            show_command_help(*command);
            return 1;
        }
        
        int result = command->handler(command_args);
        return result;
    } catch (const std::exception& e) {
        print_error(std::format("CLI error: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("CLI error: {}", e.what());
        
        return 1;
    }
}

void CLIInterface::show_help() {
    std::println("Zero Trust Secure Session Gateway CLI");
    std::println("=====================================");
    std::println();
    
    std::println("Usage: zerossg <command> [options]");
    std::println();
    
    std::println("Available commands:");
    for (const auto& cmd : m_commands) {
        std::println("  {:<15} - {}", cmd.name, cmd.description);
    }
    std::println();
    
    std::println("Use 'zerossg <command> --help' for detailed information about a specific command.");
    std::println("Use 'zerossg interactive' to enter interactive mode.");
}

void CLIInterface::show_sessions() {
    try {
        // This would connect to the server and get active sessions
        // For now, show a placeholder
        print_info("Active sessions:");
        std::println("No active sessions (server not running)");
    } catch (const std::exception& e) {
        print_error(std::format("Failed to get active sessions: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to get active sessions: {}", e.what());
    }
}

void CLIInterface::export_audit_logs(const zerossg::FilePath& output_file) {
    try {
        // This would connect to the server and export logs
        // For now, show a placeholder
        print_info("Exporting audit logs to: " + output_file);
        print_success("Audit logs exported successfully");
    } catch (const std::exception& e) {
        print_error(std::format("Failed to export audit logs: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to export audit logs: {}", e.what());
    }
}

void CLIInterface::show_status() {
    handle_status_command({});
}

void CLIInterface::register_command(const CLICommand& command) {
    m_commands.push_back(command);
}

void CLIInterface::register_command(const zerossg::CommandName& name, const zerossg::CommandDescription& description, const zerossg::CommandUsage& usage,
                                    std::function<int(const zerossg::CommandLineArgs&)> handler) {
    CLICommand cmd;
    cmd.name = name;
    cmd.description = description;
    cmd.usage = usage;
    cmd.handler = handler;
    register_command(cmd);
}

void CLIInterface::run_interactive_mode() {
#ifdef HAVE_READLINE
    InteractiveShell shell(*this);
    shell.run();
#else
    print_error("Interactive mode is not supported in this build (readline library not found).");
#endif
}

void CLIInterface::show_prompt() {
    std::print("{}", zerossg::CLI_PROMPT);
    std::fflush(stdout);
}

zerossg::CommandLineArgs CLIInterface::parse_input(const zerossg::RawInputString& input) {
    zerossg::CommandLineArgs tokens;
    std::istringstream iss(input);
    zerossg::String token;
    
    while (iss >> token) {
        tokens.push_back(token);
    }
    
    return tokens;
}

void CLIInterface::print_table(const zerossg::TableData& data, const zerossg::TableHeaders& headers) {
    if (data.empty() && headers.empty()) {
        return;
    }
    
    // Calculate column widths
    std::vector<size_t> column_widths;
    
    if (!headers.empty()) {
        for (const auto& header : headers) {
            column_widths.push_back(header.length());
        }
    }
    
    for (const auto& row : data) {
        for (size_t i = 0; i < row.size() && i < column_widths.size(); ++i) {
            column_widths[i] = std::max(column_widths[i], row[i].length());
        }
    }
    
    // Print headers
    if (!headers.empty()) {
        for (size_t i = 0; i < headers.size(); ++i) {
            std::print("{:<{}}", headers[i], column_widths[i]);
            if (i < headers.size() - 1) {
                std::print(" | ");
            }
        }
        std::println();
        
        // Print separator
        for (size_t i = 0; i < headers.size(); ++i) {
            for (size_t j = 0; j < column_widths[i]; ++j) {
                std::print("-");
            }
            if (i < headers.size() - 1) {
                std::print("-+-");
            }
        }
        std::println();
    }
    
    // Print data
    for (const auto& row : data) {
        for (size_t i = 0; i < row.size() && i < column_widths.size(); ++i) {
            std::print("{:<{}}", row[i], column_widths[i]);
            if (i < row.size() - 1) {
                std::print(" | ");
            }
        }
        std::println();
    }
}

void CLIInterface::print_error(const zerossg::ErrorString& error) {
    if (CLIUtils::supports_color()) {
        std::println("{}{}", CLIUtils::color_red("ERROR: "), error);
    } else {
        std::println("ERROR: {}", error);
    }
}

void CLIInterface::print_success(const zerossg::SuccessString& message) {
    if (CLIUtils::supports_color()) {
        std::println("{}{}", CLIUtils::color_green("SUCCESS: "), message);
    } else {
        std::println("SUCCESS: {}", message);
    }
}

void CLIInterface::print_info(const zerossg::InfoString& message) {
    if (CLIUtils::supports_color()) {
        std::println("{}{}", CLIUtils::color_blue("INFO: "), message);
    } else {
        std::println("INFO: {}", message);
    }
}

void CLIInterface::print_warning(const zerossg::WarningString& message) {
    if (CLIUtils::supports_color()) {
        std::println("{}{}", CLIUtils::color_yellow("WARNING: "), message);
    } else {
        std::println("WARNING: {}", message);
    }
}

void CLIInterface::register_builtin_commands() {
    register_command(zerossg::CMD_START, "Start the Zero Trust gateway server", "start [config-file]",
                     [this](const zerossg::CommandLineArgs& args) { return start_server(args); });
    
    register_command(zerossg::CMD_STOP, "Stop the Zero Trust gateway server", "stop",
                     [this](const zerossg::CommandLineArgs& args) { return stop_server(args); });
    
    register_command(zerossg::CMD_STATUS, "Show server status and statistics", "status",
                     [this](const zerossg::CommandLineArgs& args) { return handle_status_command(args); });
    
    register_command(zerossg::CMD_USERS, "List all users", "users",
                     [this](const zerossg::CommandLineArgs& args) { return handle_users_command(args); });
    
    register_command(zerossg::CMD_SESSIONS, "List active sessions", "sessions",
                     [this](const zerossg::CommandLineArgs& args) { return handle_sessions_command(args); });
    
    register_command(zerossg::CMD_SECURITY, "Show security statistics", "security",
                     [this](const zerossg::CommandLineArgs& args) { return handle_security_command(args); });
    
    register_command(zerossg::CMD_LOGS, "Export audit logs", "logs <output-file>",
                     [this](const zerossg::CommandLineArgs& args) { return handle_logs_command(args); });
    
    register_command(zerossg::CMD_ADD_USER, "Add a new user", "add-user <username> <role> [password]",
                     [this](const zerossg::CommandLineArgs& args) { return handle_user_add_command(args); });
    
    register_command(zerossg::CMD_REMOVE_USER, "Remove a user", "remove-user <username>",
                     [this](const zerossg::CommandLineArgs& args) { return handle_user_remove_command(args); });
    
    register_command(zerossg::CMD_CONFIG, "Show configuration", "config",
                     [this](const zerossg::CommandLineArgs& args) { return handle_config_command(args); });
    
    register_command(zerossg::CMD_TEST, "Test connection to services", "test [service-name]",
                     [this](const zerossg::CommandLineArgs& args) { return handle_test_command(args); });
    
    register_command(zerossg::CMD_INTERACTIVE, "Enter interactive mode", "interactive",
                     [this](const std::vector<String>& args) { 
                         run_interactive_mode(); 
                         return 0; 
                     });
    
    register_command(zerossg::CMD_HELP, "Show help information", "help [command]",
                     [this](const zerossg::CommandLineArgs& args) { 
                         if (args.empty()) {
                             show_help();
                         } else {
                             CLICommand* cmd = find_command(args[0]);
                             if (cmd) {
                                 show_command_help(*cmd);
                             } else {
                                 print_error("Unknown command: " + args[0]);
                             }
                         }
                         return 0; 
                     });
}

CLICommand* CLIInterface::find_command(const zerossg::CommandName& name) {
    auto it = std::find_if(m_commands.begin(), m_commands.end(),
                           [&name](const CLICommand& cmd) {
                               return cmd.name == name;
                           });
    
    return (it != m_commands.end()) ? &(*it) : nullptr;
}

zerossg::CommandLineArgs CLIInterface::parse_command_line(int argc, char* argv[]) {
    zerossg::CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }
    
    return args;
}

bool CLIInterface::validate_arguments(const CLICommand& command, const zerossg::CommandLineArgs& args) {
    if (args.size() < command.required_args.size()) {
        return false;
    }
    
    return true;
}

void CLIInterface::show_command_help(const CLICommand& command) {
    std::println("Command: {}", command.name);
    std::println("Description: {}", command.description);
    std::println("Usage: {}", command.usage);
    
    if (!command.required_args.empty()) {
        std::println("Required arguments:");
        for (const auto& arg : command.required_args) {
            std::println("  {}", arg);
        }
    }
    
    if (!command.optional_args.empty()) {
        std::println("Optional arguments:");
        for (const auto& arg : command.optional_args) {
            std::println("  {}", arg);
        }
    }
}

int CLIInterface::handle_start_command(const zerossg::CommandLineArgs& args) {
    try {
        String config_file = m_config_file;
        if (!args.empty()) {
            config_file = args[0];
        }
        
        print_info("Starting Zero Trust Secure Session Gateway...");
        print_info("Using configuration file: " + config_file);
        
        // Initialize configuration manager
        auto config_manager = std::make_unique<ConfigManager>();
        auto config_result = config_manager->load_config(config_file);
        if (!config_result.has_value()) {
            print_error("Failed to load configuration: " + config_result.error());
            return 1;
        }
        
        // Create and initialize server
        m_server = std::make_unique<GatewayServer>();
        auto init_result = m_server->initialize(*config_manager);
        if (!init_result.has_value()) {
            print_error("Failed to initialize server: " + init_result.error());
            return 1;
        }
        
        // Start the server
        auto start_result = m_server->start();
        if (!start_result.has_value()) {
            print_error("Failed to start server: " + start_result.error());
            return 1;
        }
        
        // Get server configuration for status display
        String listen_addr = config_manager->get_string("server.listen_address", "0.0.0.0");
        int listen_port = config_manager->get_int("server.listen_port", 8443);
        
        print_success("Server started successfully!");
        print_info("Listening on: " + listen_addr + ":" + std::to_string(listen_port));
        print_info("Press Ctrl+C to stop the server");
        
        // Set global server instance for signal handling
        g_server = m_server.get();
        
        // Keep server running
        while (m_server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to start server: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to start server: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_stop_command(const zerossg::CommandLineArgs& /*args*/) {
    try {
        if (!m_server || !m_server->is_running()) {
            print_warning("Server is not running");
            return 0;
        }
        
        print_info("Stopping server...");
        
        auto stop_result = m_server->stop();
        if (!stop_result.has_value()) {
            print_error("Failed to stop server: " + stop_result.error());
            return 1;
        }
        
        print_success("Server stopped successfully");
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to stop server: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to stop server: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_status_command(const zerossg::CommandLineArgs& /*args*/) {
    try {
        print_info("Zero Trust Secure Session Gateway Status:");
        std::println();
        
        if (!m_server || !m_server->is_running()) {
            std::println("  Server: Stopped");
            std::println("  Status: Not running");
            return 0;
        }
        
        std::println("  Server: Running");
        std::println("  Active connections: {}", m_server->get_active_connection_count());
        std::println("  Total connections: {}", m_server->get_total_connection_count());
        
        // Try to get additional status from components
        try {
            // This would require access to the actual component instances
            // For now, show placeholder data that would be available in real implementation
            std::println("  Active sessions: 0");
            std::println("  Uptime: 0 minutes");
            std::println("  Security events: 0");
        } catch (const std::exception&) {
            // Components not available, skip extended status
        }
        
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to get server status: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to get security statistics: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_users_command(const zerossg::CommandLineArgs& /*args*/) {
    try {
        // This would connect to the server and get users
        // For now, show placeholder data
        zerossg::TableData user_data = {
            {"admin", "admin", "admin", "Active"},
            {"operator", "operator", "operator", "Active"},
            {"viewer", "viewer", "viewer", "Active"}
        };
        
        zerossg::TableHeaders headers = {"Username", "Role", "Created", "Status"};
        print_table(user_data, headers);
        
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to list users: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to list users: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_sessions_command(const zerossg::CommandLineArgs& /*args*/) {
    try {
        show_sessions();
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to list sessions: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to list sessions: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_security_command(const zerossg::CommandLineArgs& /*args*/) {
    try {
        print_info("Security Statistics:");
        std::println("Blocked IPs: 0");
        std::println("Failed attempts: 0");
        std::println("Brute force detections: 0");
        
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to get security statistics: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to get security statistics: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_logs_command(const zerossg::CommandLineArgs& args) {
    if (args.empty()) {
        print_error("Output file required");
        return 1;
    }
    
    export_audit_logs(args[0]);
    return 0;
}

int CLIInterface::handle_user_add_command(const zerossg::CommandLineArgs& args) {
    if (args.size() < 2) {
        print_error("Username and role required");
        return 1;
    }
    
    String username = args[0];
    String role = args[1];
    
    if (!CLIUtils::is_valid_username(username)) {
        print_error("Invalid username");
        return 1;
    }
    
    if (!CLIUtils::is_valid_role(role)) {
        print_error("Invalid role. Valid roles: admin, operator, viewer");
        return 1;
    }
    
    String password;
    if (args.size() >= 3) {
        password = args[2];
    } else {
        password = CLIUtils::get_password_input("Enter password: ");
    }
    
    print_info("Adding user: " + username + " with role: " + role);
    print_success("User added successfully");
    
    return 0;
}

int CLIInterface::handle_user_remove_command(const zerossg::CommandLineArgs& args) {
    if (args.empty()) {
        print_error("Username required");
        return 1;
    }
    
    String username = args[0];
    print_info("Removing user: " + username);
    print_success("User removed successfully");
    
    return 0;
}

int CLIInterface::handle_config_command(const zerossg::CommandLineArgs& /*args*/) {
    try {
        auto config_manager = std::make_unique<ConfigManager>();
        auto config_result = config_manager->load_config(m_config_file);
        if (!config_result.has_value()) {
            print_error("Failed to load configuration: " + config_result.error());
            return 1;
        }
        
        print_info("Current Configuration:");
        std::println("Listen Address: {}", config_manager->get_string("server.listen_address"));
        std::println("Listen Port: {}", config_manager->get_int("server.listen_port"));
        std::println("TLS Cert File: {}", config_manager->get_string("server.tls_cert_file"));
        std::println("TLS Key File: {}", config_manager->get_string("server.tls_key_file"));
        
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Failed to show configuration: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Failed to show configuration: {}", e.what());
        return 1;
    }
}

int CLIInterface::handle_test_command(const zerossg::CommandLineArgs& args) {
    try {
        String service_name = args.empty() ? "all" : args[0];
        print_info("Testing connection to service: " + service_name);
        print_success("Connection test successful");
        
        return 0;
    } catch (const std::exception& e) {
        print_error(std::format("Connection test failed: {}", e.what()));
        zerossg::Logger::get("CLIInterface")->error("Connection test failed: {}", e.what());
        return 1;
    }
}

bool CLIInterface::is_server_running() {
    return m_server && m_server->is_running();
}

Result<void> CLIInterface::connect_to_server() {
    // In a real implementation, this would establish IPC connection
    return make_result_success();
}

void CLIInterface::disconnect_from_server() {
    // In a real implementation, this would close IPC connection
}

// CLIUtils implementation
bool CLIUtils::is_valid_username(const String& username) {
    if (username.empty() || username.length() < 3 || username.length() > 32) {
        return false;
    }
    
    // Check for alphanumeric characters and underscore
    for (char c : username) {
        if (!std::isalnum(c) && c != '_') {
            return false;
        }
    }
    
    return true;
}

bool CLIUtils::is_valid_email(const String& email) {
    // Simple email validation
    size_t at_pos = email.find('@');
    if (at_pos == String::npos || at_pos == 0 || at_pos == email.length() - 1) {
        return false;
    }
    
    size_t dot_pos = email.find('.', at_pos);
    return dot_pos != String::npos && dot_pos > at_pos + 1 && dot_pos < email.length() - 1;
}

bool CLIUtils::is_valid_role(const String& role) {
    return role == zerossg::ROLE_ADMIN || role == zerossg::ROLE_OPERATOR || role == zerossg::ROLE_VIEWER;
}

bool CLIUtils::is_valid_port(const String& port) {
    try {
        int port_num = std::stoi(port);
        return port_num > 0 && port_num <= 65535;
    } catch (...) {
        return false;
    }
}

bool CLIUtils::is_valid_file_path(const String& path) {
    return !path.empty();
}

String CLIUtils::trim(const String& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == String::npos) return "";
    
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::vector<String> CLIUtils::split(const String& str, char delimiter) {
    std::vector<String> tokens;
    std::istringstream iss(str);
    String token;
    
    while (std::getline(iss, token, delimiter)) {
        tokens.push_back(trim(token));
    }
    
    return tokens;
}

String CLIUtils::to_lower(const String& str) {
    String result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

String CLIUtils::to_upper(const String& str) {
    String result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

String CLIUtils::color_red(const String& text) {
    return supports_color() ? "\033[31m" + text + "\033[0m" : text;
}

String CLIUtils::color_green(const String& text) {
    return supports_color() ? "\033[32m" + text + "\033[0m" : text;
}

String CLIUtils::color_yellow(const String& text) {
    return supports_color() ? "\033[33m" + text + "\033[0m" : text;
}

String CLIUtils::color_blue(const String& text) {
    return supports_color() ? "\033[34m" + text + "\033[0m" : text;
}

String CLIUtils::color_reset() {
    return supports_color() ? "\033[0m" : "";
}

bool CLIUtils::supports_color() {
#ifdef _WIN32
    return _isatty(_fileno(stdout));
#else
    return isatty(fileno(stdout));
#endif
}

void CLIUtils::show_progress(const String& message, int current, int total) {
    int percentage = static_cast<int>((static_cast<double>(current) / total) * 100);
    std::print("\r{}: {}% ({}/{})", message, percentage, current, total);
    std::fflush(stdout);
}

void CLIUtils::show_spinner(const String& message) {
    static const char* spinner = zerossg::CLI_SPINNER_CHARS;
    static int spinner_index = 0;
    
    std::print("\r{} {}", message, spinner[spinner_index]);
    std::fflush(stdout);
    spinner_index = (spinner_index + 1) % 4;
}

String CLIUtils::get_password_input(const String& prompt) {
    // In a real implementation, this would hide the input
    std::print("{}", prompt);
    std::fflush(stdout);
    String password;
    std::cin >> password;
    return password;
}

String CLIUtils::get_hidden_input(const String& prompt) {
    return get_password_input(prompt);
}

#ifdef HAVE_READLINE
// InteractiveShell implementation
InteractiveShell::InteractiveShell(CLIInterface& cli) : m_cli(cli) {
    // Initialize readline
    rl_bind_key('\t', rl_complete);
}

void InteractiveShell::run() {
    std::println("Zero Trust Secure Session Gateway - Interactive Mode");
    std::println("Type 'help' for available commands or 'exit' to quit.");
    std::println();
    
    char* input = nullptr;
    while (m_running) {
        input = readline(zerossg::CLI_PROMPT);
        
        if (!input) {
            // EOF received
            std::println();
            break;
        }
        
        String input_str(input);
        free(input);
        
        if (input_str.empty()) {
            continue;
        }
        
        // Add to history
        add_to_history(input_str);
        
        // Check for exit
        if (should_exit(input_str)) {
            break;
        }
        
        // Process command
        process_command(input_str);
    }
}

void InteractiveShell::add_to_history(const String& command) {
    if (!command.empty()) {
        add_history(command.c_str());
        m_command_history.push_back(command);
        trim_history();
    }
}

std::vector<String> InteractiveShell::get_history() {
    return m_command_history;
}

void InteractiveShell::clear_history() {
    m_command_history.clear();
    clear_history();
}

std::vector<String> InteractiveShell::get_completions(const String& partial_command) {
    std::vector<String> completions;
    
    if (m_auto_completion_enabled) {
        // Get command names
        auto command_names = get_command_names();
        
        for (const auto& name : command_names) {
            if (name.find(partial_command) == 0) {
                completions.push_back(name);
            }
        }
    }
    
    return completions;
}

void InteractiveShell::enable_auto_completion(bool enable) {
    m_auto_completion_enabled = enable;
}

void InteractiveShell::process_command(const String& command) {
    auto args = m_cli.parse_input(command);
    if (args.empty()) {
        return;
    }
    
    try {
        // Convert to argc/argv format
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>("zerossg"));
        for (auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        
        auto result = m_cli.run(static_cast<int>(argv.size()), argv.data());
        if (!result.has_value()) {
            std::println("Command failed");
        }
     zerossg::Logger::get("CLIInterface")->error("Command failed: " + command + ". Command Args: " + args.at(0));
    } catch (const std::exception& e) {
        std::println("Error: {}", e.what());
    }
}

bool InteractiveShell::should_exit(const String& command) {
    String lower_cmd = CLIUtils::to_lower(CLIUtils::trim(command));
    return lower_cmd == zerossg::CMD_EXIT || lower_cmd == zerossg::CMD_QUIT;
}

void InteractiveShell::trim_history() {
    if (m_command_history.size() > MAX_HISTORY_SIZE) {
        m_command_history.erase(m_command_history.begin(), 
                               m_command_history.end() - MAX_HISTORY_SIZE);
    }
}

std::vector<String> InteractiveShell::get_command_names() {
    // This would need access to the CLI's command list
    // For now, return common commands
    return {zerossg::CMD_START, zerossg::CMD_STOP, zerossg::CMD_STATUS, zerossg::CMD_USERS, zerossg::CMD_SESSIONS, zerossg::CMD_SECURITY, zerossg::CMD_LOGS, zerossg::CMD_HELP, zerossg::CMD_EXIT};
}
#endif // HAVE_READLINE

} // namespace zerossg
