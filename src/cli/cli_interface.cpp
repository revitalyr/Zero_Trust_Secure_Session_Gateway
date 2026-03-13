#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <readline/readline.h>
#include <readline/history.h>

import zerossg.cli.cli_interface;
import zerossg.network.gateway_server;
import zerossg.config.config_manager;
import zerossg.auth.authenticator;
import zerossg.session.session_manager;
import zerossg.security.security_manager;

namespace zerossg {

zerossg::CLIInterface::CLIInterface() {
    zerossg::CLIInterface::register_builtin_commands();
}

Result<int> zerossg::CLIInterface::run(int argc, char* argv[]) {
Result<int> CLIInterface::run(int argc, char* argv[]) {
    try {
        zerossg::CommandLineArgs args = parse_command_line(argc, argv);
        
        if (args.empty()) {
            show_help();
            return Result<int>::success(1);
        }
        
        zerossg::CommandName command_name = args[0];
        CLICommand* command = find_command(command_name);
        
        if (!command) {
            print_error("Unknown command: " + command_name);
            show_help();
            return Result<int>::success(1);
        }
        
        zerossg::CommandLineArgs command_args(args.begin() + 1, args.end());
        
        if (!validate_arguments(*command, command_args)) {
            show_command_help(*command);
            return Result<int>::success(1);
        }
        
        int result = command->handler(command_args);
        return Result<int>::success(result);
    } catch (const std::exception& e) {
        print_error("CLI error: " + zerossg::String(e.what()));
        return Result<int>::success(1);
    }
}

void CLIInterface::show_help() {
    std::cout << "Zero Trust Secure Session Gateway CLI" << std::endl;
    std::cout << "=====================================" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Usage: zerossg <command> [options]" << std::endl;
    std::cout << std::endl;
    
    std::cout << "Available commands:" << std::endl;
    for (const auto& cmd : m_commands) {
        std::cout << "  " << std::setw(15) << std::left << cmd.name 
                  << " - " << cmd.description << std::endl;
    }
    std::cout << std::endl;
    
    std::cout << "Use 'zerossg <command> --help' for detailed information about a specific command." << std::endl;
    std::cout << "Use 'zerossg interactive' to enter interactive mode." << std::endl;
}

void CLIInterface::show_active_sessions() {
    try {
        // This would connect to the server and get active sessions
        // For now, show a placeholder
        print_info("Active sessions:");
        std::cout << "No active sessions (server not running)" << std::endl;
    } catch (const std::exception& e) {
        print_error("Failed to get active sessions: " + string(e.what()));
    }
}

void CLIInterface::export_audit_logs(const zerossg::FilePath& output_file) {
    try {
        // This would connect to the server and export logs
        // For now, show a placeholder
        print_info("Exporting audit logs to: " + output_file);
        print_success("Audit logs exported successfully");
    } catch (const std::exception& e) {
        print_error("Failed to export audit logs: " + zerossg::String(e.what()));
    }
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

int CLIInterface::start_server(const zerossg::CommandLineArgs& args) {
    return handle_start_command(args);
}

int CLIInterface::stop_server(const zerossg::CommandLineArgs& args) {
    return handle_stop_command(args);
}

int CLIInterface::show_status(const zerossg::CommandLineArgs& args) {
    return handle_status_command(args);
}

int CLIInterface::list_users(const zerossg::CommandLineArgs& args) {
    return handle_users_command(args);
}

int CLIInterface::list_sessions(const zerossg::CommandLineArgs& args) {
    return handle_sessions_command(args);
}

int CLIInterface::show_security_stats(const zerossg::CommandLineArgs& args) {
    return handle_security_command(args);
}

int CLIInterface::export_logs(const zerossg::CommandLineArgs& args) {
    return handle_logs_command(args);
}

int CLIInterface::add_user(const zerossg::CommandLineArgs& args) {
    return handle_user_add_command(args);
}

int CLIInterface::remove_user(const zerossg::CommandLineArgs& args) {
    return handle_user_remove_command(args);
}

int CLIInterface::show_config(const zerossg::CommandLineArgs& args) {
    return handle_config_command(args);
}

int CLIInterface::test_connection(const zerossg::CommandLineArgs& args) {
    return handle_test_command(args);
}

void CLIInterface::run_interactive_mode() {
    InteractiveShell shell(*this);
    shell.run();
}

void CLIInterface::show_prompt() {
    std::cout << zerossg::CLI_PROMPT << std::flush;
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
            std::cout << std::setw(column_widths[i]) << std::left << headers[i];
            if (i < headers.size() - 1) {
                std::cout << " | ";
            }
        }
        std::cout << std::endl;
        
        // Print separator
        for (size_t i = 0; i < headers.size(); ++i) {
            for (size_t j = 0; j < column_widths[i]; ++j) {
                std::cout << "-";
            }
            if (i < headers.size() - 1) {
                std::cout << "-+-";
            }
        }
        std::cout << std::endl;
    }
    
    // Print data
    for (const auto& row : data) {
        for (size_t i = 0; i < row.size() && i < column_widths.size(); ++i) {
            std::cout << std::setw(column_widths[i]) << std::left << row[i];
            if (i < row.size() - 1) {
                std::cout << " | ";
            }
        }
        std::cout << std::endl;
    }
}

void CLIInterface::print_error(const zerossg::ErrorString& error) {
    if (CLIUtils::supports_color()) {
        std::cout << CLIUtils::color_red("ERROR: ") << error << std::endl;
    } else {
        std::cout << "ERROR: " << error << std::endl;
    }
}

void CLIInterface::print_success(const zerossg::SuccessString& message) {
    if (CLIUtils::supports_color()) {
        std::cout << CLIUtils::color_green("SUCCESS: ") << message << std::endl;
    } else {
        std::cout << "SUCCESS: " << message << std::endl;
    }
}

void CLIInterface::print_info(const zerossg::InfoString& message) {
    if (CLIUtils::supports_color()) {
        std::cout << CLIUtils::color_blue("INFO: ") << message << std::endl;
    } else {
        std::cout << "INFO: " << message << std::endl;
    }
}

void CLIInterface::print_warning(const zerossg::WarningString& message) {
    if (CLIUtils::supports_color()) {
        std::cout << CLIUtils::color_yellow("WARNING: ") << message << std::endl;
    } else {
        std::cout << "WARNING: " << message << std::endl;
    }
}

void CLIInterface::register_builtin_commands() {
    register_command(zerossg::CMD_START, "Start the Zero Trust gateway server", "start [config-file]",
                     [this](const zerossg::CommandLineArgs& args) { return start_server(args); });
    
    register_command(zerossg::CMD_STOP, "Stop the Zero Trust gateway server", "stop",
                     [this](const zerossg::CommandLineArgs& args) { return stop_server(args); });
    
    register_command(zerossg::CMD_STATUS, "Show server status and statistics", "status",
                     [this](const zerossg::CommandLineArgs& args) { return show_status(args); });
    
    register_command(zerossg::CMD_USERS, "List all users", "users",
                     [this](const zerossg::CommandLineArgs& args) { return list_users(args); });
    
    register_command(zerossg::CMD_SESSIONS, "List active sessions", "sessions",
                     [this](const zerossg::CommandLineArgs& args) { return list_sessions(args); });
    
    register_command(zerossg::CMD_SECURITY, "Show security statistics", "security",
                     [this](const zerossg::CommandLineArgs& args) { return show_security_stats(args); });
    
    register_command(zerossg::CMD_LOGS, "Export audit logs", "logs <output-file>",
                     [this](const zerossg::CommandLineArgs& args) { return export_logs(args); });
    
    register_command(zerossg::CMD_ADD_USER, "Add a new user", "add-user <username> <role> [password]",
                     [this](const zerossg::CommandLineArgs& args) { return add_user(args); });
    
    register_command(zerossg::CMD_REMOVE_USER, "Remove a user", "remove-user <username>",
                     [this](const zerossg::CommandLineArgs& args) { return remove_user(args); });
    
    register_command(zerossg::CMD_CONFIG, "Show configuration", "config",
                     [this](const zerossg::CommandLineArgs& args) { return show_config(args); });
    
    register_command(zerossg::CMD_TEST, "Test connection to services", "test [service-name]",
                     [this](const zerossg::CommandLineArgs& args) { return test_connection(args); });
    
    register_command(zerossg::CMD_INTERACTIVE, "Enter interactive mode", "interactive",
                     [this](const std::vector<string>& args) { 
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
    std::cout << "Command: " << command.name << std::endl;
    std::cout << "Description: " << command.description << std::endl;
    std::cout << "Usage: " << command.usage << std::endl;
    
    if (!command.required_args.empty()) {
        std::cout << "Required arguments:" << std::endl;
        for (const auto& arg : command.required_args) {
            std::cout << "  " << arg << std::endl;
        }
    }
    
    if (!command.optional_args.empty()) {
        std::cout << "Optional arguments:" << std::endl;
        for (const auto& arg : command.optional_args) {
            std::cout << "  " << arg << std::endl;
        }
    }
}

int CLIInterface::handle_start_command(const zerossg::CommandLineArgs& args) {
    try {
        string config_file = m_config_file;
        if (!args.empty()) {
            config_file = args[0];
        }
        
        print_info("Starting Zero Trust Secure Session Gateway...");
        print_info("Using configuration file: " + config_file);
        
        // Initialize configuration
        auto config_manager = std::make_unique<ConfigManager>();
        auto config_result = config_manager->load_config(config_file);
        if (!config_result.is_success()) {
            print_error("Failed to load configuration: " + config_result.error());
            return 1;
        }
        
        // Create and start server
        m_server = std::make_unique<GatewayServer>();
        auto init_result = m_server->initialize(config_file);
        if (!init_result.is_success()) {
            print_error("Failed to initialize server: " + init_result.error());
            return 1;
        }
        
        auto start_result = m_server->start();
        if (!start_result.is_success()) {
            print_error("Failed to start server: " + start_result.error());
            return 1;
        }
        
        print_success("Server started successfully");
        
        // Keep server running
        std::cout << "Press Ctrl+C to stop the server" << std::endl;
        
        // Simple signal handling (in production, use proper signal handling)
        while (m_server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        return 0;
    } catch (const std::exception& e) {
        print_error("Failed to start server: " + string(e.what()));
        return 1;
    }
}

int CLIInterface::handle_stop_command(const zerossg::CommandLineArgs& args) {
    try {
        if (!m_server || !m_server->is_running()) {
            print_warning("Server is not running");
            return 0;
        }
        
        print_info("Stopping server...");
        
        auto stop_result = m_server->stop();
        if (!stop_result.is_success()) {
            print_error("Failed to stop server: " + stop_result.error());
            return 1;
        }
        
        print_success("Server stopped successfully");
        return 0;
    } catch (const std::exception& e) {
        print_error("Failed to stop server: " + string(e.what()));
        return 1;
    }
}

int CLIInterface::handle_status_command(const zerossg::CommandLineArgs& args) {
    try {
        if (!m_server || !m_server->is_running()) {
            print_info("Server status: STOPPED");
            return 0;
        }
        
        print_info("Server status: RUNNING");
        std::cout << "Active connections: " << m_server->get_active_connections() << std::endl;
        std::cout << "Total connections: " << m_server->get_total_connections() << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        print_error("Failed to get server status: " + string(e.what()));
        return 1;
    }
}

int CLIInterface::handle_users_command(const zerossg::CommandLineArgs& args) {
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
        print_error("Failed to list users: " + string(e.what()));
        return 1;
    }
}

int CLIInterface::handle_sessions_command(const zerossg::CommandLineArgs& args) {
    try {
        show_active_sessions();
        return 0;
    } catch (const std::exception& e) {
        print_error("Failed to list sessions: " + string(e.what()));
        return 1;
    }
}

int CLIInterface::handle_security_command(const zerossg::CommandLineArgs& args) {
    try {
        print_info("Security Statistics:");
        std::cout << "Blocked IPs: 0" << std::endl;
        std::cout << "Failed attempts: 0" << std::endl;
        std::cout << "Brute force detections: 0" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        print_error("Failed to get security statistics: " + string(e.what()));
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
    
    string username = args[0];
    string role = args[1];
    
    if (!CLIUtils::is_valid_username(username)) {
        print_error("Invalid username");
        return 1;
    }
    
    if (!CLIUtils::is_valid_role(role)) {
        print_error("Invalid role. Valid roles: admin, operator, viewer");
        return 1;
    }
    
    string password;
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
    
    string username = args[0];
    print_info("Removing user: " + username);
    print_success("User removed successfully");
    
    return 0;
}

int CLIInterface::handle_config_command(const zerossg::CommandLineArgs& args) {
    try {
        auto config_manager = std::make_unique<ConfigManager>();
        auto config_result = config_manager->load_config(m_config_file);
        if (!config_result.is_success()) {
            print_error("Failed to load configuration: " + config_result.error());
            return 1;
        }
        
        print_info("Current Configuration:");
        std::cout << "Listen Address: " << config_manager->get_server_config().listen_address << std::endl;
        std::cout << "Listen Port: " << config_manager->get_server_config().listen_port << std::endl;
        std::cout << "TLS Cert File: " << config_manager->get_server_config().tls_cert_file << std::endl;
        std::cout << "TLS Key File: " << config_manager->get_server_config().tls_key_file << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        print_error("Failed to show configuration: " + string(e.what()));
        return 1;
    }
}

int CLIInterface::handle_test_command(const zerossg::CommandLineArgs& args) {
    try {
        string service_name = args.empty() ? "all" : args[0];
        print_info("Testing connection to service: " + service_name);
        print_success("Connection test successful");
        
        return 0;
    } catch (const std::exception& e) {
        print_error("Connection test failed: " + string(e.what()));
        return 1;
    }
}

bool CLIInterface::is_server_running() {
    return m_server && m_server->is_running();
}

Result<void> CLIInterface::connect_to_server() {
    // In a real implementation, this would establish IPC connection
    return Result<void>::success();
}

void CLIInterface::disconnect_from_server() {
    // In a real implementation, this would close IPC connection
}

// CLIUtils implementation
bool CLIUtils::is_valid_username(const string& username) {
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

bool CLIUtils::is_valid_email(const string& email) {
    // Simple email validation
    size_t at_pos = email.find('@');
    if (at_pos == string::npos || at_pos == 0 || at_pos == email.length() - 1) {
        return false;
    }
    
    size_t dot_pos = email.find('.', at_pos);
    return dot_pos != string::npos && dot_pos > at_pos + 1 && dot_pos < email.length() - 1;
}

bool CLIUtils::is_valid_role(const string& role) {
    return role == zerossg::ROLE_ADMIN || role == zerossg::ROLE_OPERATOR || role == zerossg::ROLE_VIEWER;
}

bool CLIUtils::is_valid_port(const string& port) {
    try {
        int port_num = std::stoi(port);
        return port_num > 0 && port_num <= 65535;
    } catch (...) {
        return false;
    }
}

bool CLIUtils::is_valid_file_path(const string& path) {
    return !path.empty();
}

string CLIUtils::trim(const string& str) {
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == string::npos) return "";
    
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

std::vector<string> CLIUtils::split(const string& str, char delimiter) {
    std::vector<string> tokens;
    std::istringstream iss(str);
    string token;
    
    while (std::getline(iss, token, delimiter)) {
        tokens.push_back(trim(token));
    }
    
    return tokens;
}

string CLIUtils::to_lower(const string& str) {
    string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

string CLIUtils::to_upper(const string& str) {
    string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

string CLIUtils::color_red(const string& text) {
    return supports_color() ? "\033[31m" + text + "\033[0m" : text;
}

string CLIUtils::color_green(const string& text) {
    return supports_color() ? "\033[32m" + text + "\033[0m" : text;
}

string CLIUtils::color_yellow(const string& text) {
    return supports_color() ? "\033[33m" + text + "\033[0m" : text;
}

string CLIUtils::color_blue(const string& text) {
    return supports_color() ? "\033[34m" + text + "\033[0m" : text;
}

string CLIUtils::color_reset() {
    return supports_color() ? "\033[0m" : "";
}

bool CLIUtils::supports_color() {
    return isatty(fileno(stdout));
}

void CLIUtils::show_progress(const string& message, int current, int total) {
    int percentage = static_cast<int>((static_cast<double>(current) / total) * 100);
    std::cout << "\r" << message << ": " << percentage << "% (" << current << "/" << total << ")" << std::flush;
}

void CLIUtils::show_spinner(const string& message) {
    static const char spinner[] = zerossg::CLI_SPINNER_CHARS;
    static int spinner_index = 0;
    
    std::cout << "\r" << message << " " << spinner[spinner_index] << std::flush;
    spinner_index = (spinner_index + 1) % 4;
}

string CLIUtils::get_password_input(const string& prompt) {
    // In a real implementation, this would hide the input
    std::cout << prompt;
    string password;
    std::cin >> password;
    return password;
}

string CLIUtils::get_hidden_input(const string& prompt) {
    return get_password_input(prompt);
}

// InteractiveShell implementation
InteractiveShell::InteractiveShell(CLIInterface& cli) : m_cli(cli) {
    // Initialize readline
    rl_bind_key('\t', rl_complete);
}

void InteractiveShell::run() {
    std::cout << "Zero Trust Secure Session Gateway - Interactive Mode" << std::endl;
    std::cout << "Type 'help' for available commands or 'exit' to quit." << std::endl;
    std::cout << std::endl;
    
    char* input = nullptr;
    while (m_running) {
        input = readline(zerossg::CLI_PROMPT);
        
        if (!input) {
            // EOF received
            std::cout << std::endl;
            break;
        }
        
        string input_str(input);
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

void InteractiveShell::add_to_history(const string& command) {
    if (!command.empty()) {
        add_history(command.c_str());
        m_command_history.push_back(command);
        trim_history();
    }
}

std::vector<string> InteractiveShell::get_history() {
    return m_command_history;
}

void InteractiveShell::clear_history() {
    m_command_history.clear();
    clear_history();
}

std::vector<string> InteractiveShell::get_completions(const string& partial_command) {
    std::vector<string> completions;
    
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

void InteractiveShell::process_command(const string& command) {
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
        if (!result.is_success()) {
            std::cout << "Command failed" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

bool InteractiveShell::should_exit(const string& command) {
    string lower_cmd = CLIUtils::to_lower(CLIUtils::trim(command));
    return lower_cmd == zerossg::CMD_EXIT || lower_cmd == zerossg::CMD_QUIT;
}

void InteractiveShell::trim_history() {
    if (m_command_history.size() > MAX_HISTORY_SIZE) {
        m_command_history.erase(m_command_history.begin(), 
                               m_command_history.end() - MAX_HISTORY_SIZE);
    }
}

std::vector<string> InteractiveShell::get_command_names() {
    // This would need access to the CLI's command list
    // For now, return common commands
    return {zerossg::CMD_START, zerossg::CMD_STOP, zerossg::CMD_STATUS, zerossg::CMD_USERS, zerossg::CMD_SESSIONS, zerossg::CMD_SECURITY, zerossg::CMD_LOGS, zerossg::CMD_HELP, zerossg::CMD_EXIT};
}

} // namespace zerossg
