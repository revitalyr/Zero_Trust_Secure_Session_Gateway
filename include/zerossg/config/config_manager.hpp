#pragma once

#include "zerossg/interfaces.hpp"
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <string>
#include <unordered_map>
#include <mutex>

namespace zerossg {

struct ServerConfig {
    string listen_address{"0.0.0.0"};
    uint16_t listen_port{8443};
    string tls_cert_file{"server.crt"};
    string tls_key_file{"server.key"};
    string ca_cert_file{""};
    size_t thread_count{0}; // 0 = auto-detect
    bool verify_client_certificates{false};
    string cipher_list{"HIGH:!aNULL:!MD5:!RC4"};
};

struct SecurityConfig {
    size_t rate_limit_max_requests{100};
    seconds rate_limit_window{300}; // 5 minutes
    size_t brute_force_threshold{5};
    seconds brute_force_window{900}; // 15 minutes
    milliseconds default_block_duration{3600000}; // 1 hour
    bool enable_ip_whitelist{false};
    std::vector<string> allowed_ips;
    bool enable_ip_blacklist{false};
    std::vector<string> blocked_ips;
};

struct SessionConfig {
    seconds default_timeout{3600}; // 1 hour
    size_t max_sessions_per_user{5};
    seconds cleanup_interval{300}; // 5 minutes
    bool enable_session_persistence{false};
    string persistence_file{"sessions.json"};
};

struct LoggingConfig {
    string level{"info"};
    string pattern{"[%Y-%m-%d %H:%M:%S.%e] [%l] %v"};
    bool enable_console_output{true};
    bool enable_file_output{true};
    string log_file{"logs/zerossg.log"};
    size_t max_file_size{5 * 1024 * 1024}; // 5MB
    size_t max_files{3};
    bool enable_security_log{true};
    string security_log_file{"logs/security.log"};
    bool enable_audit_log{true};
    string audit_log_file{"logs/audit.log"};
};

struct DatabaseConfig {
    string type{"memory"}; // memory, file, sqlite, postgresql
    string connection_string{"localhost:5432/zerossg"};
    string username{"zerossg"};
    string password{""};
    bool enable_ssl{false};
    int connection_pool_size{10};
    seconds connection_timeout{30};
};

class ConfigManager : public IConfigManager {
public:
    ConfigManager();
    ~ConfigManager() override = default;
    
    // IConfigManager interface
    Result<void> load_config(const string& config_file) override;
    string get_string(const string& key, const string& default_value = "") override;
    int get_int(const string& key, int default_value = 0) override;
    bool get_bool(const string& key, bool default_value = false) override;
    vector<string> get_string_array(const string& key) override;
    Result<TargetService> get_target_service(const string& service_name) override;
    Result<vector<TargetService>> get_all_target_services() override;
    
    // Configuration accessors
    const ServerConfig& get_server_config() const { return m_server_config; }
    const SecurityConfig& get_security_config() const { return m_security_config; }
    const SessionConfig& get_session_config() const { return m_session_config; }
    const LoggingConfig& get_logging_config() const { return m_logging_config; }
    const DatabaseConfig& get_database_config() const { return m_database_config; }
    
    // Configuration validation
    Result<void> validate_config();
    
    // Configuration management
    Result<void> save_config(const string& config_file);
    Result<void> reload_config();
    
    // Environment variable support
    void load_from_environment();
    string get_env_var(const string& key, const string& default_value = "");
    
private:
    // Configuration data
    ServerConfig m_server_config;
    SecurityConfig m_security_config;
    SessionConfig m_session_config;
    LoggingConfig m_logging_config;
    DatabaseConfig m_database_config;
    
    // Target services
    unordered_map<string, TargetService> m_target_services;
    
    // Raw configuration data
    nlohmann::json m_config_json;
    mutable std::mutex m_config_mutex;
    
    // Helper methods
    Result<void> load_yaml_config(const string& config_file);
    Result<void> load_json_config(const string& config_file);
    
    void parse_server_config(const nlohmann::json& config);
    void parse_security_config(const nlohmann::json& config);
    void parse_session_config(const nlohmann::json& config);
    void parse_logging_config(const nlohmann::json& config);
    void parse_database_config(const nlohmann::json& config);
    void parse_target_services(const nlohmann::json& config);
    
    Result<TargetService> parse_target_service(const nlohmann::json& service_json);
    
    // Configuration validation helpers
    Result<void> validate_server_config();
    Result<void> validate_security_config();
    Result<void> validate_session_config();
    Result<void> validate_logging_config();
    Result<void> validate_database_config();
    Result<void> validate_target_services();
    
    // Utility methods
    string get_config_value(const string& key, const string& default_value = "");
    bool file_exists(const string& filename);
    string get_file_extension(const string& filename);
    
    // Default configuration
    void set_default_config();
    nlohmann::json get_default_config_json();
};

// Configuration utilities
class ConfigUtils {
public:
    // Environment variable mapping
    static string map_env_var(const string& config_key);
    
    // Configuration validation
    static bool is_valid_port(int port);
    static bool is_valid_ip_address(const string& ip);
    static bool is_valid_log_level(const string& level);
    static bool is_valid_timeout(seconds timeout);
    
    // Configuration conversion
    static seconds parse_duration(const string& duration_str);
    static string format_duration(seconds duration);
    static vector<string> parse_string_array(const nlohmann::json& json_array);
    static nlohmann::json serialize_string_array(const vector<string>& array);
    
    // File operations
    static Result<string> read_file(const string& filename);
    static Result<void> write_file(const string& filename, const string& content);
    static bool create_directory(const string& path);
};

} // namespace zerossg
