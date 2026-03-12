#pragma once

#include "zerossg/common.hpp"
#include "zerossg/types.hpp"
#include "zerossg/constants.hpp"
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <unordered_map>
#include <mutex>

namespace zerossg {

struct ServerConfig {
    HostAddress listen_address{DEFAULT_LISTEN_ADDRESS};
    PortNo listen_port{DEFAULT_LISTEN_PORT};
    FileName tls_cert_file{DEFAULT_TLS_CERT_FILE};
    FileName tls_key_file{DEFAULT_TLS_KEY_FILE};
    FileName ca_cert_file{DEFAULT_CA_CERT_FILE};
    Count thread_count{DEFAULT_THREAD_COUNT}; // 0 = auto-detect
    bool verify_client_certificates{false};
    std::string cipher_list{DEFAULT_CIPHER_LIST};
};

struct SecurityConfig {
    RateLimit rate_limit_max_requests{DEFAULT_RATE_LIMIT_MAX_REQUESTS};
    Minutes rate_limit_window{DEFAULT_RATE_LIMIT_WINDOW}; // 5 minutes
    Threshold brute_force_threshold{DEFAULT_BRUTE_FORCE_THRESHOLD};
    Minutes brute_force_window{DEFAULT_BRUTE_FORCE_WINDOW}; // 15 minutes
    Milliseconds default_block_duration{DEFAULT_BLOCK_DURATION};
    bool enable_ip_whitelist{false};
    Strings allowed_ips;
    bool enable_ip_blacklist{false};
    Strings blocked_ips;
};

struct SessionConfig {
    Hours default_timeout{DEFAULT_SESSION_TIMEOUT};
    SessionCount max_sessions_per_user{DEFAULT_MAX_SESSIONS_PER_USER};
    Minutes cleanup_interval{DEFAULT_CLEANUP_INTERVAL};
    bool enable_session_persistence{false};
    ConfigFileName persistence_file{DEFAULT_PERSISTENCE_FILE};
};

struct LoggingConfig {
    std::string level{DEFAULT_LOG_LEVEL};
    std::string pattern{DEFAULT_LOG_PATTERN};
    bool enable_console_output{true};
    bool enable_file_output{true};
    LogFileName log_file{DEFAULT_LOG_FILE};
    Count max_file_size{DEFAULT_MAX_FILE_SIZE};
    Count max_files{DEFAULT_MAX_FILES};
    bool enable_security_log{true};
    LogFileName security_log_file{DEFAULT_SECURITY_LOG_FILE};
    bool enable_audit_log{true};
    LogFileName audit_log_file{DEFAULT_AUDIT_LOG_FILE};
};

struct DatabaseConfig {
    DbType type{DEFAULT_DB_TYPE}; // memory, file, sqlite, postgresql
    ConnectionString connection_string{DEFAULT_CONNECTION_STRING};
    UserName username{DEFAULT_DB_USERNAME};
    Password password{DEFAULT_DB_PASSWORD};
    bool enable_ssl{false};
    Count connection_pool_size{DEFAULT_CONNECTION_POOL_SIZE};
    Seconds connection_timeout{DEFAULT_CONNECTION_TIMEOUT};
};

class ConfigManager : public IConfigManager {
public:
    ConfigManager();
    ~ConfigManager() override = default;
    
    // IConfigManager interface
    Result<void> load_config(const std::string& config_file) override;
    std::string get_string(const std::string& key, const std::string& default_value = "") override;
    int get_int(const std::string& key, int default_value = 0) override;
    bool get_bool(const std::string& key, bool default_value = false) override;
    Strings get_string_array(const std::string& key) override;
    Result<TargetService> get_target_service(const ServiceName& service_name) override;
    Result<std::vector<TargetService>> get_all_target_services() override;
    
    // Configuration accessors
    const ServerConfig& get_server_config() const { return m_server_config; }
    const SecurityConfig& get_security_config() const { return m_security_config; }
    const SessionConfig& get_session_config() const { return m_session_config; }
    const LoggingConfig& get_logging_config() const { return m_logging_config; }
    const DatabaseConfig& get_database_config() const { return m_database_config; }
    
    // Configuration validation
    Result<void> validate_config();
    
    // Configuration management
    Result<void> save_config(const std::string& config_file);
    Result<void> reload_config();
    
    // Environment variable support
    void load_from_environment();
    std::string get_env_var(const std::string& key, const std::string& default_value = "");
    
private:
    // Configuration data
    ServerConfig m_server_config;
    SecurityConfig m_security_config;
    SessionConfig m_session_config;
    LoggingConfig m_logging_config;
    DatabaseConfig m_database_config;
    
    // Target services
    std::unordered_map<ServiceName, TargetService> m_target_services;
    
    // Raw configuration data
    nlohmann::json m_config_json;
    mutable std::mutex m_config_mutex;
    
    // Helper methods
    Result<void> load_yaml_config(const std::string& config_file);
    Result<void> load_json_config(const std::string& config_file);
    
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
