#pragma once

// C++23 module imports
import zerossg.common;
import zerossg.types;
import zerossg.constants;

// Third-party library imports
import <nlohmann/json.hpp>;
import <yaml-cpp/yaml.h>;

// Standard library imports
import zerossg.std;

namespace zerossg {

// Import semantic aliases for type visibility
using zerossg::Result;
using zerossg::String;
using zerossg::Strings;
using zerossg::ServiceName;
using zerossg::ConfigFileName;
using zerossg::TargetService;

// Import standard library types for clarity
using std::string;
using std::vector;
using std::unordered_map;
using std::ifstream;
using std::ofstream;
using std::filesystem;
using std::exception;
using std::to_string;
using std::stoi;
using std::transform;
using std::tolower;
using std::getenv;
using std::count;
using std::istringstream;
using std::lock_guard;
using std::mutex;

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
    Result<void> load_config(const ConfigFileName& config_file) override;
    String get_string(const String& key, const String& default_value = "") override;
    int get_int(const String& key, int default_value = 0) override;
    bool get_bool(const String& key, bool default_value = false) override;
    Strings get_string_array(const String& key) override;
    Result<TargetService> get_target_service(const ServiceName& service_name) override;
    Result<TargetServices> get_all_target_services() override;
    
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
    String get_env_var(const std::string& key, const std::string& default_value = "");
    
private:
    // Configuration data
    ServerConfig m_server_config;
    SecurityConfig m_security_config;
    SessionConfig m_session_config;
    LoggingConfig m_logging_config;
    DatabaseConfig m_database_config;
    
    // Target services
    UnorderedMap<ServiceName, TargetService> m_target_services;
    
    // Raw configuration data
    nlohmann::json m_config_json;
    mutable std::mutex m_config_mutex;
    
    // Helper methods
    Result<void> load_yaml_config(const ConfigFileName& config_file);
    Result<void> load_json_config(const ConfigFileName& config_file);
    
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
    String get_config_value(const String& key, const String& default_value = "");
    bool file_exists(const String& filename);
    String get_file_extension(const String& filename);
    
    // Default configuration
    void set_default_config();
    nlohmann::json get_default_config_json();
};

// Configuration utilities
class ConfigUtils {
public:
    // Environment variable mapping
    static String map_env_var(const std::string& config_key);
    
    // Configuration validation
    static bool is_valid_port(int port);
    static bool is_valid_ip_address(const std::string& ip);
    static bool is_valid_log_level(const std::string& level);
    static bool is_valid_timeout(Seconds timeout);
    
    // Configuration conversion
    static Seconds parse_duration(const std::string& duration_str);
    static String format_duration(Seconds duration);
    static Vector<std::string> parse_string_array(const nlohmann::json& json_array);
    static nlohmann::json serialize_string_array(const Vector<std::string>& array);
    
    // File operations
    static Result<String> read_file(const FileName& filename);
    static Result<void> write_file(const FileName& filename, const String& content);
    static bool create_directory(const String& path);
};

} // namespace zerossg
