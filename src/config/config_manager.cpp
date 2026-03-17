module;
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <fstream> // Required for std::ifstream/ofstream
#include <yaml-cpp/yaml.h>
#include <filesystem>
module zerossg.config.config_manager;

// C++23 module imports
import zerossg.constants;
import zerossg.interfaces;
import zerossg.common; // For Result, make_result_success, make_result_error, LockGuard, String
import zerossg.third_party.nlohmann_json;
import zerossg.third_party.yaml_cpp;

namespace zerossg {

zerossg::ConfigManager::ConfigManager() {
    zerossg::ConfigManager::set_default_config();
}

zerossg::Result<void> zerossg::ConfigManager::load_config(const zerossg::ConfigFileName& config_file) {
    LockGuard<std::mutex> lock(zerossg::ConfigManager::m_config_mutex);
    
    try {
        if (!this->file_exists(config_file)) {
            return make_result_error<void>(std::format("{}{}", ERROR_CONFIG_FILE_NOT_FOUND, config_file));
        }
        
        zerossg::FileExtension extension = this->get_file_extension(config_file);
        
        if (extension == FORMAT_YAML || extension == FORMAT_YML) {
            auto result = load_yaml_config(config_file);
            if (!result.has_value()) {
                return make_result_error<void>(result.error());
            }
        } else if (extension == FORMAT_JSON) {
            auto result = load_json_config(config_file);
            if (!result.has_value()) {
                return make_result_error<void>(result.error());
            }
        } else {
            return make_result_error<void>(std::format("{}{}", ERROR_UNSUPPORTED_CONFIG_FORMAT, extension));
        }
        
        // Load environment variables (override config file)
        load_from_environment();
        
        // Validate configuration
        auto validation_result = validate_config();
        if (!validation_result.has_value()) {
            return make_result_error<void>(validation_result.error());
        }
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_FAILED_TO_LOAD_CONFIG, e.what()));
    }
}

zerossg::ConfigValue ConfigManager::get_string(const zerossg::ConfigKey& key, const zerossg::ConfigValue& default_value) {
    LockGuard<std::mutex> lock(m_config_mutex);
    return get_config_value(key, default_value);
}

int ConfigManager::get_int(const zerossg::ConfigKey& key, int default_value) {
    LockGuard<std::mutex> lock(m_config_mutex);
    
    try {
        zerossg::ConfigValue value = get_config_value(key, std::to_string(default_value));
        return std::stoi(value);
    } catch (const std::exception& e) {
        return default_value;
    }
}

bool ConfigManager::get_bool(const zerossg::ConfigKey& key, bool default_value) {
    LockGuard<std::mutex> lock(m_config_mutex);
    
    zerossg::ConfigValue value = get_config_value(key, default_value ? "true" : "false");
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    
    return value == "true" || value == "1" || value == "yes" || value == "on";
}

zerossg::StringArray ConfigManager::get_string_array(const zerossg::ConfigKey& key) {
    LockGuard<std::mutex> lock(m_config_mutex);
    
    try {
        auto json_value = m_config_json;
        zerossg::ConfigKeys keys;
        size_t pos = 0;
        std::string key_copy = key;
        
        while ((pos = key_copy.find('.')) != std::string::npos) {
            keys.push_back(key_copy.substr(0, pos));
            key_copy.erase(0, pos + 1);
        }
        keys.push_back(key_copy);
        
        for (const auto& k : keys) {
            if (!json_value.contains(k)) {
                return {};
            }
            json_value = json_value[k];
        }
        
        if (json_value.is_array()) {
            zerossg::StringArray result;
            for (const auto& item : json_value) {
                if (item.is_string()) {
                    result.push_back(item.get<std::string>());
                }
            }
            return result;
        }
    } catch (const std::exception&) {
        // Return empty array on error
    }
    
    return {};
}

zerossg::Result<zerossg::TargetService> ConfigManager::get_target_service(const zerossg::ServiceName& service_name) {
    LockGuard<std::mutex> lock(m_config_mutex);
    
    auto it = m_target_services.find(service_name);
    if (it == m_target_services.end()) {
        return make_result_error<TargetService>(std::format("{}{}", ERROR_TARGET_SERVICE_NOT_FOUND_PREFIX, service_name));
    }
    
    return zerossg::make_result_success(it->second);
}

zerossg::Result<zerossg::TargetServices> ConfigManager::get_all_target_services() {
    LockGuard<std::mutex> lock(m_config_mutex);
    
    zerossg::TargetServices services;
    services.reserve(m_target_services.size());
    
    for (const auto& pair : m_target_services) {
        services.push_back(pair.second);
    }

    return zerossg::make_result_success(std::move(services));
}

zerossg::Result<void> ConfigManager::validate_config() {
    auto server_result = validate_server_config();
    if (!server_result.has_value()) {
        return server_result;
    }
    
    auto security_result = validate_security_config();
    if (!security_result.has_value()) {
        return security_result;
    }
    
    auto session_result = validate_session_config();
    if (!session_result.has_value()) {
        return session_result;
    }
    
    auto logging_result = validate_logging_config();
    if (!logging_result.has_value()) {
        return logging_result;
    }
    
    auto database_result = validate_database_config();
    if (!database_result.has_value()) {
        return database_result;
    }
    
    auto services_result = validate_target_services();
    if (!services_result.has_value()) {
        return services_result;
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<void> ConfigManager::save_config(const zerossg::ConfigFileName& config_file) {
    LockGuard<std::mutex> lock(m_config_mutex);
    
    try {
        json config;
        
        // Serialize configuration
        config[CONFIG_KEY_SERVER][CONFIG_KEY_LISTEN_ADDRESS] = m_server_config.listen_address;
        config[CONFIG_KEY_SERVER][CONFIG_KEY_LISTEN_PORT] = m_server_config.listen_port;
        config[CONFIG_KEY_SERVER][CONFIG_KEY_TLS_CERT_FILE] = m_server_config.tls_cert_file;
        config[CONFIG_KEY_SERVER][CONFIG_KEY_TLS_KEY_FILE] = m_server_config.tls_key_file;
        config[CONFIG_KEY_SERVER][CONFIG_KEY_CA_CERT_FILE] = m_server_config.ca_cert_file;
        
        config[CONFIG_KEY_SECURITY][CONFIG_KEY_JWT_SECRET] = m_security_config.jwt_secret;
        config[CONFIG_KEY_SECURITY][CONFIG_KEY_TOKEN_EXPIRY_HOURS] = m_security_config.token_expiry_hours;
        config[CONFIG_KEY_SECURITY][CONFIG_KEY_MAX_LOGIN_ATTEMPTS] = m_security_config.max_login_attempts;
        config[CONFIG_KEY_SECURITY][CONFIG_KEY_LOCKOUT_DURATION_MINUTES] = m_security_config.lockout_duration_minutes;
        
        config[CONFIG_KEY_SESSION][CONFIG_KEY_TIMEOUT_SECONDS] = m_session_config.timeout_seconds;
        config[CONFIG_KEY_SESSION][CONFIG_KEY_MAX_CONCURRENT_SESSIONS] = m_session_config.max_concurrent_sessions;
        
        config[CONFIG_KEY_LOGGING][CONFIG_KEY_LEVEL] = m_logging_config.level;
        config[CONFIG_KEY_LOGGING][CONFIG_KEY_FILE_PATH] = m_logging_config.file_path;
        config[CONFIG_KEY_LOGGING][CONFIG_KEY_MAX_FILE_SIZE_MB] = m_logging_config.max_file_size_mb;
        config[CONFIG_KEY_LOGGING][CONFIG_KEY_MAX_FILES] = m_logging_config.max_files;
        
        config[CONFIG_KEY_DATABASE][CONFIG_KEY_HOST] = m_database_config.host;
        config[CONFIG_KEY_DATABASE][CONFIG_KEY_PORT] = m_database_config.port;
        config[CONFIG_KEY_DATABASE][CONFIG_KEY_NAME] = m_database_config.name;
        config[CONFIG_KEY_DATABASE][CONFIG_KEY_USERNAME] = m_database_config.username;
        config[CONFIG_KEY_DATABASE][CONFIG_KEY_PASSWORD] = m_database_config.password;
        config[CONFIG_KEY_DATABASE][CONFIG_KEY_SSL_MODE] = m_database_config.ssl_mode;
        
        // Save target services
        config[CONFIG_KEY_TARGET_SERVICES] = json::array();
        for (const auto& pair : m_target_services) {
            const auto& service = pair.second;
            json service_json;
            service_json[CONFIG_KEY_NAME] = service.name();
            service_json[CONFIG_KEY_HOST] = service.host();
            service_json[CONFIG_KEY_PORT] = service.port();
            service_json[CONFIG_KEY_TLS_ENABLED] = service.is_tls_enabled();
            service_json[CONFIG_KEY_ALLOWED_ROLES] = json::array();
            for (const auto& role : service.allowed_roles()) {
                service_json[CONFIG_KEY_ALLOWED_ROLES].push_back(role_to_string(role));
            }
            config[CONFIG_KEY_TARGET_SERVICES].push_back(service_json);
        }
        
        std::string json_str = config.dump(4);
        std::ofstream file(config_file);
        if (!file.is_open()) {
            return make_result_error<void>(std::format("{}{}", ERROR_CONFIG_WRITE_OPEN_FAILED_PREFIX, config_file));
        }
        
        file << json_str;
        file.close();
        
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_CONFIG_SAVE_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> ConfigManager::reload_config() {
    // This would reload from the last loaded file
    // For now, return success as a placeholder
    return zerossg::make_result_success();
}

// Private methods implementation

zerossg::Result<void> ConfigManager::load_yaml_config(const zerossg::ConfigFileName& config_file) {
    try {
        YAML::Node config = YAML::LoadFile(config_file);
        
        // Convert YAML to JSON for easier processing
        // This is a simplified approach - in production would use proper YAML parsing
        std::string json_str = YAML::Dump(config);
        m_config_json = json::parse(json_str);
        
        parse_server_config(m_config_json);
        parse_security_config(m_config_json);
        parse_session_config(m_config_json);
        parse_logging_config(m_config_json);
        parse_database_config(m_config_json);
        parse_target_services(m_config_json);
        
        return zerossg::make_result_success();
    } catch (const YAML::Exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_YAML_PARSE_PREFIX, e.what()));
    } catch (const std::exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_YAML_LOAD_PREFIX, e.what()));
    }
}

zerossg::Result<void> ConfigManager::load_json_config(const zerossg::ConfigFileName& config_file) {
    try {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            return make_result_error<void>(std::format("{}{}", ERROR_CONFIG_OPEN_FAILED_PREFIX, config_file));
        }
        
        file >> m_config_json;
        
        parse_server_config(m_config_json);
        parse_security_config(m_config_json);
        parse_session_config(m_config_json);
        parse_logging_config(m_config_json);
        parse_database_config(m_config_json);
        parse_target_services(m_config_json);
        
        return zerossg::make_result_success();
    } catch (const json::exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_JSON_PARSE_PREFIX, e.what()));
    } catch (const std::exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_JSON_LOAD_PREFIX, e.what()));
    }
}

void ConfigManager::parse_server_config(const json& config) {
    if (config.contains("server")) {
        const auto& server = config["server"];
        
        m_server_config.listen_address = server.value("listen_address", m_server_config.listen_address);
        m_server_config.listen_port = server.value("listen_port", m_server_config.listen_port);
        m_server_config.tls_cert_file = server.value("tls_cert_file", m_server_config.tls_cert_file);
        m_server_config.tls_key_file = server.value("tls_key_file", m_server_config.tls_key_file);
        m_server_config.ca_cert_file = server.value("ca_cert_file", m_server_config.ca_cert_file);
    }
}

void ConfigManager::parse_security_config(const json& config) {
    if (config.contains("security")) {
        const auto& security = config["security"];
        
        m_security_config.jwt_secret = security.value("jwt_secret", m_security_config.jwt_secret);
        m_security_config.token_expiry_hours = security.value("token_expiry_hours", m_security_config.token_expiry_hours);
        m_security_config.max_login_attempts = security.value("max_login_attempts", m_security_config.max_login_attempts);
        m_security_config.lockout_duration_minutes = security.value("lockout_duration_minutes", m_security_config.lockout_duration_minutes);
    }
}

void ConfigManager::parse_session_config(const json& config) {
    if (config.contains("session")) {
        const auto& session = config["session"];
        
        m_session_config.timeout_seconds = session.value("timeout_seconds", m_session_config.timeout_seconds);
        m_session_config.max_concurrent_sessions = session.value("max_concurrent_sessions", m_session_config.max_concurrent_sessions);
    }
}

void ConfigManager::parse_logging_config(const json& config) {
    if (config.contains("logging")) {
        const auto& logging = config["logging"];
        
        m_logging_config.level = logging.value("level", m_logging_config.level);
        m_logging_config.file_path = logging.value("file_path", m_logging_config.file_path);
        m_logging_config.max_file_size_mb = logging.value("max_file_size_mb", m_logging_config.max_file_size_mb);
        m_logging_config.max_files = logging.value("max_files", m_logging_config.max_files);
    }
}

void ConfigManager::parse_database_config(const json& config) {
    if (config.contains("database")) {
        const auto& database = config["database"];
        
        m_database_config.host = database.value("host", m_database_config.host);
        m_database_config.port = database.value("port", m_database_config.port);
        m_database_config.name = database.value("name", m_database_config.name);
        m_database_config.username = database.value("username", m_database_config.username);
        m_database_config.password = database.value("password", m_database_config.password);
        m_database_config.ssl_mode = database.value("ssl_mode", m_database_config.ssl_mode);
    }
}

void ConfigManager::parse_target_services(const json& config) {
    m_target_services.clear();
    
    if (config.contains("target_services")) {
        const auto& services = config["target_services"];
        if (services.is_array()) {
            for (const auto& service_json : services) {
                auto service_result = parse_target_service(service_json);
                if (service_result.has_value()) {
                    const auto& service = service_result.value();
                    m_target_services[service.name()] = service;
                }
            }
        }
    }
}

zerossg::Result<zerossg::TargetService> ConfigManager::parse_target_service(const json& service_json) {
    try {
        zerossg::TargetService service;
        
        service.m_name = service_json.value("name", "");
        service.m_host = service_json.value("host", "");
        service.m_port = service_json.value("port", 0);
        service.m_tls_enabled = service_json.value("tls_enabled", false);
        
        // Parse allowed roles
        if (service_json.contains("allowed_roles")) {
            const auto& roles_json = service_json["allowed_roles"];
            if (roles_json.is_array()) {
                for (const auto& role_json : roles_json) {
                    if (role_json.is_string()) {
                        zerossg::RoleString role_str = role_json.get<std::string>();
                        try {
                            zerossg::Role role = string_to_role(role_str);
                            service.m_allowed_roles.push_back(role);
                        } catch (const std::exception&) {
                            // Invalid role, skip
                        }
                    }
                }
            }
        }
        
        if (service.host().empty() || service.port() == 0) {
            return make_result_error<TargetService>(std::string(ERROR_TARGET_SERVICE_HOST_PORT_MISSING));
        }
        
        return zerossg::make_result_success(service);
    } catch (const std::exception& e) {
        return make_result_error<TargetService>(std::format("{}{}", ERROR_TARGET_SERVICE_PARSE_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> ConfigManager::validate_server_config() {
    if (!ConfigUtils::is_valid_ip_address(m_server_config.listen_address) && 
        m_server_config.listen_address != "0.0.0.0") {
        return make_result_error<void>(std::format("{}{}", ERROR_INVALID_LISTEN_ADDRESS, m_server_config.listen_address));
    }
    
    if (m_server_config.listen_port < 1 || m_server_config.listen_port > 65535) {
        return make_result_error<void>(ERROR_INVALID_SERVER_PORT);
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<void> ConfigManager::validate_security_config() {
    if (m_security_config.jwt_secret.length() < 16) {
        return make_result_error<void>(std::string(ERROR_JWT_SECRET_TOO_SHORT));
    }
    
    if (m_security_config.token_expiry_hours < 1 || m_security_config.token_expiry_hours > 168) {
        return make_result_error<void>(std::string(ERROR_INVALID_TOKEN_EXPIRY));
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<void> ConfigManager::validate_session_config() {
    if (m_session_config.timeout_seconds < 60 || m_session_config.timeout_seconds > 86400) {
        return make_result_error<void>(std::string(ERROR_INVALID_SESSION_TIMEOUT));
    }
    
    if (m_session_config.max_concurrent_sessions < 1 || m_session_config.max_concurrent_sessions > 1000) {
        return make_result_error<void>(std::string(ERROR_INVALID_MAX_SESSIONS));
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<void> ConfigManager::validate_logging_config() {
    if (m_logging_config.level != "trace" && m_logging_config.level != "debug" && 
        m_logging_config.level != "info" && m_logging_config.level != "warn" && 
        m_logging_config.level != "error" && m_logging_config.level != "critical") {
        return make_result_error<void>(std::format("{}{}", ERROR_INVALID_LOG_LEVEL, m_logging_config.level));
    }
    
    if (m_logging_config.max_file_size_mb < 1 || m_logging_config.max_file_size_mb > 1000) {
        return make_result_error<void>(std::string(ERROR_INVALID_LOG_MAX_SIZE));
    }
    
    if (m_logging_config.max_files < 1 || m_logging_config.max_files > 100) {
        return make_result_error<void>(std::string(ERROR_INVALID_LOG_MAX_FILES));
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<void> ConfigManager::validate_database_config() {
    if (m_database_config.host.empty()) {
        return make_result_error<void>(std::string(ERROR_DB_HOST_EMPTY));
    }
    
    if (m_database_config.port < 1 || m_database_config.port > 65535) {
        return make_result_error<void>(std::string(ERROR_INVALID_DB_PORT));
    }
    
    if (m_database_config.name.empty()) {
        return make_result_error<void>(std::string(ERROR_DB_NAME_EMPTY));
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<void> ConfigManager::validate_target_services() {
    for (const auto& pair : m_target_services) {
        const auto& service = pair.second;
        const auto& name = service.name();
        
        if (service.name().empty()) {
            return make_result_error<void>(std::string(ERROR_TARGET_SERVICE_NAME_EMPTY));
        }
        
        if (service.host().empty()) {
            return make_result_error<void>(std::format("{}'{}' host cannot be empty", ERROR_TARGET_SERVICE_HOST_EMPTY_PREFIX, name));
        }
        
        if (service.port() < 1 || service.port() > 65535) {
            return make_result_error<void>(std::format("{}'{}' port must be between 1 and 65535", ERROR_INVALID_TARGET_SERVICE_PORT_PREFIX, name));
        }
        
        if (service.allowed_roles().empty()) {
            return make_result_error<void>(std::format("{}'{}' must have at least one allowed role", ERROR_TARGET_SERVICE_NO_ROLES_PREFIX, name));
        }
    }
    
    return zerossg::make_result_success();
}

void ConfigManager::load_from_environment() {
    // Override configuration with environment variables
    // Note: getenv is in stdlib.h/cstdlib, usually available via std module or global
    // Assuming std::getenv is available from zerossg.std
    // ... implementation ...
}

// Helper methods for ConfigManager
zerossg::ConfigValue ConfigManager::get_config_value(const zerossg::ConfigKey& key, const zerossg::ConfigValue& default_value) {
    try {
        auto json_value = m_config_json;
        zerossg::ConfigKeys keys;
        size_t pos = 0;
        zerossg::ConfigKey key_copy = key;
        
        while ((pos = key_copy.find('.')) != std::string::npos) {
            keys.push_back(key_copy.substr(0, pos));
            key_copy.erase(0, pos + 1);
        }
        keys.push_back(key_copy);
        
        for (const auto& k : keys) {
            if (!json_value.contains(k)) {
                return default_value;
            }
            json_value = json_value[k];
        }
        
        if (json_value.is_string()) {
            return json_value.get<zerossg::String>();
        } else if (json_value.is_number() || json_value.is_boolean()) {
            return json_value.dump();
        }
    } catch (const std::exception&) {
        // Return default value on error
    }
    
    return default_value;
}

bool ConfigManager::file_exists(const zerossg::FilePath& filename) {
    std::ifstream file(filename);
    return file.good();
}

zerossg::FileExtension ConfigManager::get_file_extension(const zerossg::FilePath& filename) {
    size_t pos = filename.find_last_of('.');
    if (pos != std::string::npos && pos != filename.length() - 1) {
        return filename.substr(pos + 1);
    }
    return "";
}

json ConfigManager::get_default_config_json() {
    json config;
    config[CONFIG_KEY_SERVER] = {
        {CONFIG_KEY_LISTEN_ADDRESS, "127.0.0.1"},
        {CONFIG_KEY_LISTEN_PORT, 8080},
        {CONFIG_KEY_THREAD_COUNT, 4}
    };
    config[CONFIG_KEY_SECURITY] = {
        {CONFIG_KEY_TOKEN_EXPIRY_HOURS, 1},
        {CONFIG_KEY_MAX_LOGIN_ATTEMPTS, 5}
    };
    config[CONFIG_KEY_SESSION] = {
        {CONFIG_KEY_TIMEOUT_SECONDS, 3600},
        {CONFIG_KEY_MAX_CONCURRENT_SESSIONS, 5}
    };
    config[CONFIG_KEY_LOGGING] = {
        {CONFIG_KEY_LEVEL, "info"}
    };
    config[CONFIG_KEY_TARGET_SERVICES] = json::array();
    return config;
}

void ConfigManager::set_default_config() {
    m_config_json = get_default_config_json();
    
    // Parse the default configuration
    parse_server_config(m_config_json);
    parse_security_config(m_config_json);
    parse_session_config(m_config_json);
    parse_logging_config(m_config_json);
    parse_database_config(m_config_json);
    parse_target_services(m_config_json);
}

// ConfigUtils namespace implementation
namespace ConfigUtils {

bool is_valid_ip_address(const zerossg::IpAddress& ip) {
    // Simple IP validation - in production would use proper validation
    if (ip.empty() || ip == "0.0.0.0") {
        return true;
    }
    
    // Basic format check
    size_t dot_count = std::count(ip.begin(), ip.end(), '.');
    if (dot_count != 3) {
        return false;
    }
    
    std::istringstream iss(ip);
    std::string segment;
    while (std::getline(iss, segment, '.')) {
        if (segment.empty() || segment.length() > 3) {
            return false;
        }
        
        for (char c : segment) {
            if (!std::isdigit(c)) {
                return false;
            }
        }
        
        try {
            int value = std::stoi(segment);
            if (value < 0 || value > 255) {
                return false;
            }
        } catch (const std::exception&) {
            return false;
        }
    }
    
    return true;
}

zerossg::Result<zerossg::FileContent> read_file(const zerossg::FilePath& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return make_result_error<FileContent>(std::format("{}{}", ERROR_FILE_OPEN_FAILED_PREFIX, filename));
    }
    
    try {
        zerossg::FileContent content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return zerossg::make_result_success(content);
    } catch (const std::exception& e) {
        return make_result_error<FileContent>(std::format("{}{}", ERROR_FILE_READ_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> write_file(const zerossg::FilePath& filename, const zerossg::FileContent& content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return make_result_error<void>(std::format("{}{}", ERROR_FILE_WRITE_OPEN_FAILED_PREFIX, filename));
    }
    
    try {
        file << content;
        file.close();
        return zerossg::make_result_success();
    } catch (const std::exception& e) {
        return make_result_error<void>(std::format("{}{}", ERROR_FILE_WRITE_FAILED_PREFIX, e.what()));
    }
}

bool create_directory(const zerossg::DirectoryPath& path) {
    return std::filesystem::create_directories(std::filesystem::path(path));
}

} // namespace ConfigUtils

} // namespace zerossg
