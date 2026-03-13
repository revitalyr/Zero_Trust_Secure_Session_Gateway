// C++23 module imports
import zerossg.constants;
import zerossg.interfaces;
import zerossg.std;
import zerossg.config.config_manager;
import zerossg.third_party.nlohmann_json;
import zerossg.third_party.yaml_cpp;

namespace zerossg {

zerossg::ConfigManager::ConfigManager() {
    zerossg::ConfigManager::set_default_config();
}

zerossg::Result<void> zerossg::ConfigManager::load_config(const zerossg::ConfigFileName& config_file) {
    std::lock_guard<std::mutex> lock(zerossg::ConfigManager::m_config_mutex);
    std::lock_guard<std::mutex> lock(zerossg::ConfigManager::m_config_mutex);
    
    try {
        if (!zerossg::file_exists(config_file)) {
            return zerossg::make_result_error(zerossg::ERROR_CONFIG_FILE_NOT_FOUND + config_file);
        }
        
        std::string extension = get_file_extension(config_file);
        
        if (extension == FORMAT_YAML || extension == FORMAT_YML) {
            auto result = load_yaml_config(config_file);
            if (!result.is_success()) {
                return result;
            }
        } else if (extension == FORMAT_JSON) {
            auto result = load_json_config(config_file);
            if (!result.is_success()) {
                return result;
            }
        } else {
            return zerossg::make_result_error(zerossg::ERROR_UNSUPPORTED_CONFIG_FORMAT + extension);
        }
        
        // Load environment variables (override config file)
        load_from_environment();
        
        // Validate configuration
        auto validation_result = validate_config();
        if (!validation_result.is_success()) {
            return validation_result;
        }
        
        return zerossg::Result<void>{};
    } catch (const std::exception& e) {
        return zerossg::make_result_error(zerossg::ERROR_FAILED_TO_LOAD_CONFIG + zerossg::String(e.what()));
    }
}

String ConfigManager::get_string(const String& key, const String& default_value) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    return get_config_value(key, default_value);
}

int ConfigManager::get_int(const std::string& key, int default_value) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        std::string value = get_config_value(key, std::to_string(default_value));
        return std::stoi(value);
    } catch (const std::exception& e) {
        return default_value;
    }
}

bool ConfigManager::get_bool(const std::string& key, bool default_value) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    std::string value = get_config_value(key, default_value ? "true" : "false");
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    
    return value == "true" || value == "1" || value == "yes" || value == "on";
}

Strings ConfigManager::get_string_array(const String& key) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        auto json_value = m_config_json;
        std::vector<std::string> keys;
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
            std::vector<std::string> result;
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

Result<TargetService> ConfigManager::get_target_service(const ServiceName& service_name) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    auto it = m_target_services.find(service_name);
    if (it == m_target_services.end()) {
        return zerossg::make_result_error("Target service not found: " + service_name);
    }
    
    return zerossg::Result<TargetService>{it->second};
}

Result<std::vector<TargetService>> ConfigManager::get_all_target_services() {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    std::vector<TargetService> services;
    services.reserve(m_target_services.size());
    
    for (const auto& pair : m_target_services) {
        services.push_back(pair.second);
    }
    
    return Result<std::vector<TargetService>>::success(std::move(services));
}

Result<void> ConfigManager::validate_config() {
    auto server_result = validate_server_config();
    if (!server_result.is_success()) {
        return server_result;
    }
    
    auto security_result = validate_security_config();
    if (!security_result.is_success()) {
        return security_result;
    }
    
    auto session_result = validate_session_config();
    if (!session_result.is_success()) {
        return session_result;
    }
    
    auto logging_result = validate_logging_config();
    if (!logging_result.is_success()) {
        return logging_result;
    }
    
    auto database_result = validate_database_config();
    if (!database_result.is_success()) {
        return database_result;
    }
    
    auto services_result = validate_target_services();
    if (!services_result.is_success()) {
        return services_result;
    }
    
    return Result<void>{};
}

Result<void> ConfigManager::save_config(const std::string& config_file) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        nlohmann::json config;
        
        // Serialize configuration
        config["server"]["listen_address"] = m_server_config.listen_address;
        config["server"]["listen_port"] = m_server_config.listen_port;
        config["server"]["tls_cert_file"] = m_server_config.tls_cert_file;
        config["server"]["tls_key_file"] = m_server_config.tls_key_file;
        config["server"]["ca_cert_file"] = m_server_config.ca_cert_file;
        
        config["security"]["jwt_secret"] = m_security_config.jwt_secret;
        config["security"]["token_expiry_hours"] = m_security_config.token_expiry_hours;
        config["security"]["max_login_attempts"] = m_security_config.max_login_attempts;
        config["security"]["lockout_duration_minutes"] = m_security_config.lockout_duration_minutes;
        
        config["session"]["timeout_seconds"] = m_session_config.timeout_seconds;
        config["session"]["max_concurrent_sessions"] = m_session_config.max_concurrent_sessions;
        
        config["logging"]["level"] = m_logging_config.level;
        config["logging"]["file_path"] = m_logging_config.file_path;
        config["logging"]["max_file_size_mb"] = m_logging_config.max_file_size_mb;
        config["logging"]["max_files"] = m_logging_config.max_files;
        
        config["database"]["host"] = m_database_config.host;
        config["database"]["port"] = m_database_config.port;
        config["database"]["name"] = m_database_config.name;
        config["database"]["username"] = m_database_config.username;
        config["database"]["password"] = m_database_config.password;
        config["database"]["ssl_mode"] = m_database_config.ssl_mode;
        
        // Save target services
        config["target_services"] = nlohmann::json::array();
        for (const auto& pair : m_target_services) {
            const auto& service = pair.second;
            nlohmann::json service_json;
            service_json["name"] = service.name;
            service_json["host"] = service.host;
            service_json["port"] = service.port;
            service_json["tls_enabled"] = service.tls_enabled;
            service_json["allowed_roles"] = nlohmann::json::array();
            for (const auto& role : service.allowed_roles) {
                service_json["allowed_roles"].push_back(role_to_string(role));
            }
            config["target_services"].push_back(service_json);
        }
        
        std::string json_str = config.dump(4);
        std::ofstream file(config_file);
        if (!file.is_open()) {
            return make_result_error("Failed to open configuration file for writing: " + config_file);
        }
        
        file << json_str;
        file.close();
        
        return Result<void>{};
    } catch (const std::exception& e) {
        return make_result_error("Failed to save configuration: " + std::string(e.what()));
    }
}

Result<void> ConfigManager::reload_config() {
    // This would reload from the last loaded file
    // For now, return success as a placeholder
    return Result<void>{};
}

// Private methods implementation

Result<void> ConfigManager::load_yaml_config(const std::string& config_file) {
    try {
        YAML::Node config = YAML::LoadFile(config_file);
        
        // Convert YAML to JSON for easier processing
        // This is a simplified approach - in production would use proper YAML parsing
        std::string json_str = YAML::Dump(config);
        m_config_json = json.parse(json_str);
        
        parse_server_config(m_config_json);
        parse_security_config(m_config_json);
        parse_session_config(m_config_json);
        parse_logging_config(m_config_json);
        parse_database_config(m_config_json);
        parse_target_services(m_config_json);
        
        return Result<void>{};
    } catch (const YAML::Exception& e) {
        return make_result_error("YAML parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return make_result_error("Failed to load YAML configuration: " + std::string(e.what()));
    }
}

Result<void> ConfigManager::load_json_config(const std::string& config_file) {
    try {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            return make_result_error("Failed to open configuration file: " + config_file);
        }
        
        file >> m_config_json;
        
        parse_server_config(m_config_json);
        parse_security_config(m_config_json);
        parse_session_config(m_config_json);
        parse_logging_config(m_config_json);
        parse_database_config(m_config_json);
        parse_target_services(m_config_json);
        
        return Result<void>{};
    } catch (const nlohmann::json::exception& e) {
        return make_result_error("JSON parsing error: " + std::string(e.what()));
    } catch (const std::exception& e) {
        return make_result_error("Failed to load JSON configuration: " + std::string(e.what()));
    }
}

void ConfigManager::parse_server_config(const nlohmann::json& config) {
    if (config.contains("server")) {
        const auto& server = config["server"];
        
        m_server_config.listen_address = server.value("listen_address", m_server_config.listen_address);
        m_server_config.listen_port = server.value("listen_port", m_server_config.listen_port);
        m_server_config.tls_cert_file = server.value("tls_cert_file", m_server_config.tls_cert_file);
        m_server_config.tls_key_file = server.value("tls_key_file", m_server_config.tls_key_file);
        m_server_config.ca_cert_file = server.value("ca_cert_file", m_server_config.ca_cert_file);
    }
}

void ConfigManager::parse_security_config(const nlohmann::json& config) {
    if (config.contains("security")) {
        const auto& security = config["security"];
        
        m_security_config.jwt_secret = security.value("jwt_secret", m_security_config.jwt_secret);
        m_security_config.token_expiry_hours = security.value("token_expiry_hours", m_security_config.token_expiry_hours);
        m_security_config.max_login_attempts = security.value("max_login_attempts", m_security_config.max_login_attempts);
        m_security_config.lockout_duration_minutes = security.value("lockout_duration_minutes", m_security_config.lockout_duration_minutes);
    }
}

void ConfigManager::parse_session_config(const nlohmann::json& config) {
    if (config.contains("session")) {
        const auto& session = config["session"];
        
        m_session_config.timeout_seconds = session.value("timeout_seconds", m_session_config.timeout_seconds);
        m_session_config.max_concurrent_sessions = session.value("max_concurrent_sessions", m_session_config.max_concurrent_sessions);
    }
}

void ConfigManager::parse_logging_config(const nlohmann::json& config) {
    if (config.contains("logging")) {
        const auto& logging = config["logging"];
        
        m_logging_config.level = logging.value("level", m_logging_config.level);
        m_logging_config.file_path = logging.value("file_path", m_logging_config.file_path);
        m_logging_config.max_file_size_mb = logging.value("max_file_size_mb", m_logging_config.max_file_size_mb);
        m_logging_config.max_files = logging.value("max_files", m_logging_config.max_files);
    }
}

void ConfigManager::parse_database_config(const nlohmann::json& config) {
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

void ConfigManager::parse_target_services(const nlohmann::json& config) {
    m_target_services.clear();
    
    if (config.contains("target_services")) {
        const auto& services = config["target_services"];
        if (services.is_array()) {
            for (const auto& service_json : services) {
                auto service_result = parse_target_service(service_json);
                if (service_result.is_success()) {
                    const auto& service = service_result.value();
                    m_target_services[service.name] = service;
                }
            }
        }
    }
}

Result<TargetService> ConfigManager::parse_target_service(const nlohmann::json& service_json) {
    try {
        TargetService service;
        
        service.name = service_json.value("name", "");
        service.host = service_json.value("host", "");
        service.port = service_json.value("port", 0);
        service.tls_enabled = service_json.value("tls_enabled", false);
        
        // Parse allowed roles
        if (service_json.contains("allowed_roles")) {
            const auto& roles_json = service_json["allowed_roles"];
            if (roles_json.is_array()) {
                for (const auto& role_json : roles_json) {
                    if (role_json.is_string()) {
                        std::string role_str = role_json.get<std::string>();
                        try {
                            Role role = string_to_role(role_str);
                            service.allowed_roles.push_back(role);
                        } catch (const std::exception&) {
                            // Invalid role, skip
                        }
                    }
                }
            }
        }
        
        if (service.host.empty() || service.port == 0) {
            return make_result_error("Target service must have host and port");
        }
        
        return zerossg::Result<TargetService>{service};
    } catch (const std::exception& e) {
        return make_result_error("Failed to parse target service: " + std::string(e.what()));
    }
}

Result<void> ConfigManager::validate_server_config() {
    if (!ConfigUtils::is_valid_ip_address(m_server_config.listen_address) && 
        m_server_config.listen_address != "0.0.0.0") {
        return make_result_error("Invalid listen address: " + m_server_config.listen_address);
    }
    
    if (m_server_config.listen_port < 1 || m_server_config.listen_port > 65535) {
        return make_result_error("Server port must be between 1 and 65535");
    }
    
    return Result<void>{};
}

Result<void> ConfigManager::validate_security_config() {
    if (m_security_config.jwt_secret.length() < 16) {
        return make_result_error("JWT secret must be at least 16 characters long");
    }
    
    if (m_security_config.token_expiry_hours < 1 || m_security_config.token_expiry_hours > 168) {
        return make_result_error("Token expiry must be between 1 and 168 hours");
    }
    
    return Result<void>{};
}

Result<void> ConfigManager::validate_session_config() {
    if (m_session_config.timeout_seconds < 60 || m_session_config.timeout_seconds > 86400) {
        return make_result_error("Session timeout must be between 60 and 86400 seconds");
    }
    
    if (m_session_config.max_concurrent_sessions < 1 || m_session_config.max_concurrent_sessions > 1000) {
        return make_result_error("Max concurrent sessions must be between 1 and 1000");
    }
    
    return Result<void>{};
}

Result<void> ConfigManager::validate_logging_config() {
    if (m_logging_config.level != "trace" && m_logging_config.level != "debug" && 
        m_logging_config.level != "info" && m_logging_config.level != "warn" && 
        m_logging_config.level != "error" && m_logging_config.level != "critical") {
        return make_result_error("Invalid log level: " + m_logging_config.level);
    }
    
    if (m_logging_config.max_file_size_mb < 1 || m_logging_config.max_file_size_mb > 1000) {
        return make_result_error("Max file size must be between 1 and 1000 MB");
    }
    
    if (m_logging_config.max_files < 1 || m_logging_config.max_files > 100) {
        return make_result_error("Max files must be between 1 and 100");
    }
    
    return Result<void>{};
}

Result<void> ConfigManager::validate_database_config() {
    if (m_database_config.host.empty()) {
        return make_result_error("Database host cannot be empty");
    }
    
    if (m_database_config.port < 1 || m_database_config.port > 65535) {
        return make_result_error("Database port must be between 1 and 65535");
    }
    
    if (m_database_config.name.empty()) {
        return make_result_error("Database name cannot be empty");
    }
    
    return Result<void>{};
}

Result<void> ConfigManager::validate_target_services() {
    for (const auto& pair : m_target_services) {
        const auto& service = pair.second;
        const auto& name = service.name;
        
        if (service.name.empty()) {
            return make_result_error("Target service name cannot be empty");
        }
        
        if (service.host.empty()) {
            return make_result_error("Target service '" + name + "' host cannot be empty");
        }
        
        if (service.port < 1 || service.port > 65535) {
            return make_result_error("Target service '" + name + "' port must be between 1 and 65535");
        }
        
        if (service.allowed_roles.empty()) {
            return make_result_error("Target service '" + name + "' must have at least one allowed role");
        }
    }
    
    return Result<void>{};
}

void ConfigManager::load_from_environment() {
    // Override configuration with environment variables
    if (const char* env_log_level = std::getenv("ZEROSSG_LOG_LEVEL")) {
        m_config_json["logging"]["level"] = String(env_log_level);
    }
    
    if (const char* env_db_host = std::getenv("ZEROSSG_DB_HOST")) {
        m_config_json["database"]["host"] = zerossg::String(env_db_host);
    }
    
    if (const char* env_db_port = std::getenv("ZEROSSG_DB_PORT")) {
        m_config_json["database"]["port"] = std::stoi(zerossg::String(env_db_port));
    }
    
    if (const char* env_db_name = std::getenv("ZEROSSG_DB_NAME")) {
        m_config_json["database"]["name"] = String(env_db_name);
    }
    
    if (const char* env_jwt_secret = std::getenv("ZEROSSG_JWT_SECRET")) {
        m_config_json["security"]["jwt_secret"] = zerossg::String(env_jwt_secret);
    }
}

// Helper methods for ConfigManager
std::string ConfigManager::get_config_value(const std::string& key, const std::string& default_value) {
    try {
        auto json_value = m_config_json;
        std::vector<std::string> keys;
        size_t pos = 0;
        std::string key_copy = key;
        
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

bool ConfigManager::file_exists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

std::string ConfigManager::get_file_extension(const std::string& filename) {
    size_t pos = filename.find_last_of('.');
    if (pos != std::string::npos && pos != filename.length() - 1) {
        return filename.substr(pos + 1);
    }
    return "";
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

bool is_valid_ip_address(const std::string& ip) {
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

Result<std::string> read_file(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return make_result_error("Failed to open file: " + filename);
    }
    
    try {
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return Result<std::string>{content};
    } catch (const std::exception& e) {
        return make_result_error("Failed to read file: " + std::string(e.what()));
    }
}

Result<void> write_file(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return make_result_error("Failed to open file for writing: " + filename);
    }
    
    try {
        file << content;
        file.close();
        return Result<void>{};
    } catch (const std::exception& e) {
        return make_result_error("Failed to write file: " + std::string(e.what()));
    }
}

bool create_directory(const std::string& path) {
    return std::filesystem::create_directories(path);
}

} // namespace ConfigUtils

} // namespace zerossg
