// Project headers
#include "zerossg/config/config_manager.hpp"

// C++ Standard Library headers (alphabetical order)
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>

namespace zerossg {

ConfigManager::ConfigManager() {
    set_default_config();
}

Result<void> ConfigManager::load_config(const string& config_file) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        if (!file_exists(config_file)) {
            return Result<void>::error("Configuration file not found: " + config_file);
        }
        
        string extension = get_file_extension(config_file);
        
        if (extension == "yaml" || extension == "yml") {
            auto result = load_yaml_config(config_file);
            if (!result.is_success()) {
                return result;
            }
        } else if (extension == "json") {
            auto result = load_json_config(config_file);
            if (!result.is_success()) {
                return result;
            }
        } else {
            return Result<void>::error("Unsupported configuration file format: " + extension);
        }
        
        // Load environment variables (override config file)
        load_from_environment();
        
        // Validate configuration
        auto validation_result = validate_config();
        if (!validation_result.is_success()) {
            return validation_result;
        }
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to load configuration: " + string(e.what()));
    }
}

string ConfigManager::get_string(const string& key, const string& default_value) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    return get_config_value(key, default_value);
}

int ConfigManager::get_int(const string& key, int default_value) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        string value = get_config_value(key, std::to_string(default_value));
        return std::stoi(value);
    } catch (const std::exception&) {
        return default_value;
    }
}

bool ConfigManager::get_bool(const string& key, bool default_value) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    string value = get_config_value(key, default_value ? "true" : "false");
    std::transform(value.begin(), value.end(), value.begin(), ::tolower);
    
    return value == "true" || value == "1" || value == "yes" || value == "on";
}

vector<string> ConfigManager::get_string_array(const string& key) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        auto json_value = m_config_json;
        std::vector<string> keys;
        size_t pos = 0;
        string key_copy = key;
        
        while ((pos = key_copy.find('.')) != string::npos) {
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
            vector<string> result;
            for (const auto& item : json_value) {
                if (item.is_string()) {
                    result.push_back(item.get<string>());
                }
            }
            return result;
        }
    } catch (const std::exception&) {
        // Return empty array on error
    }
    
    return {};
}

Result<TargetService> ConfigManager::get_target_service(const string& service_name) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    auto it = m_target_services.find(service_name);
    if (it == m_target_services.end()) {
        return Result<TargetService>::error("Target service not found: " + service_name);
    }
    
    return Result<TargetService>::success(it->second);
}

Result<vector<TargetService>> ConfigManager::get_all_target_services() {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    vector<TargetService> services;
    services.reserve(m_target_services.size());
    
    for (const auto& pair : m_target_services) {
        services.push_back(pair.second);
    }
    
    return Result<vector<TargetService>>::success(std::move(services));
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
    
    return Result<void>::success();
}

Result<void> ConfigManager::save_config(const string& config_file) {
    std::lock_guard<std::mutex> lock(m_config_mutex);
    
    try {
        nlohmann::json config;
        
        // Serialize configuration
        config["server"]["listen_address"] = m_server_config.listen_address;
        config["server"]["listen_port"] = m_server_config.listen_port;
        config["server"]["tls_cert_file"] = m_server_config.tls_cert_file;
        config["server"]["tls_key_file"] = m_server_config.tls_key_file;
        config["server"]["ca_cert_file"] = m_server_config.ca_cert_file;
        config["server"]["thread_count"] = m_server_config.thread_count;
        config["server"]["verify_client_certificates"] = m_server_config.verify_client_certificates;
        config["server"]["cipher_list"] = m_server_config.cipher_list;
        
        config["security"]["rate_limit_max_requests"] = m_security_config.rate_limit_max_requests;
        config["security"]["rate_limit_window"] = m_security_config.rate_limit_window.count();
        config["security"]["brute_force_threshold"] = m_security_config.brute_force_threshold;
        config["security"]["brute_force_window"] = m_security_config.brute_force_window.count();
        config["security"]["default_block_duration"] = m_security_config.default_block_duration.count();
        config["security"]["enable_ip_whitelist"] = m_security_config.enable_ip_whitelist;
        config["security"]["allowed_ips"] = m_security_config.allowed_ips;
        config["security"]["enable_ip_blacklist"] = m_security_config.enable_ip_blacklist;
        config["security"]["blocked_ips"] = m_security_config.blocked_ips;
        
        config["session"]["default_timeout"] = m_session_config.default_timeout.count();
        config["session"]["max_sessions_per_user"] = m_session_config.max_sessions_per_user;
        config["session"]["cleanup_interval"] = m_session_config.cleanup_interval.count();
        config["session"]["enable_session_persistence"] = m_session_config.enable_session_persistence;
        config["session"]["persistence_file"] = m_session_config.persistence_file;
        
        config["logging"]["level"] = m_logging_config.level;
        config["logging"]["pattern"] = m_logging_config.pattern;
        config["logging"]["enable_console_output"] = m_logging_config.enable_console_output;
        config["logging"]["enable_file_output"] = m_logging_config.enable_file_output;
        config["logging"]["log_file"] = m_logging_config.log_file;
        config["logging"]["max_file_size"] = m_logging_config.max_file_size;
        config["logging"]["max_files"] = m_logging_config.max_files;
        config["logging"]["enable_security_log"] = m_logging_config.enable_security_log;
        config["logging"]["security_log_file"] = m_logging_config.security_log_file;
        config["logging"]["enable_audit_log"] = m_logging_config.enable_audit_log;
        config["logging"]["audit_log_file"] = m_logging_config.audit_log_file;
        
        config["database"]["type"] = m_database_config.type;
        config["database"]["connection_string"] = m_database_config.connection_string;
        config["database"]["username"] = m_database_config.username;
        config["database"]["password"] = m_database_config.password;
        config["database"]["enable_ssl"] = m_database_config.enable_ssl;
        config["database"]["connection_pool_size"] = m_database_config.connection_pool_size;
        config["database"]["connection_timeout"] = m_database_config.connection_timeout.count();
        
        // Write to file
        string json_str = config.dump(4);
        std::ofstream file(config_file);
        if (!file.is_open()) {
            return Result<void>::error("Failed to open configuration file for writing: " + config_file);
        }
        
        file << json_str;
        file.close();
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to save configuration: " + string(e.what()));
    }
}

Result<void> ConfigManager::reload_config() {
    // This would reload from the last loaded file
    // For now, return success as a placeholder
    return Result<void>::success();
}

void ConfigManager::load_from_environment() {
    // Server configuration
    string env_listen_address = get_env_var("ZEROSSG_LISTEN_ADDRESS");
    if (!env_listen_address.empty()) {
        m_server_config.listen_address = env_listen_address;
    }
    
    string env_listen_port = get_env_var("ZEROSSG_LISTEN_PORT");
    if (!env_listen_port.empty()) {
        m_server_config.listen_port = static_cast<uint16_t>(std::stoi(env_listen_port));
    }
    
    string env_tls_cert = get_env_var("ZEROSSG_TLS_CERT_FILE");
    if (!env_tls_cert.empty()) {
        m_server_config.tls_cert_file = env_tls_cert;
    }
    
    string env_tls_key = get_env_var("ZEROSSG_TLS_KEY_FILE");
    if (!env_tls_key.empty()) {
        m_server_config.tls_key_file = env_tls_key;
    }
    
    // Security configuration
    string env_rate_limit = get_env_var("ZEROSSG_RATE_LIMIT_MAX_REQUESTS");
    if (!env_rate_limit.empty()) {
        m_security_config.rate_limit_max_requests = static_cast<size_t>(std::stoi(env_rate_limit));
    }
    
    // Logging configuration
    string env_log_level = get_env_var("ZEROSSG_LOG_LEVEL");
    if (!env_log_level.empty()) {
        m_logging_config.level = env_log_level;
    }
    
    string env_log_file = get_env_var("ZEROSSG_LOG_FILE");
    if (!env_log_file.empty()) {
        m_logging_config.log_file = env_log_file;
    }
}

string ConfigManager::get_env_var(const string& key, const string& default_value) {
    const char* value = std::getenv(key.c_str());
    return value ? string(value) : default_value;
}

Result<void> ConfigManager::load_yaml_config(const string& config_file) {
    try {
        YAML::Node yaml_config = YAML::LoadFile(config_file);
        
        // Convert YAML to JSON for easier processing
        nlohmann::json config_json = nlohmann::json::parse(YAML::Dump(yaml_config));
        m_config_json = config_json;
        
        // Parse configuration sections
        parse_server_config(config_json);
        parse_security_config(config_json);
        parse_session_config(config_json);
        parse_logging_config(config_json);
        parse_database_config(config_json);
        parse_target_services(config_json);
        
        return Result<void>::success();
    } catch (const YAML::Exception& e) {
        return Result<void>::error("YAML parsing error: " + string(e.what()));
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to load YAML configuration: " + string(e.what()));
    }
}

Result<void> ConfigManager::load_json_config(const string& config_file) {
    try {
        std::ifstream file(config_file);
        if (!file.is_open()) {
            return Result<void>::error("Failed to open configuration file: " + config_file);
        }
        
        nlohmann::json config_json;
        file >> config_json;
        m_config_json = config_json;
        
        // Parse configuration sections
        parse_server_config(config_json);
        parse_security_config(config_json);
        parse_session_config(config_json);
        parse_logging_config(config_json);
        parse_database_config(config_json);
        parse_target_services(config_json);
        
        return Result<void>::success();
    } catch (const nlohmann::json::exception& e) {
        return Result<void>::error("JSON parsing error: " + string(e.what()));
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to load JSON configuration: " + string(e.what()));
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
        m_server_config.thread_count = server.value("thread_count", m_server_config.thread_count);
        m_server_config.verify_client_certificates = server.value("verify_client_certificates", m_server_config.verify_client_certificates);
        m_server_config.cipher_list = server.value("cipher_list", m_server_config.cipher_list);
    }
}

void ConfigManager::parse_security_config(const nlohmann::json& config) {
    if (config.contains("security")) {
        const auto& security = config["security"];
        
        m_security_config.rate_limit_max_requests = security.value("rate_limit_max_requests", m_security_config.rate_limit_max_requests);
        m_security_config.rate_limit_window = seconds(security.value("rate_limit_window", static_cast<int>(m_security_config.rate_limit_window.count())));
        m_security_config.brute_force_threshold = security.value("brute_force_threshold", m_security_config.brute_force_threshold);
        m_security_config.brute_force_window = seconds(security.value("brute_force_window", static_cast<int>(m_security_config.brute_force_window.count())));
        m_security_config.default_block_duration = milliseconds(security.value("default_block_duration", static_cast<int>(m_security_config.default_block_duration.count())));
        m_security_config.enable_ip_whitelist = security.value("enable_ip_whitelist", m_security_config.enable_ip_whitelist);
        m_security_config.allowed_ips = ConfigUtils::parse_string_array(security.value("allowed_ips", nlohmann::json::array()));
        m_security_config.enable_ip_blacklist = security.value("enable_ip_blacklist", m_security_config.enable_ip_blacklist);
        m_security_config.blocked_ips = ConfigUtils::parse_string_array(security.value("blocked_ips", nlohmann::json::array()));
    }
}

void ConfigManager::parse_session_config(const nlohmann::json& config) {
    if (config.contains("session")) {
        const auto& session = config["session"];
        
        m_session_config.default_timeout = seconds(session.value("default_timeout", static_cast<int>(m_session_config.default_timeout.count())));
        m_session_config.max_sessions_per_user = session.value("max_sessions_per_user", m_session_config.max_sessions_per_user);
        m_session_config.cleanup_interval = seconds(session.value("cleanup_interval", static_cast<int>(m_session_config.cleanup_interval.count())));
        m_session_config.enable_session_persistence = session.value("enable_session_persistence", m_session_config.enable_session_persistence);
        m_session_config.persistence_file = session.value("persistence_file", m_session_config.persistence_file);
    }
}

void ConfigManager::parse_logging_config(const nlohmann::json& config) {
    if (config.contains("logging")) {
        const auto& logging = config["logging"];
        
        m_logging_config.level = logging.value("level", m_logging_config.level);
        m_logging_config.pattern = logging.value("pattern", m_logging_config.pattern);
        m_logging_config.enable_console_output = logging.value("enable_console_output", m_logging_config.enable_console_output);
        m_logging_config.enable_file_output = logging.value("enable_file_output", m_logging_config.enable_file_output);
        m_logging_config.log_file = logging.value("log_file", m_logging_config.log_file);
        m_logging_config.max_file_size = logging.value("max_file_size", m_logging_config.max_file_size);
        m_logging_config.max_files = logging.value("max_files", m_logging_config.max_files);
        m_logging_config.enable_security_log = logging.value("enable_security_log", m_logging_config.enable_security_log);
        m_logging_config.security_log_file = logging.value("security_log_file", m_logging_config.security_log_file);
        m_logging_config.enable_audit_log = logging.value("enable_audit_log", m_logging_config.enable_audit_log);
        m_logging_config.audit_log_file = logging.value("audit_log_file", m_logging_config.audit_log_file);
    }
}

void ConfigManager::parse_database_config(const nlohmann::json& config) {
    if (config.contains("database")) {
        const auto& database = config["database"];
        
        m_database_config.type = database.value("type", m_database_config.type);
        m_database_config.connection_string = database.value("connection_string", m_database_config.connection_string);
        m_database_config.username = database.value("username", m_database_config.username);
        m_database_config.password = database.value("password", m_database_config.password);
        m_database_config.enable_ssl = database.value("enable_ssl", m_database_config.enable_ssl);
        m_database_config.connection_pool_size = database.value("connection_pool_size", m_database_config.connection_pool_size);
        m_database_config.connection_timeout = seconds(database.value("connection_timeout", static_cast<int>(m_database_config.connection_timeout.count())));
    }
}

void ConfigManager::parse_target_services(const nlohmann::json& config) {
    if (config.contains("target_services")) {
        const auto& services = config["target_services"];
        
        if (services.is_object()) {
            for (auto& [name, service_json] : services.items()) {
                auto service_result = parse_target_service(service_json);
                if (service_result.is_success()) {
                    auto service = service_result.value();
                    service.name = name; // Use the key as the service name
                    m_target_services[name] = service;
                }
            }
        }
    }
}

Result<TargetService> ConfigManager::parse_target_service(const nlohmann::json& service_json) {
    try {
        TargetService service;
        
        service.host = service_json.value("host", "");
        service.port = service_json.value("port", 0);
        service.tls_enabled = service_json.value("tls_enabled", false);
        
        // Parse allowed roles
        if (service_json.contains("allowed_roles")) {
            const auto& roles_json = service_json["allowed_roles"];
            if (roles_json.is_array()) {
                for (const auto& role_json : roles_json) {
                    if (role_json.is_string()) {
                        string role_str = role_json.get<string>();
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
            return Result<TargetService>::error("Target service must have host and port");
        }
        
        return Result<TargetService>::success(service);
    } catch (const std::exception& e) {
        return Result<TargetService>::error("Failed to parse target service: " + string(e.what()));
    }
}

Result<void> ConfigManager::validate_server_config() {
    if (!ConfigUtils::is_valid_ip_address(m_server_config.listen_address) && 
        m_server_config.listen_address != "0.0.0.0") {
        return Result<void>::error("Invalid listen address: " + m_server_config.listen_address);
    }
    
    if (!ConfigUtils::is_valid_port(m_server_config.listen_port)) {
        return Result<void>::error("Invalid listen port: " + std::to_string(m_server_config.listen_port));
    }
    
    if (m_server_config.tls_cert_file.empty() || m_server_config.tls_key_file.empty()) {
        return Result<void>::error("TLS certificate and key files must be specified");
    }
    
    return Result<void>::success();
}

Result<void> ConfigManager::validate_security_config() {
    if (m_security_config.rate_limit_max_requests == 0) {
        return Result<void>::error("Rate limit max requests must be greater than 0");
    }
    
    if (m_security_config.rate_limit_window.count() == 0) {
        return Result<void>::error("Rate limit window must be greater than 0");
    }
    
    if (m_security_config.brute_force_threshold == 0) {
        return Result<void>::error("Brute force threshold must be greater than 0");
    }
    
    return Result<void>::success();
}

Result<void> ConfigManager::validate_session_config() {
    if (m_session_config.default_timeout.count() == 0) {
        return Result<void>::error("Session default timeout must be greater than 0");
    }
    
    if (m_session_config.max_sessions_per_user == 0) {
        return Result<void>::error("Max sessions per user must be greater than 0");
    }
    
    return Result<void>::success();
}

Result<void> ConfigManager::validate_logging_config() {
    if (!ConfigUtils::is_valid_log_level(m_logging_config.level)) {
        return Result<void>::error("Invalid log level: " + m_logging_config.level);
    }
    
    return Result<void>::success();
}

Result<void> ConfigManager::validate_database_config() {
    if (m_database_config.type.empty()) {
        return Result<void>::error("Database type must be specified");
    }
    
    if (m_database_config.connection_string.empty()) {
        return Result<void>::error("Database connection string must be specified");
    }
    
    return Result<void>::success();
}

Result<void> ConfigManager::validate_target_services() {
    for (const auto& [name, service] : m_target_services) {
        if (service.host.empty()) {
            return Result<void>::error("Target service '" + name + "' must have a host");
        }
        
        if (!ConfigUtils::is_valid_port(service.port)) {
            return Result<void>::error("Target service '" + name + "' has invalid port: " + std::to_string(service.port));
        }
        
        if (service.allowed_roles.empty()) {
            return Result<void>::error("Target service '" + name + "' must have at least one allowed role");
        }
    }
    
    return Result<void>::success();
}

string ConfigManager::get_config_value(const string& key, const string& default_value) {
    try {
        auto json_value = m_config_json;
        std::vector<string> keys;
        size_t pos = 0;
        string key_copy = key;
        
        while ((pos = key_copy.find('.')) != string::npos) {
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
            return json_value.get<string>();
        } else if (json_value.is_number() || json_value.is_boolean()) {
            return json_value.dump();
        }
    } catch (const std::exception&) {
        // Return default value on error
    }
    
    return default_value;
}

bool ConfigManager::file_exists(const string& filename) {
    std::ifstream file(filename);
    return file.good();
}

string ConfigManager::get_file_extension(const string& filename) {
    size_t pos = filename.find_last_of('.');
    if (pos != string::npos && pos != filename.length() - 1) {
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

nlohmann::json ConfigManager::get_default_config_json() {
    nlohmann::json config;
    
    // Default server configuration
    config["server"]["listen_address"] = "0.0.0.0";
    config["server"]["listen_port"] = 8443;
    config["server"]["tls_cert_file"] = "server.crt";
    config["server"]["tls_key_file"] = "server.key";
    config["server"]["thread_count"] = 0;
    config["server"]["verify_client_certificates"] = false;
    config["server"]["cipher_list"] = "HIGH:!aNULL:!MD5:!RC4";
    
    // Default security configuration
    config["security"]["rate_limit_max_requests"] = 100;
    config["security"]["rate_limit_window"] = 300;
    config["security"]["brute_force_threshold"] = 5;
    config["security"]["brute_force_window"] = 900;
    config["security"]["default_block_duration"] = 3600000;
    config["security"]["enable_ip_whitelist"] = false;
    config["security"]["allowed_ips"] = nlohmann::json::array();
    config["security"]["enable_ip_blacklist"] = false;
    config["security"]["blocked_ips"] = nlohmann::json::array();
    
    // Default session configuration
    config["session"]["default_timeout"] = 3600;
    config["session"]["max_sessions_per_user"] = 5;
    config["session"]["cleanup_interval"] = 300;
    config["session"]["enable_session_persistence"] = false;
    config["session"]["persistence_file"] = "sessions.json";
    
    // Default logging configuration
    config["logging"]["level"] = "info";
    config["logging"]["pattern"] = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";
    config["logging"]["enable_console_output"] = true;
    config["logging"]["enable_file_output"] = true;
    config["logging"]["log_file"] = "logs/zerossg.log";
    config["logging"]["max_file_size"] = 5242880; // 5MB
    config["logging"]["max_files"] = 3;
    config["logging"]["enable_security_log"] = true;
    config["logging"]["security_log_file"] = "logs/security.log";
    config["logging"]["enable_audit_log"] = true;
    config["logging"]["audit_log_file"] = "logs/audit.log";
    
    // Default database configuration
    config["database"]["type"] = "memory";
    config["database"]["connection_string"] = "localhost:5432/zerossg";
    config["database"]["username"] = "zerossg";
    config["database"]["password"] = "";
    config["database"]["enable_ssl"] = false;
    config["database"]["connection_pool_size"] = 10;
    config["database"]["connection_timeout"] = 30;
    
    // Default target services
    config["target_services"]["ssh"]["host"] = "internal-ssh-server";
    config["target_services"]["ssh"]["port"] = 22;
    config["target_services"]["ssh"]["tls_enabled"] = false;
    config["target_services"]["ssh"]["allowed_roles"] = nlohmann::json::array({"admin", "operator"});
    
    config["target_services"]["web-admin"]["host"] = "internal-web-server";
    config["target_services"]["web-admin"]["port"] = 443;
    config["target_services"]["web-admin"]["tls_enabled"] = true;
    config["target_services"]["web-admin"]["allowed_roles"] = nlohmann::json::array({"admin", "operator", "viewer"});
    
    return config;
}

// ConfigUtils implementation
string ConfigUtils::map_env_var(const string& config_key) {
    // Map configuration keys to environment variables
    if (config_key == "server.listen_address") return "ZEROSSG_LISTEN_ADDRESS";
    if (config_key == "server.listen_port") return "ZEROSSG_LISTEN_PORT";
    if (config_key == "server.tls_cert_file") return "ZEROSSG_TLS_CERT_FILE";
    if (config_key == "server.tls_key_file") return "ZEROSSG_TLS_KEY_FILE";
    if (config_key == "security.rate_limit_max_requests") return "ZEROSSG_RATE_LIMIT_MAX_REQUESTS";
    if (config_key == "logging.level") return "ZEROSSG_LOG_LEVEL";
    if (config_key == "logging.log_file") return "ZEROSSG_LOG_FILE";
    
    return "";
}

bool ConfigUtils::is_valid_port(int port) {
    return port > 0 && port <= 65535;
}

bool ConfigUtils::is_valid_ip_address(const string& ip) {
    // Simple validation - in production, use more sophisticated validation
    return !ip.empty() && ip != "0.0.0.0";
}

bool ConfigUtils::is_valid_log_level(const string& level) {
    return level == "trace" || level == "debug" || level == "info" || 
           level == "warn" || level == "error" || level == "critical";
}

bool ConfigUtils::is_valid_timeout(seconds timeout) {
    return timeout.count() > 0;
}

seconds ConfigUtils::parse_duration(const string& duration_str) {
    // Simple duration parsing - in production, use more sophisticated parsing
    try {
        int value = std::stoi(duration_str);
        return seconds(value);
    } catch (...) {
        return seconds(0);
    }
}

string ConfigUtils::format_duration(seconds duration) {
    return std::to_string(duration.count());
}

vector<string> ConfigUtils::parse_string_array(const nlohmann::json& json_array) {
    vector<string> result;
    if (json_array.is_array()) {
        for (const auto& item : json_array) {
            if (item.is_string()) {
                result.push_back(item.get<string>());
            }
        }
    }
    return result;
}

nlohmann::json ConfigUtils::serialize_string_array(const vector<string>& array) {
    nlohmann::json json_array = nlohmann::json::array();
    for (const auto& item : array) {
        json_array.push_back(item);
    }
    return json_array;
}

Result<string> ConfigUtils::read_file(const string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return Result<string>::error("Failed to open file: " + filename);
    }
    
    try {
        string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
        return Result<string>::success(content);
    } catch (const std::exception& e) {
        return Result<string>::error("Failed to read file: " + string(e.what()));
    }
}

Result<void> ConfigUtils::write_file(const string& filename, const string& content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return Result<void>::error("Failed to open file for writing: " + filename);
    }
    
    try {
        file << content;
        file.close();
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to write file: " + string(e.what()));
    }
}

bool ConfigUtils::create_directory(const string& path) {
    return std::filesystem::create_directories(path);
}

} // namespace zerossg
