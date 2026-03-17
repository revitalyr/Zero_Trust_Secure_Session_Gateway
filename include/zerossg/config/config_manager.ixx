module;
#include <mutex>
export module zerossg.config.config_manager;

export import zerossg.interfaces;
export import zerossg.std;
export import zerossg.common;
export import zerossg.types;
export import zerossg.third_party.nlohmann_json;
export import zerossg.third_party.yaml_cpp;

export namespace zerossg {

export class ConfigManager : public IConfigManager {
public:
    ConfigManager();
    ~ConfigManager() = default;

    Result<void> load_config(const ConfigFileName& config_file) override;
    String get_string(const String& key, const String& default_value = "") override;
    int get_int(const String& key, int default_value = 0) override;
    bool get_bool(const String& key, bool default_value = false) override;
    StringArray get_string_array(const String& key) override;
    Result<TargetService> get_target_service(const ServiceName& service_name) override;
    Result<TargetServices> get_all_target_services() override;
    Result<void> save_config(const ConfigFileName& config_file);
    Result<void> reload_config();
    Result<void> validate_config();

private:
    Result<void> load_yaml_config(const ConfigFileName& config_file);
    Result<void> load_json_config(const ConfigFileName& config_file);
    void parse_server_config(const json& config);
    void parse_security_config(const json& config);
    void parse_session_config(const json& config);
    void parse_logging_config(const json& config);
    void parse_database_config(const json& config);
    void parse_target_services(const json& config);
    Result<TargetService> parse_target_service(const json& service_json);

    Result<void> validate_server_config();
    Result<void> validate_security_config();
    Result<void> validate_session_config();
    Result<void> validate_logging_config();
    Result<void> validate_database_config();
    Result<void> validate_target_services();

    void load_from_environment();
    ConfigValue get_config_value(const ConfigKey& key, const ConfigValue& default_value);
    bool file_exists(const FilePath& filename);
    FileExtension get_file_extension(const FilePath& filename);
    void set_default_config();

    mutable std::mutex m_config_mutex;
    json m_config_json;
    ServerConfig m_server_config;
    SecurityConfig m_security_config;
    SessionConfig m_session_config;
    LoggingConfig m_logging_config;
    DatabaseConfig m_database_config;
    TargetServiceMap m_target_services;
};

export namespace ConfigUtils {
    bool is_valid_ip_address(const IpAddress& ip);
    Result<FileContent> read_file(const FilePath& filename);
    Result<void> write_file(const FilePath& filename, const FileContent& content);
    bool create_directory(const DirectoryPath& path);
}

} // namespace zerossg
