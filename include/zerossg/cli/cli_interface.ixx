module;

#include <memory>
#include <vector>

export module zerossg.cli.cli_interface;

export import zerossg.common;

export namespace zerossg {

// CLI interface class
export class CLIInterface {
public:
    virtual ~CLIInterface() = default;
    Result<int> run(int argc, char* argv[]);
    void register_builtin_commands();
    void show_help();
    void show_status();
    void show_sessions();
    void show_users();
    void show_version();
    void export_audit_logs(const String& output_file);
};

} // namespace zerossg
