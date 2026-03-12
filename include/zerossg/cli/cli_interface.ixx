export module zerossg.cli.cli_interface;

export import <memory>;
export import <string>;
export import <vector>;

export namespace zerossg {

// Forward declarations
export class CLIInterface;

// CLI interface class
export class CLIInterface {
public:
    virtual ~CLIInterface() = default;
    virtual Result<int> run(int argc, char* argv[]) = 0;
    virtual void register_builtin_commands() = 0;
    virtual void show_help() = 0;
    virtual void show_status() = 0;
    virtual void show_sessions() = 0;
    virtual void show_users() = 0;
    virtual void show_version() = 0;
    virtual void export_audit_logs(const String& output_file) = 0;
};

} // namespace zerossg
