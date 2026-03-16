module;

#include <memory>
#include <string>
#include <vector>
#include <expected>

export module zerossg.cli.cli_interface;

export namespace zerossg {

// Type aliases
using String = std::string;
template<typename T, typename E = std::string>
using Result = std::expected<T, E>;

// Forward declarations
export class CLIInterface;

// CLI interface class
export class CLIInterface {
public:
    virtual ~CLIInterface() = default;
    virtual Result<int> run(int argc, char* argv[]);
    virtual void register_builtin_commands();
    virtual void show_help();
    virtual void show_status() = 0;
    virtual void show_sessions();
    virtual void show_users() = 0;
    virtual void show_version() = 0;
    virtual void export_audit_logs(const String& output_file);
};

} // namespace zerossg
