module;

#include <expected>
#include <string>
#include <iostream>

export module zerossg.cli.cli_interface;

export namespace zerossg {

// Type aliases for CLI
using String = std::string;
template<typename T, typename E = std::string>
using Result = std::expected<T, E>;

// Minimal CLI interface class
export class CLIInterface {
public:
    CLIInterface() = default;
    virtual ~CLIInterface() = default;
    
    Result<int> run(int argc, char* argv[]);
    void show_help();
    void show_status();
    void show_version();
    
protected:
    void print_info(const String& message);
    void print_error(const String& message);
};

} // namespace zerossg
