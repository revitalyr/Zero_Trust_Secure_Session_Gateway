// Simple CLI test - Zero Trust Secure Session Gateway
// C++23 modules implementation

#include <iostream>
#include <string>
#include <vector>

// C++23 module imports
import zerossg.cli.cli_interface;

namespace zerossg {

// Simple CLI implementation for testing
class SimpleCLI : public CLIInterface {
public:
    SimpleCLI() = default;
};

} // namespace zerossg

int main(int argc, char* argv[]) {
    try {
        zerossg::SimpleCLI cli;
        return cli.run(argc, argv).value_or(1);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred\n";
        return 1;
    }
}
