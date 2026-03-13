export module zerossg.logging.logger;

import <string>;
import <memory>;

export namespace zerossg {

    class Logger {
    public:
        // Deleted constructor to enforce getting logger via get()
        Logger() = delete;

        static void init(const std::string& level = "info", const std::string& file_path = "", bool enable_console = true);
        static std::shared_ptr<Logger> get(const std::string& name);

        void trace(const std::string& msg);
        void debug(const std::string& msg);
        void info(const std::string& msg);
        void warn(const std::string& msg);
        void error(const std::string& msg);
        void critical(const std::string& msg);

    private:
        // Private constructor for make_shared
        Logger(const std::string& name);
        class Impl;
        std::unique_ptr<Impl> pimpl;
    };
}