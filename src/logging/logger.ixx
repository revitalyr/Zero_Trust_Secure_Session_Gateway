export module zerossg.logging.logger;

import zerossg.std;
import zerossg.common;

export namespace zerossg {

    class Logger {
    public:
        // Deleted constructor to enforce getting logger via get()
        Logger() = delete;

        static void init(const String& level = "info", const FilePath& file_path = "", bool enable_console = true);
        static SharedPtr<Logger> get(const String& name);

        void trace(const String& msg);
        void debug(const String& msg);
        void info(const String& msg);
        void warn(const String& msg);
        void error(const String& msg);
        void critical(const String& msg);

    private:
        // Private constructor for make_shared
        Logger(const String& name);
        class Impl;
        UniquePtr<Impl> pimpl;
    };
}