module;

#include <string>
#include <utility>
#include <stdexcept>
#include <optional>

export module zerossg.result;

export namespace zerossg {

    // Forward declaration
    template <typename T>
    class Result;

    using String = std::string;

    template <typename T>
    class Result {
    public:
        // Constructors for success case
        Result(const T& value) noexcept
            : m_value(value), m_is_success(true) {}

        Result(T&& value) noexcept
            : m_value(std::move(value)), m_is_success(true) {}

        // Static factory for creating an error result
        [[nodiscard]] static Result<T> error(const String& message) noexcept {
            return Result(message);
        }

        // Check status
        [[nodiscard]] bool is_success() const noexcept {
            return m_is_success;
        }

        // Accessors (throw on incorrect access)
        const T& value() const {
            if (!m_is_success) throw std::runtime_error("Attempted to access value of an error Result.");
            return m_value.value();
        }

        const String& error() const {
            if (m_is_success) throw std::runtime_error("Attempted to access error of a success Result.");
            return m_error;
        }

    private:
        // Private constructor for error case
        explicit Result(const String& error_message) noexcept
            : m_error(error_message), m_is_success(false) {}

        std::optional<T> m_value;
        String m_error;
        bool m_is_success;
    };

    // Specialization for void results
    template <>
    class Result<void> {
    public:
        // Default constructor for success
        Result() noexcept : m_is_success(true) {}

        [[nodiscard]] static Result<void> error(const String& message) noexcept {
            return Result<void>(message);
        }

        [[nodiscard]] bool is_success() const noexcept {
            return m_is_success;
        }

        const String& error() const {
            if (m_is_success) throw std::runtime_error("Attempted to access error of a success Result.");
            return m_error;
        }

    private:
        explicit Result(const String& error_message) noexcept
            : m_error(error_message), m_is_success(false) {}

        String m_error;
        bool m_is_success;
    };

    // Helper functions used in other parts of the code
    template <typename T>
    [[nodiscard]] inline Result<std::decay_t<T>> make_result_success(T&& value) noexcept {
        return Result<std::decay_t<T>>(std::forward<T>(value));
    }

    [[nodiscard]] inline Result<void> make_result_success() noexcept {
        return Result<void>();
    }

    template <typename T>
    [[nodiscard]] inline Result<T> make_result_error(const String& message) noexcept {
        return Result<T>::error(message);
    }

} // namespace zerossg