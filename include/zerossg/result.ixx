export module zerossg.result;

export import zerossg.std;

export namespace zerossg {

export template<typename T>
class Result {
public:
    // Constructors
    Result() = default;
    Result(const T& value) : m_value(value), m_has_value(true) {}
    Result(T&& value) : m_value(std::move(value)), m_has_value(true) {}
    Result(const String& error) : m_error(error), m_has_value(false) {}
    
    // Factory methods
    static Result<T> success(const T& value) { return Result<T>(value); }
    static Result<T> success(T&& value) { return Result<T>(std::move(value)); }
    static Result<T> error(const String& message) { return Result<T>(message); }
    
    // Accessors
    bool is_success() const { return m_has_value; }
    bool is_error() const { return !m_has_value; }
    
    const T& value() const {
        if (!m_has_value) {
            throw std::runtime_error("Attempted to access value of error result");
        }
        return m_value;
    }
    
    T& value() {
        if (!m_has_value) {
            throw std::runtime_error("Attempted to access value of error result");
        }
        return m_value;
    }
    
    const String& error() const {
        if (m_has_value) {
            throw std::runtime_error("Attempted to access error of success result");
        }
        return m_error;
    }
    
    // Convenience operators
    explicit operator bool() const { return m_has_value; }
    T& operator*() { return value(); }
    const T& operator*() const { return value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

private:
    T m_value{};
    String m_error{};
    bool m_has_value = false;
};

// Specialization for void
export template<>
class Result<void> {
public:
    Result() = default;
    Result(const String& error) : m_error(error), m_has_value(false) {}
    
    static Result<void> success() { return Result<void>(); }
    static Result<void> error(const String& message) { return Result<void>(message); }
    
    bool is_success() const { return m_has_value; }
    bool is_error() const { return !m_has_value; }
    
    const String& error() const {
        if (m_has_value) {
            throw std::runtime_error("Attempted to access error of success result");
        }
        return m_error;
    }
    
    explicit operator bool() const { return m_has_value; }

private:
    String m_error{};
    bool m_has_value = true;
};

// Helper functions
export template<typename T>
Result<T> make_result_success(const T& value) {
    return Result<T>::success(value);
}

export template<typename T>
Result<T> make_result_success(T&& value) {
    return Result<T>::success(std::move(value));
}

inline Result<void> make_result_success() {
    return Result<void>::success();
}

export template<typename T>
Result<T> make_result_error(const String& message) {
    return Result<T>::error(message);
}

} // namespace zerossg
