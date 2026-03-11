#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <functional>
#include <stdexcept>
#include <system_error>

namespace zerossg {

// Common type aliases
using std::string;
using std::unique_ptr;
using std::shared_ptr;
using std::weak_ptr;
using std::vector;
using std::unordered_map;
using std::chrono::system_clock;
using std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::optional;

// Result type for error handling
template<typename T>
class Result {
public:
    static Result success(T value) {
        return Result(std::move(value));
    }
    
    static Result error(std::string message) {
        return Result(std::move(message));
    }
    
    bool is_success() const { return m_has_value; }
    bool is_error() const { return !m_has_value; }
    
    const T& value() const {
        if (!m_has_value) {
            throw std::runtime_error("Attempting to access value of error result");
        }
        return m_value;
    }
    
    T& value() {
        if (!m_has_value) {
            throw std::runtime_error("Attempting to access value of error result");
        }
        return m_value;
    }
    
    const std::string& error() const {
        if (m_has_value) {
            throw std::runtime_error("Attempting to access error of success result");
        }
        return m_error;
    }

private:
    Result(T value) : m_value(std::move(value)), m_has_value(true) {}
    Result(std::string error) : m_error(std::move(error)), m_has_value(false) {}
    
    T m_value;
    std::string m_error;
    bool m_has_value;
};

// Specialization for void
template<>
class Result<void> {
public:
    static Result success() {
        return Result(true);
    }
    
    static Result error(std::string message) {
        return Result(std::move(message));
    }
    
    bool is_success() const { return m_success; }
    bool is_error() const { return !m_success; }
    
    const std::string& error() const {
        if (m_success) {
            throw std::runtime_error("Attempting to access error of success result");
        }
        return m_error;
    }

private:
    Result(bool success) : m_success(success) {}
    Result(std::string error) : m_error(std::move(error)), m_success(false) {}
    
    std::string m_error;
    bool m_success;
};

} // namespace zerossg
