# Modern C++ Refactoring Guide

This guide provides comprehensive refactoring patterns for upgrading C++ code to modern standards (C++11 through C++26).

## Core Principles

### 1. Prefer RAII and Smart Pointers
- Replace raw `new`/`delete` with smart pointers
- Use `std::unique_ptr` for exclusive ownership
- Use `std::shared_ptr` for shared ownership
- Avoid `std::auto_ptr` (deprecated)

### 2. Embrace Value Semantics
- Implement move constructors and move assignment
- Use `std::move` and `std::forward`
- Design for copy elision
- Prefer pass-by-value with move for sink parameters

### 3. Use Modern Language Features
- Replace macros with `constexpr` and inline functions
- Use `nullptr` instead of `NULL` or `0`
- Use range-based for loops
- Leverage `auto` for type deduction

### 4. Follow Modern Naming Conventions
- Member variables: `snake_case` with `m_` prefix
- Static members: `snake_case` with `s_` prefix
- No trailing underscores
- Use semantic type aliases

## C++11 Essential Refactoring

### Smart Pointers
```cpp
// Before
class Resource {
    Data* data_;
public:
    Resource() : data_(new Data()) {}
    ~Resource() { delete data_; }
};

// After
class Resource {
    std::unique_ptr<Data> data_;
public:
    Resource() : data_(std::make_unique<Data>()) {}
    // Destructor automatically handles cleanup
};
```

### Move Semantics
```cpp
// Before
class Widget {
    std::vector<int> data_;
public:
    Widget(const Widget& other) : data_(other.data_) {} // Copy
};

// After
class Widget {
    std::vector<int> data_;
public:
    Widget(const Widget& other) = default;
    Widget(Widget&& other) noexcept : data_(std::move(other.data_)) {}
    Widget& operator=(Widget&& other) noexcept {
        data_ = std::move(other.data_);
        return *this;
    }
};
```

### Range-Based For Loops
```cpp
// Before
for (auto it = container.begin(); it != container.end(); ++it) {
    process(*it);
}

// After
for (auto& item : container) {
    process(item);
}
```

## C++14 Improvements

### Generic Lambdas
```cpp
// Before
auto lambda = [](int x) -> int { return x * 2; };

// After
auto lambda = [](auto x) { return x * 2; };
```

### Return Type Deduction
```cpp
// Before
template<typename T, typename U>
auto add(T t, U u) -> decltype(t + u) {
    return t + u;
}

// After
template<typename T, typename U>
auto add(T t, U u) {
    return t + u;
}
```

### `std::make_unique`
```cpp
// Before
auto ptr = std::unique_ptr<Widget>(new Widget(args));

// After
auto ptr = std::make_unique<Widget>(args);
```

## C++17 Features

### Structured Bindings
```cpp
// Before
auto pair = std::make_pair(42, "hello");
int value = pair.first;
std::string text = pair.second;

// After
auto [value, text] = std::make_pair(42, "hello");
```

### `std::optional`
```cpp
// Before
int* find_value(const std::map<int, int>& m, int key) {
    auto it = m.find(key);
    return it != m.end() ? &it->second : nullptr;
}

// After
std::optional<int> find_value(const std::map<int, int>& m, int key) {
    auto it = m.find(key);
    return it != m.end() ? std::optional<int>{it->second} : std::nullopt;
}
```

### `std::variant`
```cpp
// Before
union Data {
    int i;
    double d;
    char type;
};

// After
using Data = std::variant<int, double, std::string>;
```

### `std::string_view`
```cpp
// Before
void process(const std::string& str) {
    // Creates copy if not lvalue
}

// After
void process(std::string_view sv) {
    // No copy, works with string, const char*, etc.
}
```

## C++20 Innovations

### Concepts
```cpp
// Before
template<typename T>
class Container {
    static_assert(std::is_integral_v<typename T::value_type>, "Must contain integral type");
};

// After
template<typename T>
concept Integral = std::is_integral_v<T>;

template<Integral T>
class Container {
    // Constraint is part of template signature
};
```

### Ranges
```cpp
// Before
std::vector<int> result;
for (const auto& item : source) {
    if (item % 2 == 0) {
        result.push_back(item * item);
    }
}

// After
auto result = source 
    | std::views::filter([](int x) { return x % 2 == 0; })
    | std::views::transform([](int x) { return x * x; })
    | std::ranges::to<std::vector<int>>();
```

### Three-Way Comparison
```cpp
// Before
bool operator<(const Point& other) const {
    if (x != other.x) return x < other.x;
    return y < other.y;
}

// After
std::strong_ordering operator<=>(const Point& other) const {
    if (auto cmp = x <=> other.x; cmp != 0) return cmp;
    return y <=> other.y;
}
```

### Designated Initializers
```cpp
// Before
Point create_point(int x, int y) {
    Point p;
    p.x = x;
    p.y = y;
    return p;
}

// After
Point create_point(int x, int y) {
    return Point{.x = x, .y = y};
}
```

### `constexpr` Improvements
```cpp
// Before
constexpr bool is_power_of_two(int n) {
    return n > 0 && (n & (n - 1)) == 0;
}

// After
consteval bool is_power_of_two(int n) {
    return n > 0 && (n & (n - 1)) == 0;
}
```

## C++23 Features

### `std::expected`
```cpp
// Before
std::optional<int> divide(int a, int b) {
    if (b == 0) return std::nullopt;
    return a / b;
}

// After
std::expected<int, std::string> divide(int a, int b) {
    if (b == 0) return std::unexpected("Division by zero");
    return a / b;
}
```

### `std::mdspan`
```cpp
// Before
void process_matrix(int* data, size_t rows, size_t cols) {
    for (size_t i = 0; i < rows; ++i) {
        for (size_t j = 0; j < cols; ++j) {
            // Bounds checking required manually
            if (i * cols + j < rows * cols) {
                process_element(data[i * cols + j]);
            }
        }
    }
}

// After
void process_matrix(std::mdspan<int, std::dynamic_extent, std::dynamic_extent> matrix) {
    for (auto row : matrix) {
        for (auto element : row) {
            process_element(element);
        }
    }
}
```

### Deducing `this`
```cpp
// Before
template<typename Derived>
class Base {
    Derived* self() { return static_cast<Derived*>(this); }
};

// After
template<typename Derived>
class Base {
    auto self() { return static_cast<Derived*>(this); }
};
```

## C++26 Expected Features

### `constexpr` Improvements
```cpp
// More constexpr standard library functions
constexpr auto result = std::sqrt(144.0); // constexpr in C++26
```

### Enhanced Pattern Matching
```cpp
// After (speculated)
auto process(const std::variant<int, double, std::string>& v) {
    return std::visit([](const auto& value) {
        using T = std::decay_t<decltype(value)>;
        if constexpr (std::is_same_v<T, int>) {
            return "int: " + std::to_string(value);
        } else if constexpr (std::is_same_v<T, double>) {
            return "double: " + std::to_string(value);
        } else {
            return "string: " + value;
        }
    }, v);
}
```

## Refactoring Patterns

### Factory Pattern Modernization
```cpp
// Before
class WidgetFactory {
public:
    static Widget* create(const std::string& type) {
        if (type == "button") return new Button();
        if (type == "label") return new Label();
        return nullptr;
    }
};

// After
class WidgetFactory {
public:
    static std::unique_ptr<Widget> create(const std::string& type) {
        if (type == "button") return std::make_unique<Button>();
        if (type == "label") return std::make_unique<Label>();
        return nullptr;
    }
};
```

### Observer Pattern with `std::function`
```cpp
// Before
class Observer {
public:
    virtual void update(int value) = 0;
    virtual ~Observer() = default;
};

class Subject {
    std::vector<Observer*> observers_;
public:
    void notify(int value) {
        for (auto* obs : observers_) {
            obs->update(value);
        }
    }
};

// After
class Subject {
    std::vector<std::function<void(int)>> observers_;
public:
    void notify(int value) {
        for (const auto& obs : observers_) {
            obs(value);
        }
    }
};
```

### Error Handling Modernization
```cpp
// Before
bool process_data(const Data& data, Result& result) {
    if (!data.validate()) {
        result.error = "Invalid data";
        return false;
    }
    // Process data
    return true;
}

// After
std::expected<ProcessedData, std::string> process_data(const Data& data) {
    if (!data.validate()) {
        return std::unexpected("Invalid data");
    }
    // Process data
    return ProcessedData{/*...*/};
}
```

## Performance Optimizations

### Move-Aware Containers
```cpp
// Before
std::vector<std::string> strings;
for (const auto& str : input_strings) {
    strings.push_back(str); // Copy
}

// After
std::vector<std::string> strings;
strings.reserve(input_strings.size());
for (const auto& str : input_strings) {
    strings.emplace_back(str); // Move or perfect forward
}
```

### Cache-Friendly Data Structures
```cpp
// Before
class Node {
    std::unique_ptr<Node> left_;
    std::unique_ptr<Node> right_;
    int data_;
};

// After (for better cache locality)
class Node {
    std::array<std::unique_ptr<Node>, 2> children_; // Better cache layout
    int data_;
};
```

### Compile-Time Computations
```cpp
// Before
const int factorial(int n) {
    return n <= 1 ? 1 : n * factorial(n - 1);
}

// After
consteval int factorial(int n) {
    return n <= 1 ? 1 : n * factorial(n - 1);
}
```

## Testing Modernization

### GoogleTest with Modern Features
```cpp
// Before
TEST(MyTest, VectorOperations) {
    std::vector<int> v = {1, 2, 3};
    EXPECT_EQ(v.size(), 3);
}

// After
TEST(MyTest, VectorOperations) {
    constexpr std::array v = {1, 2, 3};
    static_assert(v.size() == 3);
    EXPECT_EQ(v, std::array{1, 2, 3});
}
```

### Parameterized Tests
```cpp
// After
class MyTest : public ::testing::TestWithParam<int> {};

TEST_P(MyTest, ParameterizedTest) {
    int param = GetParam();
    EXPECT_TRUE(process(param));
}

INSTANTIATE_TEST_SUITE_P(MyTest, 
    ::testing::Values(1, 2, 3, 4, 5));
```

## Build System Modernization

### CMake Updates
```cmake
# Modern CMake practices
cmake_minimum_required(VERSION 3.20)
project(MyProject VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Modern target creation
add_executable(myapp 
    src/main.cpp
    src/module.cpp
)

target_compile_features(myapp PUBLIC cxx_std_26)

# Modern linking
target_link_libraries(myapp 
    PRIVATE 
    Boost::boost_system
    OpenSSL::SSL
)

# Installation
include(GNUInstallDirs)
install(TARGETS myapp
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
```

## Migration Checklist

### C++11 Migration
- [ ] Replace raw pointers with smart pointers
- [ ] Use range-based for loops
- [ ] Add move semantics
- [ ] Use `nullptr` instead of `NULL`
- [ ] Replace macros with `constexpr`

### C++14 Migration
- [ ] Use `std::make_unique`
- [ ] Implement generic lambdas
- [ ] Use return type deduction
- [ ] Add `[[deprecated]]` attributes

### C++17 Migration
- [ ] Use structured bindings
- [ ] Replace optional pointers with `std::optional`
- [ ] Use `std::variant` instead of unions
- [ ] Use `std::string_view` for non-owning strings
- [ ] Use `std::filesystem`

### C++20 Migration
- [ ] Add concepts for template constraints
- [ ] Use ranges for algorithm composition
- [ ] Implement three-way comparison
- [ ] Use designated initializers
- [ ] Add `consteval` where possible

### C++23 Migration
- [ ] Use `std::expected` for error handling
- [ ] Use `std::mdspan` for array views
- [ ] Implement deducing `this`
- [ ] Use `std::print` for formatting

### C++26 Migration (Future)
- [ ] Use enhanced constexpr
- [ ] Implement pattern matching
- [ ] Use improved ranges
- [ ] Adopt new standard library features

## Common Pitfalls to Avoid

### Dangling References
```cpp
// Bad
std::string& get_bad() {
    std::string local = "temp";
    return local; // Dangling!
}

// Good
std::string get_good() {
    return "temp"; // RVO applies
}
```

### Self-Assignment
```cpp
// Bad
MyClass& operator=(const MyClass& other) {
    if (this != &other) {
        delete data_;
        data_ = new Data(*other.data_);
    }
    return *this;
}

// Good
MyClass& operator=(MyClass other) noexcept {
    if (this != &other) {
        data_ = std::move(other.data_);
    }
    return *this;
}
```

### Exception Safety
```cpp
// Bad
void bad_function() {
    Resource* r1 = new Resource();
    Resource* r2 = new Resource();
    delete r1; // Might leak if second new fails
    delete r2;
}

// Good
void good_function() {
    auto r1 = std::make_unique<Resource>();
    auto r2 = std::make_unique<Resource>();
    // Automatic cleanup, even if exceptions occur
}
```

## Tools and Automation

### Clang-Tidy Configuration
```yaml
# .clang-tidy
Checks: >
    modernize-*,
    performance-*,
    readability-*,
    bugprone-*
CheckOptions:
    - key-UseAuto
    - modernize-use-nullptr
    - modernize-use-override
```

### Clang-Format Configuration
```yaml
# .clang-format
BasedOnStyle: Google
IndentWidth: 4
ColumnLimit: 100
```

### Static Analysis
```bash
# Run clang-tidy
clang-tidy -checks='-*,modernize-*' src/*.cpp

# Run clang-format
clang-format -i src/*.cpp

# Use clang-analyzer
clang++ --analyze -Xanalyzer -std=c++20 src/*.cpp
```

## Continuous Integration

### GitHub Actions
```yaml
name: Modern C++ CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y clang-tidy clang-format
    - name: Build and test
      run: |
        cmake -B build -DCMAKE_BUILD_TYPE=Release
        cmake --build build
        cd build && ctest
    - name: Run clang-tidy
      run: |
        clang-tidy -p build src/**/*.cpp
    - name: Check format
      run: |
        clang-format --dry-run --Werror src/**/*.cpp
```

This refactoring guide provides a comprehensive roadmap for modernizing C++ code from legacy patterns to C++26 standards.
