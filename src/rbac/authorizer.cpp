#include "zerossg/rbac/authorizer.hpp"
#include <algorithm>

namespace zerossg {

AuthorizationManager::AuthorizationManager() {
    initialize_default_permissions();
    initialize_default_services();
}

Result<bool> AuthorizationManager::can_access_service(const User& user, const string& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto service_it = m_services.find(service_name);
    if (service_it == m_services.end()) {
        return Result<bool>::error("Service not found: " + service_name);
    }
    
    const TargetService& service = service_it->second;
    return Result<bool>::success(can_role_access_service(user.role, service));
}

Result<bool> AuthorizationManager::has_permission(const User& user, const string& permission) {
    return Result<bool>::success(role_has_permission(user.role, permission));
}

Result<vector<string>> AuthorizationManager::get_allowed_services(const User& user) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    vector<string> allowed_services;
    
    for (const auto& pair : m_services) {
        const TargetService& service = pair.second;
        if (can_role_access_service(user.role, service)) {
            allowed_services.push_back(service.name);
        }
    }
    
    return Result<vector<string>>::success(std::move(allowed_services));
}

Result<void> AuthorizationManager::add_service(const TargetService& service) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    m_services[service.name] = service;
    return Result<void>::success();
}

Result<void> AuthorizationManager::update_service(const string& service_name, const TargetService& service) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return Result<void>::error("Service not found: " + service_name);
    }
    
    m_services[service_name] = service;
    return Result<void>::success();
}

Result<void> AuthorizationManager::remove_service(const string& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    if (m_services.erase(service_name) == 0) {
        return Result<void>::error("Service not found: " + service_name);
    }
    
    return Result<void>::success();
}

Result<optional<TargetService>> AuthorizationManager::get_service(const string& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return Result<optional<TargetService>>::success(std::nullopt);
    }
    
    return Result<optional<TargetService>>::success(it->second);
}

Result<vector<TargetService>> AuthorizationManager::list_services() {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    vector<TargetService> services;
    services.reserve(m_services.size());
    
    for (const auto& pair : m_services) {
        services.push_back(pair.second);
    }
    
    return Result<vector<TargetService>>::success(std::move(services));
}

Result<void> AuthorizationManager::add_permission_to_role(Role role, const string& permission) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    m_role_permissions[role].insert(permission);
    return Result<void>::success();
}

Result<void> AuthorizationManager::remove_permission_from_role(Role role, const string& permission) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    auto role_it = m_role_permissions.find(role);
    if (role_it != m_role_permissions.end()) {
        role_it->second.erase(permission);
    }
    
    return Result<void>::success();
}

Result<vector<string>> AuthorizationManager::get_role_permissions(Role role) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    auto it = m_role_permissions.find(role);
    if (it == m_role_permissions.end()) {
        return Result<vector<string>>::success(vector<string>{});
    }
    
    vector<string> permissions(it->second.begin(), it->second.end());
    return Result<vector<string>>::success(std::move(permissions));
}

Result<void> AuthorizationManager::set_role_hierarchy(Role superior, Role subordinate) {
    std::lock_guard<std::mutex> lock(m_hierarchy_mutex);
    
    m_role_hierarchy[superior].insert(subordinate);
    return Result<void>::success();
}

Result<bool> AuthorizationManager::is_role_superior(Role role_a, Role role_b) {
    std::lock_guard<std::mutex> lock(m_hierarchy_mutex);
    
    if (role_a == role_b) {
        return Result<bool>::success(true);
    }
    
    auto it = m_role_hierarchy.find(role_a);
    if (it == m_role_hierarchy.end()) {
        return Result<bool>::success(false);
    }
    
    // Check if role_b is in the hierarchy of role_a
    for (Role subordinate : it->second) {
        if (subordinate == role_b) {
            return Result<bool>::success(true);
        }
        
        // Recursively check subordinates
        auto subordinate_result = is_role_superior(subordinate, role_b);
        if (subordinate_result.is_success() && subordinate_result.value()) {
            return Result<bool>::success(true);
        }
    }
    
    return Result<bool>::success(false);
}

void AuthorizationManager::initialize_default_permissions() {
    // Admin permissions - full access
    m_role_permissions[Role::ADMIN] = {
        "user.create", "user.read", "user.update", "user.delete",
        "service.create", "service.read", "service.update", "service.delete",
        "session.create", "session.read", "session.update", "session.delete",
        "config.read", "config.update",
        "logs.read", "logs.export",
        "system.admin"
    };
    
    // Operator permissions - operational access
    m_role_permissions[Role::OPERATOR] = {
        "user.read",
        "service.read",
        "session.create", "session.read", "session.delete",
        "config.read",
        "logs.read"
    };
    
    // Viewer permissions - read-only access
    m_role_permissions[Role::VIEWER] = {
        "user.read",
        "service.read",
        "session.read",
        "config.read"
    };
    
    // Set role hierarchy: ADMIN > OPERATOR > VIEWER
    m_role_hierarchy[Role::ADMIN].insert(Role::OPERATOR);
    m_role_hierarchy[Role::ADMIN].insert(Role::VIEWER);
    m_role_hierarchy[Role::OPERATOR].insert(Role::VIEWER);
}

void AuthorizationManager::initialize_default_services() {
    // SSH service example
    TargetService ssh_service;
    ssh_service.name = "ssh";
    ssh_service.host = "internal-ssh-server";
    ssh_service.port = 22;
    ssh_service.allowed_roles = {Role::ADMIN, Role::OPERATOR};
    ssh_service.tls_enabled = false;
    m_services["ssh"] = ssh_service;
    
    // Web service example
    TargetService web_service;
    web_service.name = "web-admin";
    web_service.host = "internal-web-server";
    web_service.port = 443;
    web_service.allowed_roles = {Role::ADMIN, Role::OPERATOR, Role::VIEWER};
    web_service.tls_enabled = true;
    m_services["web-admin"] = web_service;
    
    // Database service example
    TargetService db_service;
    db_service.name = "database";
    db_service.host = "internal-db-server";
    db_service.port = 5432;
    db_service.allowed_roles = {Role::ADMIN};
    db_service.tls_enabled = true;
    m_services["database"] = db_service;
}

bool AuthorizationManager::can_role_access_service(Role role, const TargetService& service) {
    // Check if role is explicitly allowed
    if (std::find(service.allowed_roles.begin(), service.allowed_roles.end(), role) 
        != service.allowed_roles.end()) {
        return true;
    }
    
    // Check role hierarchy - if this role is superior to any allowed role
    for (Role allowed_role : service.allowed_roles) {
        auto hierarchy_result = is_role_superior(role, allowed_role);
        if (hierarchy_result.is_success() && hierarchy_result.value()) {
            return true;
        }
    }
    
    return false;
}

bool AuthorizationManager::role_has_permission(Role role, const string& permission) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    auto it = m_role_permissions.find(role);
    if (it == m_role_permissions.end()) {
        return false;
    }
    
    // Check direct permission
    if (it->second.find(permission) != it->second.end()) {
        return true;
    }
    
    // Check hierarchical permissions
    std::lock_guard<std::mutex> hierarchy_lock(m_hierarchy_mutex);
    for (const auto& pair : m_role_hierarchy) {
        if (pair.second.find(role) != pair.second.end()) {
            // role is subordinate to pair.first
            auto superior_it = m_role_permissions.find(pair.first);
            if (superior_it != m_role_permissions.end() &&
                superior_it->second.find(permission) != superior_it->second.end()) {
                return true;
            }
        }
    }
    
    return false;
}

vector<Role> AuthorizationManager::get_inferior_roles(Role role) {
    std::lock_guard<std::mutex> lock(m_hierarchy_mutex);
    
    vector<Role> inferior_roles;
    auto it = m_role_hierarchy.find(role);
    if (it != m_role_hierarchy.end()) {
        for (Role subordinate : it->second) {
            inferior_roles.push_back(subordinate);
            // Recursively get subordinates of subordinates
            auto subordinates = get_inferior_roles(subordinate);
            inferior_roles.insert(inferior_roles.end(), subordinates.begin(), subordinates.end());
        }
    }
    
    return inferior_roles;
}

} // namespace zerossg
