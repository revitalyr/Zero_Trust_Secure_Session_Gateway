// C++23 module imports
import zerossg.rbac.authorizer;
import zerossg.constants;
import zerossg.types;
import zerossg.result; // Added Result import

namespace zerossg {

using zerossg::PERMISSION_CONFIG_UPDATE;
using zerossg::PERMISSION_LOGS_READ;
using zerossg::PERMISSION_LOGS_EXPORT;
using zerossg::PERMISSION_SYSTEM_ADMIN;
using zerossg::HOST_SSH_SERVER;
using zerossg::HOST_WEB_SERVER;
using zerossg::HOST_DB_SERVER;
using zerossg::SERVICE_WEB_ADMIN;
using zerossg::SERVICE_SSH_INTERNAL;
using zerossg::SERVICE_DATABASE_INTERNAL;
using zerossg::DEFAULT_SSH_PORT;
using zerossg::DEFAULT_WEB_PORT;
using zerossg::DEFAULT_DATABASE_PORT;

AuthorizationManager::AuthorizationManager() {
    initialize_default_permissions();
    initialize_default_services();
}

Result<bool> AuthorizationManager::can_access_service(const User& user, const ServiceName& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto service_it = m_services.find(service_name);
    if (service_it == m_services.end()) {
        return Result<bool>::error(ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    const TargetService& service = service_it->second;
    return Result<bool>::success(can_role_access_service(user.m_role, service));
}

Result<bool> AuthorizationManager::has_permission(const User& user, const String& permission) {
    return Result<bool>::success(role_has_permission(user.m_role, permission));
}

Result<Strings> AuthorizationManager::get_allowed_services(const User& user) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    Strings allowed_services;
    
    for (const auto& pair : m_services) {
        const TargetService& service = pair.second;
        if (can_role_access_service(user.m_role, service)) {
            allowed_services.push_back(service.m_name);
        }
    }
    
    return Result<Strings>::success(std::move(allowed_services));
}

Result<void> AuthorizationManager::add_service(const TargetService& service) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    m_services[service.m_name] = service;
    return Result<void>::success();
}

Result<void> AuthorizationManager::update_service(const ServiceName& service_name, const TargetService& service) {
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
        PERMISSION_USER_CREATE, PERMISSION_USER_READ, PERMISSION_USER_UPDATE, PERMISSION_USER_DELETE,
        PERMISSION_SERVICE_CREATE, PERMISSION_SERVICE_READ, PERMISSION_SERVICE_UPDATE, PERMISSION_SERVICE_DELETE,
        PERMISSION_SESSION_CREATE, PERMISSION_SESSION_READ, PERMISSION_SESSION_DELETE,
        PERMISSION_CONFIG_READ, PERMISSION_CONFIG_UPDATE,
        PERMISSION_LOGS_READ, PERMISSION_LOGS_EXPORT,
        PERMISSION_SYSTEM_ADMIN
    };
    
    // Operator permissions - operational access
    m_role_permissions[Role::OPERATOR] = {
        PERMISSION_USER_READ,
        PERMISSION_SERVICE_READ,
        PERMISSION_SESSION_CREATE, PERMISSION_SESSION_READ, PERMISSION_SESSION_DELETE,
        PERMISSION_CONFIG_READ,
        PERMISSION_LOGS_READ
    };
    
    // Viewer permissions - read-only access
    m_role_permissions[Role::VIEWER] = {
        PERMISSION_USER_READ,
        PERMISSION_SERVICE_READ,
        PERMISSION_SESSION_READ,
        PERMISSION_CONFIG_READ
    };
    
    // Set role hierarchy: ADMIN > OPERATOR > VIEWER
    m_role_hierarchy[Role::ADMIN].insert(Role::OPERATOR);
    m_role_hierarchy[Role::ADMIN].insert(Role::VIEWER);
    m_role_hierarchy[Role::OPERATOR].insert(Role::VIEWER);
}

void AuthorizationManager::initialize_default_services() {
    // SSH service example
    TargetService ssh_service;
    ssh_service.name = SERVICE_SSH_INTERNAL;
    ssh_service.host = HOST_SSH_SERVER;
    ssh_service.port = DEFAULT_SSH_PORT;
    ssh_service.allowed_roles = {Role::ADMIN, Role::OPERATOR};
    ssh_service.tls_enabled = false;
    m_services[SERVICE_SSH_INTERNAL] = ssh_service;
    
    // Web service example
    TargetService web_service;
    web_service.name = SERVICE_WEB_ADMIN;
    web_service.host = HOST_WEB_SERVER;
    web_service.port = DEFAULT_WEB_PORT;
    web_service.allowed_roles = {Role::ADMIN, Role::OPERATOR, Role::VIEWER};
    web_service.tls_enabled = true;
    m_services[SERVICE_WEB_ADMIN] = web_service;
    
    // Database service example
    TargetService db_service;
    db_service.name = SERVICE_DATABASE_INTERNAL;
    db_service.host = HOST_DB_SERVER;
    db_service.port = DEFAULT_DATABASE_PORT;
    db_service.allowed_roles = {Role::ADMIN};
    db_service.tls_enabled = true;
    m_services[SERVICE_DATABASE_INTERNAL] = db_service;
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
