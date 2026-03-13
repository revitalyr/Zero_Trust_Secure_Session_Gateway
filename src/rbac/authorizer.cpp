// C++23 module imports
import zerossg.rbac.authorizer;
import zerossg.constants;
import zerossg.types;
import zerossg.result;
import zerossg.std;

namespace zerossg {

AuthorizationManager::AuthorizationManager() {
    initialize_default_permissions();
    initialize_default_services();
}

zerossg::Result<bool> AuthorizationManager::can_access_service(const zerossg::User& user, const zerossg::ServiceName& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto service_it = m_services.find(service_name);
    if (service_it == m_services.end()) {
        return zerossg::Result<bool>::error(zerossg::ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    const zerossg::TargetService& service = service_it->second;
    return zerossg::Result<bool>::success(can_role_access_service(user.m_role, service));
}

zerossg::Result<bool> AuthorizationManager::has_permission(const zerossg::User& user, const zerossg::Permission& permission) {
    return zerossg::Result<bool>::success(role_has_permission(user.m_role, permission));
}

zerossg::Result<zerossg::Strings> AuthorizationManager::get_allowed_services(const zerossg::User& user) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    zerossg::Strings allowed_services;
    
    for (const auto& pair : m_services) {
        const zerossg::TargetService& service = pair.second;
        if (can_role_access_service(user.m_role, service)) {
            allowed_services.push_back(service.m_name);
        }
    }
    
    return zerossg::Result<zerossg::Strings>::success(std::move(allowed_services));
}

zerossg::Result<void> AuthorizationManager::add_service(const zerossg::TargetService& service) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    m_services[service.m_name] = service;
    return zerossg::Result<void>::success();
}

zerossg::Result<void> AuthorizationManager::update_service(const zerossg::ServiceName& service_name, const zerossg::TargetService& service) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return zerossg::Result<void>::error(zerossg::ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    m_services[service_name] = service;
    return zerossg::Result<void>::success();
}

zerossg::Result<void> AuthorizationManager::remove_service(const zerossg::ServiceName& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    if (m_services.erase(service_name) == 0) {
        return zerossg::Result<void>::error(zerossg::ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    return zerossg::Result<void>::success();
}

zerossg::Result<std::optional<zerossg::TargetService>> AuthorizationManager::get_service(const zerossg::ServiceName& service_name) {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return zerossg::Result<std::optional<zerossg::TargetService>>::success(std::nullopt);
    }
    
    return zerossg::Result<std::optional<zerossg::TargetService>>::success(it->second);
}

zerossg::Result<zerossg::TargetServices> AuthorizationManager::list_services() {
    std::lock_guard<std::mutex> lock(m_services_mutex);
    
    zerossg::TargetServices services;
    services.reserve(m_services.size());
    
    for (const auto& pair : m_services) {
        services.push_back(pair.second);
    }
    
    return zerossg::Result<zerossg::TargetServices>::success(std::move(services));
}

zerossg::Result<void> AuthorizationManager::add_permission_to_role(zerossg::Role role, const zerossg::Permission& permission) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    m_role_permissions[role].insert(permission);
    return zerossg::Result<void>::success();
}

zerossg::Result<void> AuthorizationManager::remove_permission_from_role(zerossg::Role role, const zerossg::Permission& permission) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    auto role_it = m_role_permissions.find(role);
    if (role_it != m_role_permissions.end()) {
        role_it->second.erase(permission);
    }
    
    return zerossg::Result<void>::success();
}

zerossg::Result<zerossg::Permissions> AuthorizationManager::get_role_permissions(zerossg::Role role) {
    std::lock_guard<std::mutex> lock(m_permissions_mutex);
    
    auto it = m_role_permissions.find(role);
    if (it == m_role_permissions.end()) {
        return zerossg::Result<zerossg::Permissions>::success(zerossg::Permissions{});
    }
    
    zerossg::Permissions permissions(it->second.begin(), it->second.end());
    return zerossg::Result<zerossg::Permissions>::success(std::move(permissions));
}

zerossg::Result<void> AuthorizationManager::set_role_hierarchy(zerossg::Role superior, zerossg::Role subordinate) {
    std::lock_guard<std::mutex> lock(m_hierarchy_mutex);
    
    m_role_hierarchy[superior].insert(subordinate);
    return zerossg::Result<void>::success();
}

zerossg::Result<bool> AuthorizationManager::is_role_superior(zerossg::Role role_a, zerossg::Role role_b) {
    std::lock_guard<std::mutex> lock(m_hierarchy_mutex);
    
    if (role_a == role_b) {
        return zerossg::Result<bool>::success(true);
    }
    
    auto it = m_role_hierarchy.find(role_a);
    if (it == m_role_hierarchy.end()) {
        return zerossg::Result<bool>::success(false);
    }
    
    // Check if role_b is in the hierarchy of role_a
    for (zerossg::Role subordinate : it->second) {
        if (subordinate == role_b) {
            return zerossg::Result<bool>::success(true);
        }
        
        // Recursively check subordinates
        auto subordinate_result = is_role_superior(subordinate, role_b);
        if (subordinate_result.is_success() && subordinate_result.value()) {
            return zerossg::Result<bool>::success(true);
        }
    }
    
    return zerossg::Result<bool>::success(false);
}

void AuthorizationManager::initialize_default_permissions() {
    // Admin permissions - full access
    m_role_permissions[zerossg::Role::ADMIN] = {
        zerossg::PERMISSION_USER_CREATE, zerossg::PERMISSION_USER_READ, zerossg::PERMISSION_USER_UPDATE, zerossg::PERMISSION_USER_DELETE,
        zerossg::PERMISSION_SERVICE_CREATE, zerossg::PERMISSION_SERVICE_READ, zerossg::PERMISSION_SERVICE_UPDATE, zerossg::PERMISSION_SERVICE_DELETE,
        zerossg::PERMISSION_SESSION_CREATE, zerossg::PERMISSION_SESSION_READ, zerossg::PERMISSION_SESSION_DELETE,
        zerossg::PERMISSION_CONFIG_READ, zerossg::PERMISSION_CONFIG_UPDATE,
        zerossg::PERMISSION_LOGS_READ, zerossg::PERMISSION_LOGS_EXPORT,
        zerossg::PERMISSION_SYSTEM_ADMIN
    };
    
    // Operator permissions - operational access
    m_role_permissions[zerossg::Role::OPERATOR] = {
        zerossg::PERMISSION_USER_READ,
        zerossg::PERMISSION_SERVICE_READ,
        zerossg::PERMISSION_SESSION_CREATE, zerossg::PERMISSION_SESSION_READ, zerossg::PERMISSION_SESSION_DELETE,
        zerossg::PERMISSION_CONFIG_READ,
        zerossg::PERMISSION_LOGS_READ
    };
    
    // Viewer permissions - read-only access
    m_role_permissions[zerossg::Role::VIEWER] = {
        zerossg::PERMISSION_USER_READ,
        zerossg::PERMISSION_SERVICE_READ,
        zerossg::PERMISSION_SESSION_READ,
        zerossg::PERMISSION_CONFIG_READ
    };
    
    // Set role hierarchy: ADMIN > OPERATOR > VIEWER
    m_role_hierarchy[zerossg::Role::ADMIN].insert(zerossg::Role::OPERATOR);
    m_role_hierarchy[zerossg::Role::ADMIN].insert(zerossg::Role::VIEWER);
    m_role_hierarchy[zerossg::Role::OPERATOR].insert(zerossg::Role::VIEWER);
}

void AuthorizationManager::initialize_default_services() {
    // SSH service example
    zerossg::TargetService ssh_service;
    ssh_service.name = zerossg::SERVICE_SSH_INTERNAL;
    ssh_service.host = zerossg::HOST_SSH_SERVER;
    ssh_service.port = zerossg::DEFAULT_SSH_PORT;
    ssh_service.allowed_roles = {zerossg::Role::ADMIN, zerossg::Role::OPERATOR};
    ssh_service.tls_enabled = false;
    m_services[zerossg::SERVICE_SSH_INTERNAL] = ssh_service;
    
    // Web service example
    zerossg::TargetService web_service;
    web_service.name = zerossg::SERVICE_WEB_ADMIN;
    web_service.host = zerossg::HOST_WEB_SERVER;
    web_service.port = zerossg::DEFAULT_WEB_PORT;
    web_service.allowed_roles = {zerossg::Role::ADMIN, zerossg::Role::OPERATOR, zerossg::Role::VIEWER};
    web_service.tls_enabled = true;
    m_services[zerossg::SERVICE_WEB_ADMIN] = web_service;
    
    // Database service example
    zerossg::TargetService db_service;
    db_service.name = zerossg::SERVICE_DATABASE_INTERNAL;
    db_service.host = zerossg::HOST_DB_SERVER;
    db_service.port = zerossg::DEFAULT_DATABASE_PORT;
    db_service.allowed_roles = {zerossg::Role::ADMIN};
    db_service.tls_enabled = true;
    m_services[zerossg::SERVICE_DATABASE_INTERNAL] = db_service;
}

bool AuthorizationManager::can_role_access_service(zerossg::Role role, const zerossg::TargetService& service) {
    // Check if role is explicitly allowed
    if (std::find(service.allowed_roles.begin(), service.allowed_roles.end(), role) 
        != service.allowed_roles.end()) {
        return true;
    }
    
    // Check role hierarchy - if this role is superior to any allowed role
    for (zerossg::Role allowed_role : service.allowed_roles) {
        auto hierarchy_result = is_role_superior(role, allowed_role);
        if (hierarchy_result.is_success() && hierarchy_result.value()) {
            return true;
        }
    }
    
    return false;
}

bool AuthorizationManager::role_has_permission(zerossg::Role role, const zerossg::Permission& permission) {
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

zerossg::Roles AuthorizationManager::get_inferior_roles(zerossg::Role role) {
    std::lock_guard<std::mutex> lock(m_hierarchy_mutex);
    
    zerossg::Roles inferior_roles;
    auto it = m_role_hierarchy.find(role);
    if (it != m_role_hierarchy.end()) {
        for (zerossg::Role subordinate : it->second) {
            inferior_roles.push_back(subordinate);
            // Recursively get subordinates of subordinates
            auto subordinates = get_inferior_roles(subordinate);
            inferior_roles.insert(inferior_roles.end(), subordinates.begin(), subordinates.end());
        }
    }
    
    return inferior_roles;
}

} // namespace zerossg
