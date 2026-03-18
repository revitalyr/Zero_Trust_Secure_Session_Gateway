module;
#include <algorithm>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

import zerossg.constants;
module zerossg.rbac.authorizer;


// C++23 module imports
import zerossg.constants;
import zerossg.types;
import zerossg.common; // For make_result_error, make_result_success, LockGuard

namespace zerossg {


AuthorizationManager::AuthorizationManager() {
    initialize_default_permissions();
    initialize_default_services();
}

zerossg::Result<bool> AuthorizationManager::can_access_service(const zerossg::User& user, const zerossg::ServiceName& service_name) {
    auto logger = zerossg::Logger::get("AuthorizationManager");
    LockGuard<std::mutex> lock(m_services_mutex);
    
    auto service_it = m_services.find(service_name);
    if (service_it == m_services.end()) {
        return make_result_error<bool>(ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    const zerossg::TargetService& service = service_it->second;
    return zerossg::make_result_success(can_role_access_service(user.role(), service));
}

zerossg::Result<bool> AuthorizationManager::has_permission(const zerossg::User& user, const zerossg::Permission& permission) {
   auto logger = Logger::get("AuthorizationManager");
    return zerossg::make_result_success(role_has_permission(user.role(), permission));
}

zerossg::Result<zerossg::Strings> AuthorizationManager::get_allowed_services(const zerossg::User& user) {
    LockGuard<std::mutex> lock(m_services_mutex);

   auto logger = zerossg::Logger::get("AuthorizationManager");
    zerossg::Strings allowed_services;
    
    for (const auto& pair : m_services) {
        const zerossg::TargetService& service = pair.second;
        if (can_role_access_service(user.role(), service)) {
            allowed_services.push_back(service.name());
        }
    }
    
    return zerossg::make_result_success(std::move(allowed_services));
}

zerossg::Result<void> AuthorizationManager::add_service(const zerossg::TargetService& service) {
    LockGuard<std::mutex> lock(m_services_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    m_services[service.name()] = service;
    return zerossg::make_result_success();
}

zerossg::Result<void> AuthorizationManager::update_service(const zerossg::ServiceName& service_name, const zerossg::TargetService& service) {
    LockGuard<std::mutex> lock(m_services_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return zerossg::make_result_error<void>(ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    m_services[service_name] = service;
    return zerossg::make_result_success();
}

zerossg::Result<void> AuthorizationManager::remove_service(const zerossg::ServiceName& service_name) {
    LockGuard<std::mutex> lock(m_services_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    if (m_services.erase(service_name) == 0) {
        return zerossg::make_result_error<void>(ERROR_SERVICE_NOT_FOUND_PREFIX + service_name);
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<std::optional<zerossg::TargetService>> AuthorizationManager::get_service(const zerossg::ServiceName& service_name) {
    LockGuard<std::mutex> lock(m_services_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    auto it = m_services.find(service_name);
    if (it == m_services.end()) {
        return zerossg::make_result_success(std::optional<zerossg::TargetService>{std::nullopt});
    }
    
    return zerossg::make_result_success(std::optional<zerossg::TargetService>{it->second});
}

zerossg::Result<zerossg::TargetServices> AuthorizationManager::list_services() {
    LockGuard<std::mutex> lock(m_services_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    zerossg::TargetServices services;
    services.reserve(m_services.size());
    
    for (const auto& pair : m_services) {
        services.push_back(pair.second);
    }
    
    return zerossg::make_result_success(std::move(services));
}

zerossg::Result<void> AuthorizationManager::add_permission_to_role(zerossg::Role role, const zerossg::Permission& permission) {
    LockGuard<std::mutex> lock(m_permissions_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    m_role_permissions[role].insert(permission);
    return zerossg::make_result_success();
}

zerossg::Result<void> AuthorizationManager::remove_permission_from_role(zerossg::Role role, const zerossg::Permission& permission) {
    LockGuard<std::mutex> lock(m_permissions_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    auto role_it = m_role_permissions.find(role);
    if (role_it != m_role_permissions.end()) {
        role_it->second.erase(permission);
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<zerossg::Permissions> AuthorizationManager::get_role_permissions(zerossg::Role role) {
    LockGuard<std::mutex> lock(m_permissions_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    auto it = m_role_permissions.find(role);
    if (it == m_role_permissions.end()) {
        return zerossg::make_result_success(zerossg::Permissions{});
    }
    
    zerossg::Permissions permissions(it->second.begin(), it->second.end());
    return zerossg::make_result_success(std::move(permissions));
}

zerossg::Result<void> AuthorizationManager::set_role_hierarchy(zerossg::Role superior, zerossg::Role subordinate) {
    LockGuard<std::mutex> lock(m_hierarchy_mutex);
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
    m_role_hierarchy[superior].insert(subordinate);
    return zerossg::make_result_success();
}

zerossg::Result<bool> AuthorizationManager::is_role_superior(zerossg::Role role_a, zerossg::Role role_b) {
    LockGuard<std::mutex> lock(m_hierarchy_mutex);
    
  auto logger = zerossg::Logger::get("AuthorizationManager");
    if (role_a == role_b) {
        return zerossg::make_result_success(true);
    }
    
    auto it = m_role_hierarchy.find(role_a);
    if (it == m_role_hierarchy.end()) {
        return zerossg::make_result_success(false);
    }
    
    // Check if role_b is in the hierarchy of role_a
    for (zerossg::Role subordinate : it->second) {
        if (subordinate == role_b) {
            return zerossg::make_result_success(true);
        }
        
        // Recursively check subordinates
        auto subordinate_result = is_role_superior(subordinate, role_b);
        if (subordinate_result.has_value() && subordinate_result.value()) {
            return zerossg::make_result_success(true);
        }
    }
    
    return zerossg::make_result_success(false);
}

void AuthorizationManager::initialize_default_permissions() {
    // Admin permissions - full access
    auto logger = zerossg::Logger::get("AuthorizationManager");

    std::set<Permission> admin_permissions = {
        PERMISSION_USER_CREATE, PERMISSION_USER_READ, PERMISSION_USER_UPDATE, PERMISSION_USER_DELETE,
        PERMISSION_SERVICE_CREATE, PERMISSION_SERVICE_READ, PERMISSION_SERVICE_UPDATE, PERMISSION_SERVICE_DELETE,
        PERMISSION_SESSION_CREATE, PERMISSION_SESSION_READ, PERMISSION_SESSION_DELETE,
        zerossg::PERMISSION_CONFIG_READ, zerossg::PERMISSION_CONFIG_UPDATE,
        zerossg::PERMISSION_LOGS_READ, zerossg::PERMISSION_LOGS_EXPORT,
        zerossg::PERMISSION_SYSTEM_ADMIN
    };

    m_role_permissions[zerossg::Role::ADMIN] = admin_permissions;
}
    
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
    auto logger = zerossg::Logger::get("AuthorizationManager");
 
    // SSH service example
    zerossg::TargetService ssh_service(
        zerossg::SERVICE_SSH_INTERNAL,
        zerossg::HOST_SSH_SERVER,
        zerossg::DEFAULT_SSH_PORT,
        {zerossg::Role::ADMIN, zerossg::Role::OPERATOR},
        false);
    m_services[zerossg::SERVICE_SSH_INTERNAL] = ssh_service;
 
    // Web service example
    zerossg::TargetService web_service(
        zerossg::SERVICE_WEB_ADMIN,
        zerossg::HOST_WEB_SERVER,
        zerossg::DEFAULT_WEB_PORT,
        {zerossg::Role::ADMIN, zerossg::Role::OPERATOR, zerossg::Role::VIEWER},
        true);
    m_services[zerossg::SERVICE_WEB_ADMIN] = web_service;
 
    // Database service example
    zerossg::TargetService db_service(
        zerossg::SERVICE_DATABASE_INTERNAL,
        zerossg::HOST_DB_SERVER,
        zerossg::DEFAULT_DATABASE_PORT,
        {zerossg::Role::ADMIN},
        true);
    m_services[zerossg::SERVICE_DATABASE_INTERNAL] = db_service;

bool AuthorizationManager::can_role_access_service(zerossg::Role role, const zerossg::TargetService& service) {
  auto logger = zerossg::Logger::get("AuthorizationManager");

    // Check if role is explicitly allowed
    if (std::find(service.allowed_roles().begin(), service.allowed_roles().end(), role) 
        != service.allowed_roles().end()) {
        return true;
    }
    
    // Check role hierarchy - if this role is superior to any allowed role
    for (zerossg::Role allowed_role : service.allowed_roles()) {
        auto hierarchy_result = is_role_superior(role, allowed_role);
        if (hierarchy_result.has_value() && hierarchy_result.value()) {
            return true;
        }
    }
    
    return false;
}

bool AuthorizationManager::role_has_permission(zerossg::Role role, const zerossg::Permission& permission) {
  auto logger = zerossg::Logger::get("AuthorizationManager");
    LockGuard<std::mutex> lock(m_permissions_mutex);
    
    auto it = m_role_permissions.find(role);
    if (it == m_role_permissions.end()) {
        return false;
    }
    
    // Check direct permission
    if (it->second.find(permission) != it->second.end()) {
        return true;
    }
    
    // Check hierarchical permissions
    LockGuard<std::mutex> hierarchy_lock(m_hierarchy_mutex);
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
    LockGuard<std::mutex> lock(m_hierarchy_mutex);    
  auto logger = zerossg::Logger::get("AuthorizationManager");
    
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
