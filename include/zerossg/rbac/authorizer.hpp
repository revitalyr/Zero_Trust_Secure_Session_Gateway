#pragma once

#include "zerossg/interfaces.hpp"
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace zerossg {

class AuthorizationManager : public IAuthorizer {
public:
    AuthorizationManager();
    ~AuthorizationManager() override = default;
    
    // IAuthorizer interface
    Result<bool> can_access_service(const User& user, const string& service_name) override;
    Result<bool> has_permission(const User& user, const string& permission) override;
    Result<vector<string>> get_allowed_services(const User& user) override;
    
    // Service management
    Result<void> add_service(const TargetService& service);
    Result<void> update_service(const string& service_name, const TargetService& service);
    Result<void> remove_service(const string& service_name);
    Result<optional<TargetService>> get_service(const string& service_name);
    Result<vector<TargetService>> list_services();
    
    // Permission management
    Result<void> add_permission_to_role(Role role, const string& permission);
    Result<void> remove_permission_from_role(Role role, const string& permission);
    Result<vector<string>> get_role_permissions(Role role);
    
    // Role hierarchy
    Result<void> set_role_hierarchy(Role superior, Role subordinate);
    Result<bool> is_role_superior(Role role_a, Role role_b);
    
private:
    // Service storage
    unordered_map<string, TargetService> m_services;
    mutable std::mutex m_services_mutex;
    
    // Role-based permissions
    unordered_map<Role, unordered_set<string>> m_role_permissions;
    mutable std::mutex m_permissions_mutex;
    
    // Role hierarchy (who can access what)
    unordered_map<Role, unordered_set<Role>> m_role_hierarchy;
    mutable std::mutex m_hierarchy_mutex;
    
    // Initialize default permissions and services
    void initialize_default_permissions();
    void initialize_default_services();
    
    // Helper methods
    bool can_role_access_service(Role role, const TargetService& service);
    bool role_has_permission(Role role, const string& permission);
    vector<Role> get_inferior_roles(Role role);
};

} // namespace zerossg
