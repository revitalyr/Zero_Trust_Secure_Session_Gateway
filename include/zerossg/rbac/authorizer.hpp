#pragma once

// C++23 module imports
import zerossg.interfaces;

// Standard library imports
import <mutex>;
import <unordered_map>;
import <unordered_set>;
import <vector>;

namespace zerossg {

class AuthorizationManager : public IAuthorizer {
public:
    AuthorizationManager();
    ~AuthorizationManager() override = default;
    
    // IAuthorizer interface
    Result<bool> can_access_service(const User& user, const ServiceName& service_name) override;
    Result<bool> has_permission(const User& user, const std::string& permission) override;
    Result<Strings> get_allowed_services(const User& user) override;
    
    // Service management
    Result<void> add_service(const TargetService& service);
    Result<void> update_service(const ServiceName& service_name, const TargetService& service);
    Result<void> remove_service(const ServiceName& service_name);
    Result<Optional<TargetService>> get_service(const ServiceName& service_name);
    Result<Vector<TargetService>> list_services();
    
    // Permission management
    Result<void> add_permission_to_role(Role role, const std::string& permission);
    Result<void> remove_permission_from_role(Role role, const std::string& permission);
    Result<Vector<std::string>> get_role_permissions(Role role);
    
    // Role hierarchy
    Result<void> set_role_hierarchy(Role superior, Role subordinate);
    Result<bool> is_role_superior(Role role_a, Role role_b);
    
private:
    // Service storage
    UnorderedMap<ServiceName, TargetService> m_services;
    mutable std::mutex m_services_mutex;
    
    // Role-based permissions
    UnorderedMap<Role, UnorderedSet<std::string>> m_role_permissions;
    mutable std::mutex m_permissions_mutex;
    
    // Role hierarchy (who can access what)
    UnorderedMap<Role, UnorderedSet<Role>> m_role_hierarchy;
    mutable std::mutex m_hierarchy_mutex;
    
    // Initialize default permissions and services
    void initialize_default_permissions();
    void initialize_default_services();
    
    // Helper methods
    bool can_role_access_service(Role role, const TargetService& service);
    bool role_has_permission(Role role, const std::string& permission);
    Vector<Role> get_inferior_roles(Role role);
};

} // namespace zerossg
