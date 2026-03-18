module;

#include <mutex>
#include <unordered_map>
#include <set>
#include <optional>

export module zerossg.rbac.authorizer;

import zerossg.interfaces;
export import zerossg.common;
export import zerossg.types;

export namespace zerossg {

export class AuthorizationManager : public IAuthorizer {
public:
    AuthorizationManager();
    ~AuthorizationManager() = default;

    Result<bool> can_access_service(const User& user, const ServiceName& service_name) override;
    Result<bool> has_permission(const User& user, const String& permission) override;
    Result<Strings> get_allowed_services(const User& user) override;

    Result<void> add_service(const TargetService& service);
    Result<void> update_service(const ServiceName& service_name, const TargetService& service);
    Result<void> remove_service(const ServiceName& service_name);
    Result<std::optional<TargetService>> get_service(const ServiceName& service_name);
    Result<TargetServices> list_services();

    Result<void> add_permission_to_role(Role role, const Permission& permission);
    Result<void> remove_permission_from_role(Role role, const Permission& permission);
    Result<Permissions> get_role_permissions(Role role);

    Result<void> set_role_hierarchy(Role superior, Role subordinate);
    Result<bool> is_role_superior(Role role_a, Role role_b);

private:
    void initialize_default_permissions();
    void initialize_default_services();
    bool can_role_access_service(Role role, const TargetService& service);
    bool role_has_permission(Role role, const Permission& permission);
    Roles<Role> get_inferior_roles(Role role);

    mutable std::mutex m_services_mutex;
    mutable std::mutex m_permissions_mutex;
    mutable std::mutex m_hierarchy_mutex;

    TargetServiceMap m_services;
    UnorderedMap<Role, std::set<Permission>> m_role_permissions;
    UnorderedMap<Role, std::set<Role>> m_role_hierarchy;
};

} // namespace zerossg
