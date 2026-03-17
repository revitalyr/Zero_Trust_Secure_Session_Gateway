#define BOOST_UT_DISABLE_MODULE
#include <boost/ut.hpp>
#include <memory>
#include <algorithm>
#include <optional> // Explicitly include optional before imports to avoid redefinition issues
import zerossg.rbac.authorizer;
import zerossg.types;

using namespace zerossg;

// Import needed types for tests
using zerossg::User;
using zerossg::Role;

boost::ut::suite AuthorizationSuite = [] {
    using namespace boost::ut;

    std::unique_ptr<AuthorizationManager> authz_manager;

    auto setup = [&] {
        authz_manager = std::make_unique<AuthorizationManager>();
    };

    "ServiceAccessByRole"_test = [&] {
        setup();
        // Create test users
        User admin_user("admin", "hash", zerossg::Role::ADMIN);
        User operator_user("operator", "hash", zerossg::Role::OPERATOR);
        User viewer_user("viewer", "hash", zerossg::Role::VIEWER);
        
        // Test SSH service (admin and operator only)
        auto ssh_access = authz_manager->can_access_service(admin_user, "ssh");
        expect(ssh_access.has_value());
        expect(ssh_access.value());
        
        ssh_access = authz_manager->can_access_service(operator_user, "ssh");
        expect(ssh_access.has_value());
        expect(ssh_access.value());
        
        ssh_access = authz_manager->can_access_service(viewer_user, "ssh");
        expect(ssh_access.has_value());
        expect(!ssh_access.value());
        
        // Test web-admin service (all roles)
        auto web_access = authz_manager->can_access_service(viewer_user, "web-admin");
        expect(web_access.has_value());
        expect(web_access.value());
        
        // Test database service (admin only)
        auto db_access = authz_manager->can_access_service(operator_user, "database");
        expect(db_access.has_value());
        expect(!db_access.value());
        
        db_access = authz_manager->can_access_service(admin_user, "database");
        expect(db_access.has_value());
        expect(db_access.value());
    };

    "PermissionChecking"_test = [&] {
        setup();
        User admin_user("admin", "hash", zerossg::Role::ADMIN);
        User operator_user("operator", "hash", zerossg::Role::OPERATOR);
        User viewer_user("viewer", "hash", zerossg::Role::VIEWER);
        
        // Test admin permissions
        auto permission = authz_manager->has_permission(admin_user, "user.delete");
        expect(permission.has_value());
        expect(permission.value());
        
        permission = authz_manager->has_permission(admin_user, "system.admin");
        expect(permission.has_value());
        expect(permission.value());
        
        // Test operator permissions
        permission = authz_manager->has_permission(operator_user, "session.create");
        expect(permission.has_value());
        expect(permission.value());
        
        permission = authz_manager->has_permission(operator_user, "user.delete");
        expect(permission.has_value());
        expect(!permission.value());
        
        // Test viewer permissions
        permission = authz_manager->has_permission(viewer_user, "service.read");
        expect(permission.has_value());
        expect(permission.value());
        
        permission = authz_manager->has_permission(viewer_user, "session.create");
        expect(permission.has_value());
        expect(!permission.value());
    };

    "AllowedServices"_test = [&] {
        setup();
        User viewer_user("viewer", "hash", Role::VIEWER);
        User admin_user("admin", "hash", Role::ADMIN);
        
        // Get allowed services for viewer
        auto services = authz_manager->get_allowed_services(viewer_user);
        expect(services.has_value());
        expect(services.value().size() == 1_ul); // Only web-admin
        expect(std::find(services.value().begin(), services.value().end(), "web-admin") != services.value().end());
        
        // Get allowed services for admin
        services = authz_manager->get_allowed_services(admin_user);
        expect(services.has_value());
        expect(services.value().size() == 3_ul); // All services
    };

    "ServiceManagement"_test = [&] {
        setup();
        // Create new service
        TargetService new_service("test-service", "test-host", 8080, {Role::ADMIN}, false);
        
        // Add service
        auto add_result = authz_manager->add_service(new_service);
        expect(add_result.has_value());
        
        // Get service
        auto get_result = authz_manager->get_service("test-service");
        expect(get_result.has_value());
        expect(get_result.value().has_value());
        expect(get_result.value()->name() == "test-service");
        expect(get_result.value()->host() == "test-host");
        expect(get_result.value()->port() == 8080_i);
        
        // Update service
        TargetService updated_service("test-service", "test-host", 9090, {Role::ADMIN}, false);
        auto update_result = authz_manager->update_service("test-service", updated_service);
        expect(update_result.has_value());
        
        // Verify update
        get_result = authz_manager->get_service("test-service");
        expect(get_result.has_value());
        expect(get_result.value()->port() == 9090_i);
        
        // Remove service
        auto remove_result = authz_manager->remove_service("test-service");
        expect(remove_result.has_value());
        
        // Verify removal
        get_result = authz_manager->get_service("test-service");
        expect(get_result.has_value());
        expect(!get_result.value().has_value());
    };

    "RolePermissions"_test = [&] {
        setup();
        // Test getting role permissions
        auto permissions = authz_manager->get_role_permissions(Role::ADMIN);
        expect(permissions.has_value());
        expect(permissions.value().size() > 0_ul);
        
        // Check for specific admin permission
        auto& perms = permissions.value();
        auto found = std::find(perms.begin(), perms.end(), "system.admin");
        expect(found != perms.end());
        
        // Add permission to role
        auto add_result = authz_manager->add_permission_to_role(Role::VIEWER, "custom.permission");
        expect(add_result.has_value());
        
        // Verify permission was added
        permissions = authz_manager->get_role_permissions(Role::VIEWER);
        expect(permissions.has_value());
        auto& viewer_perms = permissions.value();
        found = std::find(viewer_perms.begin(), viewer_perms.end(), "custom.permission");
        expect(found != viewer_perms.end());
        
        // Remove permission from role
        auto remove_result = authz_manager->remove_permission_from_role(Role::VIEWER, "custom.permission");
        expect(remove_result.has_value());
        
        // Verify permission was removed
        permissions = authz_manager->get_role_permissions(Role::VIEWER);
        expect(permissions.has_value());
        auto& final_viewer_perms = permissions.value();
        found = std::find(final_viewer_perms.begin(), final_viewer_perms.end(), "custom.permission");
        expect(found == final_viewer_perms.end());
    };

    "RoleHierarchy"_test = [&] {
        setup();
        // Test role hierarchy
        auto is_superior = authz_manager->is_role_superior(Role::ADMIN, Role::VIEWER);
        expect(is_superior.has_value());
        expect(is_superior.value());
        
        is_superior = authz_manager->is_role_superior(Role::VIEWER, Role::ADMIN);
        expect(is_superior.has_value());
        expect(!is_superior.value());
        
        is_superior = authz_manager->is_role_superior(Role::ADMIN, Role::ADMIN);
        expect(is_superior.has_value());
        expect(is_superior.value());
        
        // Set custom hierarchy
        auto set_result = authz_manager->set_role_hierarchy(Role::OPERATOR, Role::ADMIN);
        expect(set_result.has_value());
        
        // Test custom hierarchy
        is_superior = authz_manager->is_role_superior(Role::OPERATOR, Role::ADMIN);
        expect(is_superior.has_value());
        expect(is_superior.value());
    };
};
