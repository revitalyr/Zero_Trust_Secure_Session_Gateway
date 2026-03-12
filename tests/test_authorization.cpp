#include <gtest/gtest.h>
#include "zerossg/rbac/authorizer.hpp"
import zerossg.types;

using namespace zerossg;

// Import needed types for tests
using zerossg::User;
using zerossg::Role;
using zerossg::UserName;

class AuthorizationTest : public ::testing::Test {
protected:
    void SetUp() override {
        authz_manager = std::make_unique<AuthorizationManager>();
    }
    
    void TearDown() override {
        authz_manager.reset();
    }
    
    std::unique_ptr<AuthorizationManager> authz_manager;
};

TEST_F(AuthorizationTest, ServiceAccessByRole) {
    // Create test users
    User admin_user("admin", "hash", zerossg::Role::ADMIN);
    User operator_user("operator", "hash", zerossg::Role::OPERATOR);
    User viewer_user("viewer", "hash", zerossg::Role::VIEWER);
    
    // Test SSH service (admin and operator only)
    auto ssh_access = authz_manager->can_access_service(admin_user, "ssh");
    EXPECT_TRUE(ssh_access.is_success());
    EXPECT_TRUE(ssh_access.value());
    
    ssh_access = authz_manager->can_access_service(operator_user, "ssh");
    EXPECT_TRUE(ssh_access.is_success());
    EXPECT_TRUE(ssh_access.value());
    
    ssh_access = authz_manager->can_access_service(viewer_user, "ssh");
    EXPECT_TRUE(ssh_access.is_success());
    EXPECT_FALSE(ssh_access.value());
    
    // Test web-admin service (all roles)
    auto web_access = authz_manager->can_access_service(viewer_user, "web-admin");
    EXPECT_TRUE(web_access.is_success());
    EXPECT_TRUE(web_access.value());
    
    // Test database service (admin only)
    auto db_access = authz_manager->can_access_service(operator_user, "database");
    EXPECT_TRUE(db_access.is_success());
    EXPECT_FALSE(db_access.value());
    
    db_access = authz_manager->can_access_service(admin_user, "database");
    EXPECT_TRUE(db_access.is_success());
    EXPECT_TRUE(db_access.value());
}

TEST_F(AuthorizationTest, PermissionChecking) {
    User admin_user("admin", "hash", zerossg::Role::ADMIN);
    User operator_user("operator", "hash", zerossg::Role::OPERATOR);
    User viewer_user("viewer", "hash", zerossg::Role::VIEWER);
    
    // Test admin permissions
    auto permission = authz_manager->has_permission(admin_user, "user.delete");
    EXPECT_TRUE(permission.is_success());
    EXPECT_TRUE(permission.value());
    
    permission = authz_manager->has_permission(admin_user, "system.admin");
    EXPECT_TRUE(permission.is_success());
    EXPECT_TRUE(permission.value());
    
    // Test operator permissions
    permission = authz_manager->has_permission(operator_user, "session.create");
    EXPECT_TRUE(permission.is_success());
    EXPECT_TRUE(permission.value());
    
    permission = authz_manager->has_permission(operator_user, "user.delete");
    EXPECT_TRUE(permission.is_success());
    EXPECT_FALSE(permission.value());
    
    // Test viewer permissions
    permission = authz_manager->has_permission(viewer_user, "service.read");
    EXPECT_TRUE(permission.is_success());
    EXPECT_TRUE(permission.value());
    
    permission = authz_manager->has_permission(viewer_user, "session.create");
    EXPECT_TRUE(permission.is_success());
    EXPECT_FALSE(permission.value());
}

TEST_F(AuthorizationTest, AllowedServices) {
    User viewer_user("viewer", "hash", Role::VIEWER);
    User admin_user("admin", "hash", Role::ADMIN);
    
    // Get allowed services for viewer
    auto services = authz_manager->get_allowed_services(viewer_user);
    EXPECT_TRUE(services.is_success());
    EXPECT_EQ(services.value().size(), 1); // Only web-admin
    EXPECT_TRUE(std::find(services.value().begin(), services.value().end(), "web-admin") != services.value().end());
    
    // Get allowed services for admin
    services = authz_manager->get_allowed_services(admin_user);
    EXPECT_TRUE(services.is_success());
    EXPECT_EQ(services.value().size(), 3); // All services
}

TEST_F(AuthorizationTest, ServiceManagement) {
    // Create new service
    TargetService new_service;
    new_service.name = "test-service";
    new_service.host = "test-host";
    new_service.port = 8080;
    new_service.tls_enabled = false;
    new_service.allowed_roles = {Role::ADMIN};
    
    // Add service
    auto add_result = authz_manager->add_service(new_service);
    EXPECT_TRUE(add_result.is_success());
    
    // Get service
    auto get_result = authz_manager->get_service("test-service");
    EXPECT_TRUE(get_result.is_success());
    EXPECT_TRUE(get_result.value().has_value());
    EXPECT_EQ(get_result.value()->name, "test-service");
    EXPECT_EQ(get_result.value()->host, "test-host");
    EXPECT_EQ(get_result.value()->port, 8080);
    
    // Update service
    new_service.port = 9090;
    auto update_result = authz_manager->update_service("test-service", new_service);
    EXPECT_TRUE(update_result.is_success());
    
    // Verify update
    get_result = authz_manager->get_service("test-service");
    EXPECT_TRUE(get_result.is_success());
    EXPECT_EQ(get_result.value()->port, 9090);
    
    // Remove service
    auto remove_result = authz_manager->remove_service("test-service");
    EXPECT_TRUE(remove_result.is_success());
    
    // Verify removal
    get_result = authz_manager->get_service("test-service");
    EXPECT_TRUE(get_result.is_success());
    EXPECT_FALSE(get_result.value().has_value());
}

TEST_F(AuthorizationTest, RolePermissions) {
    // Test getting role permissions
    auto permissions = authz_manager->get_role_permissions(Role::ADMIN);
    EXPECT_TRUE(permissions.is_success());
    EXPECT_GT(permissions.value().size(), 0);
    
    // Check for specific admin permission
    auto found = std::find(permissions.value().begin(), permissions.value().end(), "system.admin");
    EXPECT_NE(found, permissions.value().end());
    
    // Add permission to role
    auto add_result = authz_manager->add_permission_to_role(Role::VIEWER, "custom.permission");
    EXPECT_TRUE(add_result.is_success());
    
    // Verify permission was added
    permissions = authz_manager->get_role_permissions(Role::VIEWER);
    EXPECT_TRUE(permissions.is_success());
    found = std::find(permissions.value().begin(), permissions.value().end(), "custom.permission");
    EXPECT_NE(found, permissions.value().end());
    
    // Remove permission from role
    auto remove_result = authz_manager->remove_permission_from_role(Role::VIEWER, "custom.permission");
    EXPECT_TRUE(remove_result.is_success());
    
    // Verify permission was removed
    permissions = authz_manager->get_role_permissions(Role::VIEWER);
    EXPECT_TRUE(permissions.is_success());
    found = std::find(permissions.value().begin(), permissions.value().end(), "custom.permission");
    EXPECT_EQ(found, permissions.value().end());
}

TEST_F(AuthorizationTest, RoleHierarchy) {
    // Test role hierarchy
    auto is_superior = authz_manager->is_role_superior(Role::ADMIN, Role::VIEWER);
    EXPECT_TRUE(is_superior.is_success());
    EXPECT_TRUE(is_superior.value());
    
    is_superior = authz_manager->is_role_superior(Role::VIEWER, Role::ADMIN);
    EXPECT_TRUE(is_superior.is_success());
    EXPECT_FALSE(is_superior.value());
    
    is_superior = authz_manager->is_role_superior(Role::ADMIN, Role::ADMIN);
    EXPECT_TRUE(is_superior.is_success());
    EXPECT_TRUE(is_superior.value());
    
    // Set custom hierarchy
    auto set_result = authz_manager->set_role_hierarchy(Role::OPERATOR, Role::ADMIN);
    EXPECT_TRUE(set_result.is_success());
    
    // Test custom hierarchy
    is_superior = authz_manager->is_role_superior(Role::OPERATOR, Role::ADMIN);
    EXPECT_TRUE(is_superior.is_success());
    EXPECT_TRUE(is_superior.value());
}
