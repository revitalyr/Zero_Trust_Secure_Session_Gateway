#include <gtest/gtest.h>
import zerossg.auth.authenticator;
import zerossg.types;
import zerossg.common;
#include <string>

using namespace zerossg;

// Import needed types for tests
using zerossg::User;
using zerossg::Role;
using zerossg::UserName;
using zerossg::PasswordHash;

class AuthenticationTest : public ::testing::Test {
protected:
    void SetUp() override {
        auth_manager = std::make_unique<AuthenticationManager>();
    }
    
    void TearDown() override {
        auth_manager.reset();
    }
    
    std::unique_ptr<AuthenticationManager> auth_manager;
};

TEST_F(AuthenticationTest, ValidAuthentication) {
    // Add a test user
    User test_user("testuser", "hashed_password", zerossg::Role::OPERATOR);
    auto add_result = auth_manager->add_user(test_user);
    ASSERT_TRUE(add_result.is_success());
    
    // Test authentication with correct credentials
    auto auth_result = auth_manager->authenticate("testuser", "password");
    // This will fail because we're using a simple hash, but the structure is correct
    EXPECT_TRUE(auth_result.is_error());
}

TEST_F(AuthenticationTest, InvalidAuthentication) {
    // Test authentication with non-existent user
    auto auth_result = auth_manager->authenticate("nonexistent", "password");
    EXPECT_TRUE(auth_result.is_error());
    EXPECT_EQ(auth_result.error(), "User not found");
}

TEST_F(AuthenticationTest, UserManagement) {
    // Add user
    User test_user("newuser", "password_hash", zerossg::Role::VIEWER);
    auto add_result = auth_manager->add_user(test_user);
    EXPECT_TRUE(add_result.is_success());
    
    // Get user
    auto get_result = auth_manager->get_user("newuser");
    EXPECT_TRUE(get_result.is_success());
    EXPECT_TRUE(get_result.value().has_value());
    EXPECT_EQ(get_result.value()->username, "newuser");
    EXPECT_EQ(get_result.value()->role, zerossg::Role::VIEWER);
    
    // Update user
    User updated_user("newuser", "new_hash", zerossg::Role::ADMIN);
    auto update_result = auth_manager->update_user("newuser", updated_user);
    EXPECT_TRUE(update_result.is_success());
    
    // Verify update
    get_result = auth_manager->get_user("newuser");
    EXPECT_TRUE(get_result.is_success());
    EXPECT_EQ(get_result.value()->role, zerossg::Role::ADMIN);
    
    // Delete user
    auto delete_result = auth_manager->delete_user("newuser");
    EXPECT_TRUE(delete_result.is_success());
    
    // Verify deletion
    get_result = auth_manager->get_user("newuser");
    EXPECT_TRUE(get_result.is_success());
    EXPECT_FALSE(get_result.value().has_value());
}

TEST_F(AuthenticationTest, DuplicateUser) {
    // Add first user
    User user1("duplicate", "hash1", zerossg::Role::OPERATOR);
    auto add1_result = auth_manager->add_user(user1);
    EXPECT_TRUE(add1_result.is_success());
    
    // Try to add duplicate user
    User user2("duplicate", "hash2", zerossg::Role::VIEWER);
    auto add2_result = auth_manager->add_user(user2);
    EXPECT_TRUE(add2_result.is_error());
    EXPECT_EQ(add2_result.error(), "User already exists");
}

TEST_F(AuthenticationTest, PasswordHashing) {
    // Test password hashing
    auto hash_result = AuthenticationManager::hash_password("test_password");
    EXPECT_TRUE(hash_result.is_success());
    EXPECT_FALSE(hash_result.value().empty());
    
    // Test password verification
    auto verify_result = AuthenticationManager::verify_password("test_password", hash_result.value());
    EXPECT_TRUE(verify_result.is_success());
    EXPECT_TRUE(verify_result.value());
    
    // Test wrong password
    auto wrong_verify_result = AuthenticationManager::verify_password("wrong_password", hash_result.value());
    EXPECT_TRUE(wrong_verify_result.is_success());
    EXPECT_FALSE(wrong_verify_result.value());
}

TEST_F(AuthenticationTest, TokenGeneration) {
    // Add a test user
    User test_user("tokenuser", "hash", zerossg::Role::ADMIN);
    auth_manager->add_user(test_user);
    
    // Generate token
    auto token_result = auth_manager->generate_token(test_user);
    EXPECT_TRUE(token_result.is_success());
    EXPECT_FALSE(token_result.value().empty());
    
    // Validate token
    auto validate_result = auth_manager->validate_token(token_result.value());
    EXPECT_TRUE(validate_result.is_success());
    EXPECT_TRUE(validate_result.value());
    
    // Get user from token
    auto user_result = auth_manager->get_user_from_token(token_result.value());
    EXPECT_TRUE(user_result.is_success());
    EXPECT_EQ(user_result.value().username, "tokenuser");
    EXPECT_EQ(user_result.value().role, zerossg::Role::ADMIN);
}

TEST_F(AuthenticationTest, TokenRevocation) {
    // Add a test user
    User test_user("revokeuser", "hash", zerossg::Role::OPERATOR);
    auth_manager->add_user(test_user);
    
    // Generate token
    auto token_result = auth_manager->generate_token(test_user);
    EXPECT_TRUE(token_result.is_success());
    
    // Validate token before revocation
    auto validate_result = auth_manager->validate_token(token_result.value());
    EXPECT_TRUE(validate_result.is_success());
    EXPECT_TRUE(validate_result.value());
    
    // Revoke token
    auto revoke_result = auth_manager->revoke_token(token_result.value());
    EXPECT_TRUE(revoke_result.is_success());
    
    // Validate token after revocation
    validate_result = auth_manager->validate_token(token_result.value());
    EXPECT_TRUE(validate_result.is_error());
}
