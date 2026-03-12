#include <gtest/gtest.h>
#include "zerossg/session/session_manager.hpp"
import zerossg.types;
#include <thread>
#include <chrono>

using namespace zerossg;

class SessionManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        session_manager = std::make_unique<SessionManager>();
    }
    
    void TearDown() override {
        session_manager.reset();
    }
    
    std::unique_ptr<SessionManager> session_manager;
};

TEST_F(SessionManagerTest, CreateSession) {
    User test_user("testuser", "hash", Role::OPERATOR);
    string client_ip = "192.168.1.100";
    string target_service = "ssh";
    
    // Create session
    auto session_result = session_manager->create_session(test_user, client_ip, target_service);
    EXPECT_TRUE(session_result.is_success());
    EXPECT_FALSE(session_result.value().empty());
    
    // Get session
    auto get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_success());
    EXPECT_EQ(get_result.value().username, "testuser");
    EXPECT_EQ(get_result.value().client_ip, client_ip);
    EXPECT_EQ(get_result.value().target_service, target_service);
    EXPECT_TRUE(get_result.value().active);
}

TEST_F(SessionManagerTest, SessionValidation) {
    User test_user("testuser", "hash", Role::VIEWER);
    string client_ip = "192.168.1.101";
    string target_service = "web-admin";
    
    // Create session
    auto session_result = session_manager->create_session(test_user, client_ip, target_service);
    EXPECT_TRUE(session_result.is_success());
    
    // Validate session
    auto validate_result = session_manager->is_session_valid(session_result.value());
    EXPECT_TRUE(validate_result.is_success());
    EXPECT_TRUE(validate_result.value());
    
    // Terminate session
    auto terminate_result = session_manager->terminate_session(session_result.value());
    EXPECT_TRUE(terminate_result.is_success());
    
    // Validate terminated session
    validate_result = session_manager->is_session_valid(session_result.value());
    EXPECT_TRUE(validate_result.is_error());
}

TEST_F(SessionManagerTest, SessionUpdate) {
    User test_user("testuser", "hash", Role::ADMIN);
    string client_ip = "192.168.1.102";
    string target_service = "database";
    
    // Create session
    auto session_result = session_manager->create_session(test_user, client_ip, target_service);
    EXPECT_TRUE(session_result.is_success());
    
    // Get session
    auto get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_success());
    Session session = get_result.value();
    
    // Update session
    session.active = false;
    auto update_result = session_manager->update_session(session_result.value(), session);
    EXPECT_TRUE(update_result.is_success());
    
    // Verify update
    get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_success());
    EXPECT_FALSE(get_result.value().active);
}

TEST_F(SessionManagerTest, MultipleSessionsPerUser) {
    User test_user("testuser", "hash", Role::OPERATOR);
    string client_ip = "192.168.1.103";
    string target_service = "ssh";
    
    // Create maximum allowed sessions (5)
    std::vector<string> session_ids;
    for (int i = 0; i < 5; ++i) {
        auto session_result = session_manager->create_session(test_user, client_ip, target_service);
        EXPECT_TRUE(session_result.is_success());
        session_ids.push_back(session_result.value());
    }
    
    // Try to create one more session (should fail)
    auto session_result = session_manager->create_session(test_user, client_ip, target_service);
    EXPECT_TRUE(session_result.is_error());
    EXPECT_EQ(session_result.error(), "Maximum session limit reached for user: testuser");
    
    // Terminate one session
    auto terminate_result = session_manager->terminate_session(session_ids[0]);
    EXPECT_TRUE(terminate_result.is_success());
    
    // Now should be able to create a new session
    session_result = session_manager->create_session(test_user, client_ip, target_service);
    EXPECT_TRUE(session_result.is_success());
}

TEST_F(SessionManagerTest, ActiveSessionsList) {
    User user1("user1", "hash", Role::OPERATOR);
    User user2("user2", "hash", Role::VIEWER);
    
    // Create sessions
    auto session1_result = session_manager->create_session(user1, "192.168.1.104", "ssh");
    auto session2_result = session_manager->create_session(user2, "192.168.1.105", "web-admin");
    
    EXPECT_TRUE(session1_result.is_success());
    EXPECT_TRUE(session2_result.is_success());
    
    // Get active sessions
    auto active_result = session_manager->get_active_sessions();
    EXPECT_TRUE(active_result.is_success());
    EXPECT_EQ(active_result.value().size(), 2);
    
    // Terminate one session
    auto terminate_result = session_manager->terminate_session(session1_result.value());
    EXPECT_TRUE(terminate_result.is_success());
    
    // Check active sessions again
    active_result = session_manager->get_active_sessions();
    EXPECT_TRUE(active_result.is_success());
    EXPECT_EQ(active_result.value().size(), 1);
    EXPECT_EQ(active_result.value()[0].username, "user2");
}

TEST_F(SessionManagerTest, SessionExtension) {
    User test_user("testuser", "hash", Role::ADMIN);
    string client_ip = "192.168.1.106";
    string target_service = "database";
    
    // Create session
    auto session_result = session_manager->create_session(test_user, client_ip, target_service);
    EXPECT_TRUE(session_result.is_success());
    
    // Get original expiry time
    auto get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_success());
    auto original_expiry = get_result.value().expires_at;
    
    // Extend session by 1 hour
    auto extend_result = session_manager->extend_session(session_result.value(), seconds(3600));
    EXPECT_TRUE(extend_result.is_success());
    
    // Verify extension
    get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_success());
    auto new_expiry = get_result.value().expires_at;
    EXPECT_GT(new_expiry, original_expiry);
    EXPECT_EQ(new_expiry - original_expiry, seconds(3600));
}

TEST_F(SessionManagerTest, SessionFiltering) {
    User user1("user1", "hash", Role::OPERATOR);
    User user2("user2", "hash", Role::VIEWER);
    
    string client_ip1 = "192.168.1.107";
    string client_ip2 = "192.168.1.108";
    
    // Create sessions for different users and services
    auto session1_result = session_manager->create_session(user1, client_ip1, "ssh");
    auto session2_result = session_manager->create_session(user2, client_ip2, "web-admin");
    auto session3_result = session_manager->create_session(user1, client_ip1, "database");
    
    EXPECT_TRUE(session1_result.is_success());
    EXPECT_TRUE(session2_result.is_success());
    EXPECT_TRUE(session3_result.is_success());
    
    // Filter by user
    auto user_sessions = session_manager->get_sessions_by_user("user1");
    EXPECT_TRUE(user_sessions.is_success());
    EXPECT_EQ(user_sessions.value().size(), 2);
    
    // Filter by service
    auto ssh_sessions = session_manager->get_sessions_by_service("ssh");
    EXPECT_TRUE(ssh_sessions.is_success());
    EXPECT_EQ(ssh_sessions.value().size(), 1);
    EXPECT_EQ(ssh_sessions.value()[0].target_service, "ssh");
    
    // Filter by IP
    auto ip_sessions = session_manager->get_sessions_by_ip(client_ip1);
    EXPECT_TRUE(ip_sessions.is_success());
    EXPECT_EQ(ip_sessions.value().size(), 2);
}

TEST_F(SessionManagerTest, Statistics) {
    User test_user("testuser", "hash", Role::OPERATOR);
    
    // Check initial statistics
    EXPECT_EQ(session_manager->get_active_session_count(), 0);
    EXPECT_EQ(session_manager->get_total_session_count(), 0);
    
    // Create sessions
    auto session1_result = session_manager->create_session(test_user, "192.168.1.109", "ssh");
    auto session2_result = session_manager->create_session(test_user, "192.168.1.110", "web-admin");
    
    EXPECT_TRUE(session1_result.is_success());
    EXPECT_TRUE(session2_result.is_success());
    
    // Check statistics
    EXPECT_EQ(session_manager->get_active_session_count(), 2);
    EXPECT_EQ(session_manager->get_total_session_count(), 2);
    
    // Terminate one session
    auto terminate_result = session_manager->terminate_session(session1_result.value());
    EXPECT_TRUE(terminate_result.is_success());
    
    // Check statistics after termination
    EXPECT_EQ(session_manager->get_active_session_count(), 1);
    EXPECT_EQ(session_manager->get_total_session_count(), 2); // Total count doesn't decrease
}

TEST_F(SessionManagerTest, CleanupExpiredSessions) {
    User test_user("testuser", "hash", Role::VIEWER);
    
    // Create session
    auto session_result = session_manager->create_session(test_user, "192.168.1.111", "web-admin");
    EXPECT_TRUE(session_result.is_success());
    
    // Manually expire the session by setting expiry time in the past
    auto get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_success());
    Session session = get_result.value();
    session.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(1);
    auto update_result = session_manager->update_session(session_result.value(), session);
    EXPECT_TRUE(update_result.is_success());
    
    // Session should still be considered active before cleanup
    auto active_result = session_manager->get_active_sessions();
    EXPECT_TRUE(active_result.is_success());
    EXPECT_EQ(active_result.value().size(), 1);
    
    // Cleanup expired sessions
    auto cleanup_result = session_manager->cleanup_expired_sessions();
    EXPECT_TRUE(cleanup_result.is_success());
    
    // Session should no longer be active
    active_result = session_manager->get_active_sessions();
    EXPECT_TRUE(active_result.is_success());
    EXPECT_EQ(active_result.value().size(), 0);
    
    // Trying to get expired session should fail
    get_result = session_manager->get_session(session_result.value());
    EXPECT_TRUE(get_result.is_error());
    EXPECT_EQ(get_result.error(), "Session has expired: " + session_result.value());
}
