#include <gtest/gtest.h>

// Basic test without modules to verify compilation
TEST(BasicTest, SimpleAssertions) {
    EXPECT_TRUE(true);
    EXPECT_EQ(42, 42);
    EXPECT_STRNE("hello", "world");
}

TEST(BasicTest, MoreAssertions) {
    EXPECT_FALSE(false);
    EXPECT_NE(1, 2);
    EXPECT_STREQ("test", "test");
}
