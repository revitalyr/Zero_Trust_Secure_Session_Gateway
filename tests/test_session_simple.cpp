#include <gtest/gtest.h>

// Simple test without modules to check basic compilation
TEST(SimpleTest, BasicAssertions) {
    EXPECT_TRUE(true);
    EXPECT_EQ(1, 1);
    EXPECT_STRNE("hello", "world");
}
