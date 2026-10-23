#include <gtest/gtest.h>
#include <sodium.h>

#include "crypto.h"

TEST(Crypto, InitSucceeds) {
    EXPECT_TRUE(pm::init_crypto());
}

TEST(Crypto, InitIsSafeToCallTwice) {
    ASSERT_TRUE(pm::init_crypto());
    EXPECT_TRUE(pm::init_crypto());
}

TEST(Crypto, RandomBytesAreNotAllZero) {
    ASSERT_TRUE(pm::init_crypto());
    unsigned char buf[32] = {};
    randombytes_buf(buf, sizeof buf);

    bool any_nonzero = false;
    for (unsigned char b : buf) {
        any_nonzero = any_nonzero || b != 0;
    }
    EXPECT_TRUE(any_nonzero);
}
