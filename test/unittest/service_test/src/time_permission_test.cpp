/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdlib>
#include <ctime>
#include <chrono>
#include <fstream>
#include <gtest/gtest.h>
#include "time_common.h"
#include "time_permission.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;

class TimePermissionTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void TimePermissionTest::SetUpTestCase(void) {
}

void TimePermissionTest::TearDownTestCase(void) {
}

void TimePermissionTest::SetUp(void) {
}

void TimePermissionTest::TearDown(void) {
}

/**
* @tc.name: CheckCallingPermission001
* @tc.desc: Test time permission checking functionality with invalid and valid permission names
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Call CheckCallingPermission with empty permission name string
*           2. Verify function returns false for empty permission
*           3. Call CheckCallingPermission with non-empty permission name
*           4. Verify function returns false for invalid permission name
* @tc.expect: Both permission checks return false indicating permission denial for invalid inputs
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckCallingPermission001, TestSize.Level1)
{
    std::string permissionName("");
    bool ret = TimePermission::CheckCallingPermission(permissionName);
    EXPECT_EQ(false, ret);

    bool ret1 = TimePermission::CheckCallingPermission("permissionName");
    EXPECT_EQ(false, ret1);
}

}