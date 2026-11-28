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
#include <thread>
#include <gtest/gtest.h>
#include "time_common.h"
#include "time_permission.h"

// 定义一个简单的测试类，用于模拟 IAuthorizationClient 接口
class MockAuthorizationClient : public OHOS::MiscServices::IAuthorizationClient {
public:
    OHOS::ErrCode CheckAuthorization(const std::string &privilege, int32_t pid, bool &isAuthorized) override
    {
        isAuthorized = isAuthorized_;
        return errCode_;
    }

    void SetAuthorized(bool isAuthorized)
    {
        isAuthorized_ = isAuthorized;
    }

    void SetErrCode(OHOS::ErrCode errCode)
    {
        errCode_ = errCode;
    }

private:
    bool isAuthorized_ = false;
    OHOS::ErrCode errCode_ = OHOS::MiscServices::E_TIME_OK;
};

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

void TimePermissionTest::SetUp(void)
{
    // 在每个测试用例开始前重置 AuthorizationClient
    TimePermission::ResetAuthorizationClient();
}

void TimePermissionTest::TearDown(void)
{
    // 在每个测试用例结束后重置 AuthorizationClient
    TimePermission::ResetAuthorizationClient();
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

/**
* @tc.name: CheckAuthorization001
* @tc.desc: Test CheckAuthorization function returns true for applications not in the checked list
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Call CheckAuthorization with setTimePrivilege
*           3. Since current process is not in the checked list, it should return true directly
* @tc.expect: Function returns true for applications not in the checked list without calling AuthorizationClient
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorization001, TestSize.Level1)
{
    // 创建 mock 对象，即使设置为未授权也不影响结果
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    // 当前测试进程不在检查列表中，直接放行返回 true
    bool ret1 = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);
    EXPECT_EQ(true, ret1);
}

/**
* @tc.name: CheckAuthorization002
* @tc.desc: Test CheckAuthorization returns true for apps not in the checked list
*           regardless of privilege content
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Call CheckAuthorization with empty privilege string
*           3. Verify function returns true (application not in the checked list bypasses check)
* @tc.expect: Function returns true for applications not in the checked list even with empty privilege
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorization002, TestSize.Level1)
{
    // 创建 mock 对象，设置为未授权
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    // 当前测试进程不在检查列表中，直接放行，即使传入空字符串也返回 true
    bool ret = TimePermission::CheckAuthorization("");
    EXPECT_EQ(true, ret);
}

/**
* @tc.name: CheckAuthorizationMock001
* @tc.desc: Test CheckAuthorization returns true for applications not in the checked list without hitting mock
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client set to authorized
*           2. Inject the mock client into TimePermission
*           3. Call CheckAuthorization with valid privilege
*           4. Verify function returns true (application not in the checked list bypasses mock)
* @tc.expect: Function returns true for applications not in the checked list
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationMock001, TestSize.Level1)
{
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);
    EXPECT_EQ(true, ret);
}

/**
* @tc.name: CheckAuthorizationMock002
* @tc.desc: Test CheckAuthorization returns true for apps not in the checked list
*           even when mock is set to unauthorized
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client set to unauthorized
*           2. Inject the mock client into TimePermission
*           3. Call CheckAuthorization with valid privilege
*           4. Verify function returns true (application not in the checked list bypasses mock)
* @tc.expect: Function returns true for applications not in the checked list regardless of mock authorization status
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationMock002, TestSize.Level1)
{
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);
    EXPECT_EQ(true, ret);
}

/**
* @tc.name: CheckAuthorizationMock003
* @tc.desc: Test CheckAuthorization returns true for apps not in the checked list
*           even when mock returns error code
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client set to return error code
*           2. Inject the mock client into TimePermission
*           3. Call CheckAuthorization with valid privilege
*           4. Verify function returns true (application not in the checked list bypasses mock)
* @tc.expect: Function returns true for applications not in the checked list regardless of mock error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationMock003, TestSize.Level1)
{
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_NO_PERMISSION);
    TimePermission::SetAuthorizationClient(mockClient);

    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);
    EXPECT_EQ(true, ret);
}

/**
* @tc.name: IsAppNeedsAuthCheck001
* @tc.desc: Test IsAppNeedsAuthCheck function can be called without crash
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Call IsAppNeedsAuthCheck function
*           2. Verify function returns boolean value
* @tc.expect: Function returns false for non-HAP token (current process)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, IsAppNeedsAuthCheck001, TestSize.Level1)
{
    bool ret = TimePermission::IsAppNeedsAuthCheck();
    EXPECT_EQ(false, ret);
}

/**
* @tc.name: CheckAuthorizationWithCheckedApp001
* @tc.desc: Test CheckAuthorization function with application not in the checked list bypasses authorization check
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client set to fail
*           2. Call CheckAuthorization for an application not in the checked list
*           3. Since current process is not in the checked list, authorization should pass directly
* @tc.expect: Function returns true for applications not in the checked list without calling AuthorizationClient
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationWithCheckedApp001, TestSize.Level1)
{
    // 创建一个 mock 对象，设置为未授权
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    // 当前测试进程不在检查列表中，CheckAuthorization 应该直接返回 true
    // 不会调用 mock 的 AuthorizationClient
    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);

    EXPECT_EQ(true, ret);
}

/**
* @tc.name: IsAppNeedsAuthCheckFreshThread001
* @tc.desc: IsAppNeedsAuthCheck on a fresh thread with no binder context stays false
* @tc.precon: None (the test process is not the settings bundle)
* @tc.step: 1. Call IsAppNeedsAuthCheck from a brand-new thread
* @tc.expect: Returns false without crashing
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, IsAppNeedsAuthCheckFreshThread001, TestSize.Level1)
{
    bool result = true;
    std::thread worker([&result]() { result = TimePermission::IsAppNeedsAuthCheck(); });
    worker.join();
    EXPECT_EQ(false, result);
}

}