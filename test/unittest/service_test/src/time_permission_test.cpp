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
* @tc.desc: Test CheckAuthorization function with authorized and unauthorized scenarios using mock
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Set mock to return authorized = true
*           3. Call CheckAuthorization with setTimePrivilege
*           4. Verify function returns true
*           5. Set mock to return authorized = false
*           6. Call CheckAuthorization again
*           7. Verify function returns false
* @tc.expect: Function returns correct authorization status based on mock
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorization001, TestSize.Level1)
{
    // 创建 mock 对象
    auto mockClient = std::make_shared<MockAuthorizationClient>();

    // 测试场景1：授权成功
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    // Test with setTimePrivilege (ohos.privilege.modify_system_time)
    bool ret1 = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);
    EXPECT_EQ(true, ret1);

    // 测试场景2：授权失败
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    // mock 对象已注入，直接测试
    bool ret2 = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);
    EXPECT_EQ(false, ret2);
}

/**
* @tc.name: CheckAuthorization002
* @tc.desc: Test CheckAuthorization function with empty privilege string using mock
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Call CheckAuthorization with empty privilege string
*           3. Verify function returns false (mock should not be called for empty)
* @tc.expect: Function returns false for empty privilege string
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorization002, TestSize.Level1)
{
    // 创建 mock 对象，设置为未授权（验证空字符串直接返回 false，不依赖 mock）
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    // 空字符串应该直接返回 false
    bool ret = TimePermission::CheckAuthorization("");
    EXPECT_EQ(false, ret);
}

/**
* @tc.name: CheckAuthorizationMock001
* @tc.desc: Test CheckAuthorization function with authorized privilege using mock client
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Set expectation for CheckAuthorization method to return E_TIME_OK and isAuthorized = true
*           3. Inject the mock client into TimePermission
*           4. Call CheckAuthorization with valid privilege (setTimePrivilege)
*           5. Verify function returns true indicating authorization success
* @tc.expect: Function returns true for authorized privilege
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationMock001, TestSize.Level1)
{
    // 创建一个 mock 对象
    auto mockClient = std::make_shared<MockAuthorizationClient>();

    // 设置期望：当调用 CheckAuthorization 时，返回 E_TIME_OK 和 isAuthorized = true
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_OK);

    // 注入 mock 对象
    TimePermission::SetAuthorizationClient(mockClient);

    // 测试 CheckAuthorization 函数，使用 setTimePrivilege (ohos.privilege.modify_system_time)
    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);

    // 验证结果
    EXPECT_EQ(true, ret);
}

/**
* @tc.name: CheckAuthorizationMock002
* @tc.desc: Test CheckAuthorization function with unauthorized privilege using mock client
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Set expectation for CheckAuthorization method to return E_TIME_OK and isAuthorized = false
*           3. Inject the mock client into TimePermission
*           4. Call CheckAuthorization with valid privilege (setTimePrivilege)
*           5. Verify function returns false indicating authorization failure
* @tc.expect: Function returns false for unauthorized privilege
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationMock002, TestSize.Level1)
{
    // 创建一个 mock 对象
    auto mockClient = std::make_shared<MockAuthorizationClient>();

    // 设置期望：当调用 CheckAuthorization 时，返回 E_TIME_OK 和 isAuthorized = false
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);

    // 注入 mock 对象
    TimePermission::SetAuthorizationClient(mockClient);

    // 测试 CheckAuthorization 函数，使用 setTimePrivilege (ohos.privilege.modify_system_time)
    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);

    // 验证结果
    EXPECT_EQ(false, ret);
}

/**
* @tc.name: CheckAuthorizationMock003
* @tc.desc: Test CheckAuthorization function with error code using mock client
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Create a mock authorization client
*           2. Set expectation for CheckAuthorization method to return E_TIME_NO_PERMISSION
*           3. Inject the mock client into TimePermission
*           4. Call CheckAuthorization with valid privilege (setTimePrivilege)
*           5. Verify function returns false indicating authorization failure
* @tc.expect: Function returns false when CheckAuthorization returns an error code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationMock003, TestSize.Level1)
{
    // 创建一个 mock 对象
    auto mockClient = std::make_shared<MockAuthorizationClient>();

    // 设置期望：当调用 CheckAuthorization 时，返回 E_TIME_NO_PERMISSION
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_NO_PERMISSION);

    // 注入 mock 对象
    TimePermission::SetAuthorizationClient(mockClient);

    // 测试 CheckAuthorization 函数，使用 setTimePrivilege (ohos.privilege.modify_system_time)
    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);

    // 验证结果
    EXPECT_EQ(false, ret);
}

/**
* @tc.name: IsExemptedBundle001
* @tc.desc: Test IsExemptedBundle function can be called without crash
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Call IsExemptedBundle function
*           2. Verify function returns boolean value
* @tc.expect: Function returns false for non-HAP token (current process)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, IsExemptedBundle001, TestSize.Level1)
{
    // 测试 IsExemptedBundle 可以被调用且不崩溃
    // 当前测试进程不是 HAP token，应该返回 false
    EXPECT_NO_FATAL_FAILURE(TimePermission::IsExemptedBundle());
    bool ret = TimePermission::IsExemptedBundle();
    EXPECT_EQ(false, ret);
}

/**
* @tc.name: CheckAuthorizationWithExemptedBundle001
* @tc.desc: Test CheckAuthorization function with exempted bundle list
* @tc.precon: Time permission service is available and accessible
* @tc.step: 1. Call CheckAuthorization with mock client set to fail
*           2. Since current process is not in exempted list, authorization should fail
* @tc.expect: Function returns false when not exempted and authorization fails
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimePermissionTest, CheckAuthorizationWithExemptedBundle001, TestSize.Level1)
{
    // 创建一个 mock 对象，设置为未授权
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);

    // 对于非豁免的非 HAP 进程，CheckAuthorization 应该调用 mock 并返回 false
    // 如果当前是 HAP 且不在豁免列表中，也应该返回 false
    // 使用 setTimePrivilege (ohos.privilege.modify_system_time) 进行测试
    bool ret = TimePermission::CheckAuthorization(TimePermission::setTimePrivilege);

    // 当前测试进程不是豁免 bundle，且 mock 返回未授权，所以应该返回 false
    EXPECT_EQ(false, ret);
}

}