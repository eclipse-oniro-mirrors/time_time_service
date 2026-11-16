/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "time_system_ability.h"
#include "time_permission.h"
#undef private
#undef protected

#include <gtest/gtest.h>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "token_setproc.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr int MAX_PID_LIST_SIZE_IMPL = 1024;
constexpr int MAX_EXEMPTION_SIZE_IMPL = 1000;
constexpr int32_t PROXY_UID = 3057;
// Any non-negative pid is accepted by the ProxyTimer parameter checks.
constexpr int VALID_TEST_PID = 1000;

// The original token of the test process is a shell token (TOKEN_SHELL), which
// CheckProxyCallingPermission() trusts. Saved once so permission-passing cases
// can restore it after a hap token has been injected by a permission-denied
// case. Native token allocation (GetAccessTokenId) is NOT used here on purpose:
// it pulls in libspm symbols that the device image does not provide.
uint64_t g_origTokenId = 0;
}

class TimerProxyBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    // Switch the current process token to a hap token, which makes
    // CheckProxyCallingPermission() return false (only TOKEN_NATIVE /
    // TOKEN_SHELL are trusted).
    void SetHapToken();

    // Restore the original shell token of the test process, which makes
    // CheckProxyCallingPermission() return true.
    void RestoreShellToken();
};

void TimerProxyBranchTest::SetUpTestCase(void)
{
    g_origTokenId = IPCSkeleton::GetSelfTokenID();
}

void TimerProxyBranchTest::TearDownTestCase(void)
{
}

void TimerProxyBranchTest::SetUp(void)
{
}

void TimerProxyBranchTest::TearDown(void)
{
    // Restore the shell token so later suites are not affected.
    RestoreShellToken();
}

void TimerProxyBranchTest::SetHapToken()
{
    static HapInfoParams hapInfo = {
        .userID = 1,
        .bundleName = "proxy_branch",
        .instIndex = 0,
        .appIDDesc = "test",
        .apiVersion = 8,
        .isSystemApp = true
    };
    static HapPolicyParams hapPolicy = { .apl = APL_SYSTEM_BASIC, .domain = "test.domain" };
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimerProxyBranchTest::RestoreShellToken()
{
    if (g_origTokenId != 0) {
        SetSelfTokenID(g_origTokenId);
    }
}

/**
* @tc.name: ProxyTimerPermissionDenied001
* @tc.desc: ProxyTimer from a hap token is rejected by the proxy permission check
* @tc.precon: Current token is a hap token (not TOKEN_NATIVE / TOKEN_SHELL)
* @tc.step: 1. Switch to hap token
*           2. Call TimeSystemAbility::ProxyTimer
* @tc.expect: ProxyTimer returns E_TIME_NO_PERMISSION
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ProxyTimerPermissionDenied001, TestSize.Level1)
{
    SetHapToken();
    std::vector<int> pidList = { VALID_TEST_PID };
    auto result = TimeSystemAbility::GetInstance()->ProxyTimer(PROXY_UID, pidList, true, true);
    EXPECT_EQ(result, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: ProxyTimerPidListExceed001
* @tc.desc: ProxyTimer with more pids than MAX_PID_LIST_SIZE is rejected
* @tc.precon: Current token is a native token (proxy permission passes)
* @tc.step: 1. Switch to native token
*           2. Call ProxyTimer with a pid list of 1025 entries
* @tc.expect: ProxyTimer returns E_TIME_PARAMETERS_INVALID
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ProxyTimerPidListExceed001, TestSize.Level1)
{
    RestoreShellToken();
    std::vector<int> pidList(MAX_PID_LIST_SIZE_IMPL + 1, VALID_TEST_PID);
    auto result = TimeSystemAbility::GetInstance()->ProxyTimer(PROXY_UID, pidList, true, true);
    EXPECT_EQ(result, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: ProxyTimerUidInvalid001
* @tc.desc: ProxyTimer with a negative uid is rejected
* @tc.precon: Current token is a native token (proxy permission passes)
* @tc.step: 1. Switch to native token
*           2. Call ProxyTimer with uid = -1
* @tc.expect: ProxyTimer returns E_TIME_PARAMETERS_INVALID
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ProxyTimerUidInvalid001, TestSize.Level1)
{
    RestoreShellToken();
    std::vector<int> pidList = { VALID_TEST_PID };
    auto result = TimeSystemAbility::GetInstance()->ProxyTimer(-1, pidList, true, true);
    EXPECT_EQ(result, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: ProxyTimerPidInvalid001
* @tc.desc: ProxyTimer with a negative pid inside the list is rejected
* @tc.precon: Current token is a native token (proxy permission passes)
* @tc.step: 1. Switch to native token
*           2. Call ProxyTimer with pidList containing -1
* @tc.expect: ProxyTimer returns E_TIME_PARAMETERS_INVALID
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ProxyTimerPidInvalid001, TestSize.Level1)
{
    RestoreShellToken();
    std::vector<int> pidList = { -1 };
    auto result = TimeSystemAbility::GetInstance()->ProxyTimer(PROXY_UID, pidList, true, true);
    EXPECT_EQ(result, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: SetTimerExemptionPermissionDenied001
* @tc.desc: SetTimerExemption from a hap token is rejected by the proxy permission check
* @tc.precon: Current token is a hap token
* @tc.step: 1. Switch to hap token
*           2. Call TimeSystemAbility::SetTimerExemption
* @tc.expect: SetTimerExemption returns E_TIME_NO_PERMISSION
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, SetTimerExemptionPermissionDenied001, TestSize.Level1)
{
    SetHapToken();
    std::vector<std::string> nameArr = { "branch_exemption" };
    auto result = TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_EQ(result, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetTimerExemptionExceed001
* @tc.desc: SetTimerExemption with more names than MAX_EXEMPTION_SIZE is rejected
* @tc.precon: Current token is a native token (proxy permission passes)
* @tc.step: 1. Switch to native token
*           2. Call SetTimerExemption with 1001 names
* @tc.expect: SetTimerExemption returns E_TIME_PARAMETERS_INVALID
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, SetTimerExemptionExceed001, TestSize.Level1)
{
    RestoreShellToken();
    std::vector<std::string> nameArr(MAX_EXEMPTION_SIZE_IMPL + 1, "branch_exemption");
    auto result = TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_EQ(result, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: SetAdjustPolicyPermissionDenied001
* @tc.desc: SetAdjustPolicy from a hap token is rejected by the proxy permission check
* @tc.precon: Current token is a hap token
* @tc.step: 1. Switch to hap token
*           2. Call TimeSystemAbility::SetAdjustPolicy
* @tc.expect: SetAdjustPolicy returns E_TIME_NO_PERMISSION
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, SetAdjustPolicyPermissionDenied001, TestSize.Level1)
{
    SetHapToken();
    std::unordered_map<std::string, uint32_t> policyMap = { { "branch_policy", 1 } };
    auto result = TimeSystemAbility::GetInstance()->SetAdjustPolicy(policyMap);
    EXPECT_EQ(result, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetAdjustPolicyExceed001
* @tc.desc: SetAdjustPolicy with more entries than MAX_EXEMPTION_SIZE is rejected
* @tc.precon: Current token is a native token (proxy permission passes)
* @tc.step: 1. Switch to native token
*           2. Call SetAdjustPolicy with 1001 entries
* @tc.expect: SetAdjustPolicy returns E_TIME_PARAMETERS_INVALID
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, SetAdjustPolicyExceed001, TestSize.Level1)
{
    RestoreShellToken();
    std::unordered_map<std::string, uint32_t> policyMap;
    for (int i = 0; i <= MAX_EXEMPTION_SIZE_IMPL; i++) {
        policyMap.emplace("branch_policy_" + std::to_string(i), 1);
    }
    auto result = TimeSystemAbility::GetInstance()->SetAdjustPolicy(policyMap);
    EXPECT_EQ(result, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: ResetAllProxyPermissionDenied001
* @tc.desc: ResetAllProxy from a hap token is rejected by the proxy permission check
* @tc.precon: Current token is a hap token
* @tc.step: 1. Switch to hap token
*           2. Call TimeSystemAbility::ResetAllProxy
* @tc.expect: ResetAllProxy returns E_TIME_NO_PERMISSION
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ResetAllProxyPermissionDenied001, TestSize.Level1)
{
    SetHapToken();
    auto result = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(result, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: ResetAllProxySuccess001
* @tc.desc: ResetAllProxy with the shell token passes the proxy check and resets
* @tc.precon: Current token is the original shell token
* @tc.step: 1. Restore the shell token
*           2. Call TimeSystemAbility::ResetAllProxy
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ResetAllProxySuccess001, TestSize.Level1)
{
    RestoreShellToken();
    auto result = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(result, E_TIME_OK);
}

/**
* @tc.name: SetTimerExemptionSuccess001
* @tc.desc: SetTimerExemption with the shell token passes and returns E_TIME_OK
* @tc.precon: Current token is the original shell token
* @tc.step: 1. Restore the shell token
*           2. Call SetTimerExemption with a small name set
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, SetTimerExemptionSuccess001, TestSize.Level1)
{
    RestoreShellToken();
    std::vector<std::string> nameArr = { "proxy_branch_exemption_ok" };
    auto result = TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_EQ(result, E_TIME_OK);
    // Restore the exemption state.
    auto undo = TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, false);
    EXPECT_EQ(undo, E_TIME_OK);
}

/**
* @tc.name: SetAdjustPolicySuccess001
* @tc.desc: SetAdjustPolicy with the shell token passes and returns E_TIME_OK
* @tc.precon: Current token is the original shell token
* @tc.step: 1. Restore the shell token
*           2. Call SetAdjustPolicy with a one-entry map
* @tc.expect: Returns E_TIME_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, SetAdjustPolicySuccess001, TestSize.Level1)
{
    RestoreShellToken();
    std::unordered_map<std::string, uint32_t> policyMap = { { "proxy_branch_policy_ok", 1 } };
    auto result = TimeSystemAbility::GetInstance()->SetAdjustPolicy(policyMap);
    EXPECT_EQ(result, E_TIME_OK);
    // Restore the policy entry: the consumer resolves a lookup miss to policy
    // 0, so writing 0 back is equivalent to the entry never having been set.
    std::unordered_map<std::string, uint32_t> undoMap = { { "proxy_branch_policy_ok", 0 } };
    auto undo = TimeSystemAbility::GetInstance()->SetAdjustPolicy(undoMap);
    EXPECT_EQ(undo, E_TIME_OK);
}

/**
* @tc.name: ProxyTimerSuccess001
* @tc.desc: ProxyTimer with the shell token and valid parameters returns E_TIME_OK
* @tc.precon: Current token is the original shell token
* @tc.step: 1. Restore the shell token
*           2. Call ProxyTimer with a valid uid and pid list
* @tc.expect: Returns E_TIME_OK (reset back afterwards)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ProxyTimerSuccess001, TestSize.Level1)
{
    RestoreShellToken();
    std::vector<int> pidList = { 1 };
    auto result = TimeSystemAbility::GetInstance()->ProxyTimer(PROXY_UID, pidList, true, true);
    EXPECT_EQ(result, E_TIME_OK);
    // Reset the proxy state for this uid.
    auto undo = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(undo, E_TIME_OK);
}
} // namespace MiscServices
} // namespace OHOS
