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
#include "timer_proxy.h"
#include "timer_info.h"
#undef private
#undef protected

#include <chrono>
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
// Free function with external linkage in timer_proxy.cpp (declared there
// without a header, so re-declare it here for direct white-box calls).
uint64_t GetProxyKey(int uid, int pid);

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
constexpr int MAX_PID_LIST_SIZE_IMPL = 1024;
constexpr int MAX_EXEMPTION_SIZE_IMPL = 1000;
constexpr int32_t PROXY_UID = 3057;
// Any non-negative pid is accepted by the ProxyTimer parameter checks.
constexpr int VALID_TEST_PID = 1000;

// Round-2 helpers: dedicated uid/pid values and a raw TimerInfo factory.
constexpr int R2P_UID = 3081;
constexpr int R2P_PID = 3082;

// Builds a TimerInfo with full control over the fields the proxy walks.
std::shared_ptr<TimerInfo> MakeProxyTimer(uint64_t id,
    std::chrono::steady_clock::time_point whenElapsed, int uid = R2P_UID, int pid = R2P_PID,
    const std::string &bundleName = "proxy_branch_bundle", const std::string &name = "proxy_branch_timer",
    std::chrono::milliseconds windowLength = std::chrono::milliseconds(0),
    std::function<int32_t(const uint64_t)> callback = nullptr)
{
    auto whenMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        whenElapsed.time_since_epoch()).count();
    return std::make_shared<TimerInfo>(name, id, ITimerManager::TimerType::ELAPSED_REALTIME,
        std::chrono::milliseconds(whenMs), whenElapsed, windowLength, whenElapsed,
        std::chrono::milliseconds(0), callback, nullptr, 0, false, uid, pid, bundleName);
}

// The original token of the test process is a shell token (TOKEN_SHELL), which
// CheckProxyCallingPermission() trusts. Saved once so permission-passing cases
// can restore it after a hap token has been injected by a permission-denied
// case. Native token allocation (GetAccessTokenId) is NOT used here on purpose:
// it pulls in libspm symbols that the device image does not provide.
uint64_t g_origTokenId = 0;

// Mock for the IAuthorizationClient seam in TimePermission, letting the
// settings-bundle CheckAuthorization cases control (err, isAuthorized).
class MockAuthorizationClient : public IAuthorizationClient {
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
    OHOS::ErrCode errCode_ = E_TIME_OK;
};

// A hap token whose bundleName matches the checkedBundles_ whitelist entry
// ("settings"). The (userID, bundleName, instIndex) key is deliberately
// distinct from the real settings app so the device token stays untouched.
void SetSettingsBundleToken()
{
    static HapInfoParams hapInfo = {
        .userID = 1,
        .bundleName = "settings",
        .instIndex = 99,
        .appIDDesc = "test",
        .apiVersion = 8,
        .isSystemApp = false
    };
    static HapPolicyParams hapPolicy = { .apl = APL_SYSTEM_BASIC, .domain = "test.domain" };
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}
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
    // Drop any mock authorization client the settings cases injected.
    TimePermission::ResetAuthorizationClient();
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

// ---------------------------------------------------------------------------
// Round-2 white-box cases: TimerProxy internals.
// Every case restores the maps it seeds.
// ---------------------------------------------------------------------------

/**
* @tc.name: CallbackAlarmIfNeedError001
* @tc.desc: CallbackAlarmIfNeed reports a non-zero callback result
* @tc.precon: A timer whose callback returns -1
* @tc.step: 1. Call CallbackAlarmIfNeed with the failing-callback timer
*           2. Call CallbackAlarmIfNeed with nullptr
* @tc.expect: The callback result passes through as -1; nullptr yields E_TIME_NULLPTR
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, CallbackAlarmIfNeedError001, TestSize.Level1)
{
    auto now = std::chrono::steady_clock::now();
    auto alarm = MakeProxyTimer(7007001, now + std::chrono::minutes(1), R2P_UID, R2P_PID,
        "proxy_branch_bundle", "proxy_branch_timer", std::chrono::milliseconds(0),
        [](uint64_t) { return -1; });
    EXPECT_EQ(TimerProxy::GetInstance().CallbackAlarmIfNeed(alarm), -1);
    EXPECT_EQ(TimerProxy::GetInstance().CallbackAlarmIfNeed(nullptr), E_TIME_NULLPTR);
}

/**
* @tc.name: ProxyTimerEmptyCallback001
* @tc.desc: ProxyTimer rejects an empty insert callback before doing any work
* @tc.precon: None
* @tc.step: 1. Call TimerProxy::ProxyTimer with an empty insertAlarmCallback
*           2. Call UpdateProxyWhenElapsedForProxyTimers with an empty callback
* @tc.expect: ProxyTimer returns false; the internal helper returns without changes
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, ProxyTimerEmptyCallback001, TestSize.Level1)
{
    auto now = std::chrono::steady_clock::now();
    EXPECT_FALSE(TimerProxy::GetInstance().ProxyTimer(R2P_UID, R2P_PID, true, true, now, nullptr));
    // Internal guard: returns before taking any lock, safe to call directly.
    TimerProxy::GetInstance().UpdateProxyWhenElapsedForProxyTimers(R2P_UID, R2P_PID, now, nullptr, true);
    EXPECT_FALSE(TimerProxy::GetInstance().IsProxy(R2P_UID, R2P_PID));
}

/**
* @tc.name: AdjustTimerDeliveryMatrix001
* @tc.desc: AdjustTimer's delivery callback handles null, exempt, overdue and fresh timers
* @tc.precon: An exemption entry and a policy entry for the probe bundles
* @tc.step: 1. SetTimerExemption + SetAdjustPolicy for the probe bundles
*           2. AdjustTimer(true) delivering nullptr / exempt / overdue / fresh timers
*           3. AdjustTimer(false) delivering the adjusted timer (restore path)
*           4. SetTimerExemption(name, false) erases the exemption entry
* @tc.expect: Only the fresh timer ends in ADJUST state and returns to INIT after restore
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, AdjustTimerDeliveryMatrix001, TestSize.Level1)
{
    auto &proxy = TimerProxy::GetInstance();
    auto now = std::chrono::steady_clock::now();
    auto exempt = MakeProxyTimer(7007101, now + std::chrono::minutes(10), R2P_UID, R2P_PID,
        "proxy_ex_bundle");
    auto overdue = MakeProxyTimer(7007102, now - std::chrono::minutes(10), R2P_UID, R2P_PID,
        "proxy_adj_bundle");
    auto fresh = MakeProxyTimer(7007103, now + std::chrono::minutes(10), R2P_UID, R2P_PID,
        "proxy_adj_bundle");
    proxy.SetTimerExemption({"proxy_ex_bundle"}, true);
    std::unordered_map<std::string, uint32_t> policy = {{"proxy_adj_bundle", 2}};
    proxy.SetAdjustPolicy(policy);
    // Deliver null (guard branch), exempt, overdue and fresh timers in one walk.
    EXPECT_TRUE(proxy.AdjustTimer(true, 60000, now, 1000, [&exempt, &overdue, &fresh](
        AdjustTimerCallback cb) {
        cb(nullptr);
        cb(exempt);
        cb(overdue);
        cb(fresh);
    }));
    EXPECT_EQ(exempt->state, TimerInfo::TimerState::INIT);  // Exemption kept it untouched.
    EXPECT_EQ(overdue->state, TimerInfo::TimerState::INIT); // Overdue -> restore (not in adjustTimers_).
    EXPECT_EQ(fresh->state, TimerInfo::TimerState::ADJUST); // Adjusted and recorded.
    EXPECT_TRUE(proxy.AdjustTimer(false, 0, now, 0, [&fresh](AdjustTimerCallback cb) { cb(fresh); }));
    EXPECT_EQ(fresh->state, TimerInfo::TimerState::INIT);   // Restored from adjustTimers_.
    // Exemption erasure path.
    proxy.SetTimerExemption({"proxy_ex_bundle"}, false);
    EXPECT_FALSE(proxy.IsTimerExemption(exempt));
    // Policy entry back to 0 (equivalent to unset for the consumer).
    std::unordered_map<std::string, uint32_t> undo = {{"proxy_adj_bundle", 0}};
    proxy.SetAdjustPolicy(undo);
}

/**
* @tc.name: IsTimerExemptionAncoName001
* @tc.desc: IsTimerExemption treats a timer name carrying the anco tag as exempt
* @tc.precon: None
* @tc.step: 1. Build a timer whose name contains "@anco_exemption"
*           2. Call IsTimerExemption with windowLength zero
* @tc.expect: Returns true (anco exemption tag branch)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, IsTimerExemptionAncoName001, TestSize.Level1)
{
    auto now = std::chrono::steady_clock::now();
    auto anco = MakeProxyTimer(7007201, now + std::chrono::minutes(1), R2P_UID, R2P_PID,
        "proxy_anco_bundle", "proxy@anco_exemption");
    EXPECT_TRUE(TimerProxy::GetInstance().IsTimerExemption(anco));
}

/**
* @tc.name: TimerProxyRecordMaps001
* @tc.desc: The uid/proxy bookkeeping maps record, dedup and erase as specified
* @tc.precon: None
* @tc.step: 1. RecordUidTimerMap with isRebatched=true / nullptr / twice (dedup)
*           2. RecordProxyTimerMap with nullptr and twice (pid key)
*           3. RemoveUidTimerMap by id and by object, plus the Locked variants
* @tc.expect: Counters and IsProxy toggle exactly as asserted and end clean
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, TimerProxyRecordMaps001, TestSize.Level1)
{
    auto &proxy = TimerProxy::GetInstance();
    auto now = std::chrono::steady_clock::now();
    auto alarm = MakeProxyTimer(7007301, now + std::chrono::minutes(1));
    // isRebatched=true: early return, nothing recorded.
    proxy.RecordUidTimerMap(alarm, true);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(R2P_UID), 0);
    // nullptr alarm guard.
    proxy.RecordUidTimerMap(nullptr, false);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(R2P_UID), 0);
    // Record twice: the second call takes the erase-then-insert branch.
    proxy.RecordUidTimerMap(alarm, false);
    proxy.RecordUidTimerMap(alarm, false);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(R2P_UID), 1);
    // nullptr and double-record for the pid-keyed proxy map.
    proxy.RecordProxyTimerMap(nullptr, true);
    proxy.RecordProxyTimerMap(alarm, true);
    proxy.RecordProxyTimerMap(alarm, true);
    EXPECT_TRUE(proxy.IsProxy(R2P_UID, R2P_PID));
    // Remove by timer id: matching entry erased, empty uid entry dropped.
    proxy.RemoveUidTimerMap(7007301);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(R2P_UID), 0);
    // Remove by object: same end state through the shared_ptr overload.
    proxy.RecordUidTimerMap(alarm, false);
    proxy.RemoveUidTimerMap(alarm);
    EXPECT_EQ(proxy.CountUidTimerMapByUid(R2P_UID), 0);
    // Locked variants: nullptr, unknown uid, and the empty-after-erase path.
    proxy.RemoveUidTimerMapLocked(nullptr);
    proxy.RemoveUidTimerMapLocked(alarm); // uid absent: early return.
    proxy.RecordUidTimerMap(alarm, false);
    proxy.RemoveUidTimerMapLocked(alarm); // last timer: uid entry erased.
    EXPECT_EQ(proxy.CountUidTimerMapByUid(R2P_UID), 0);
    // Clean the pid-keyed proxy map entry seeded above: dropping the id only
    // empties the set, so remove the key itself for a full cleanup.
    proxy.EraseTimerFromProxyTimerMap(7007301, R2P_UID, R2P_PID);
    {
        std::lock_guard<std::mutex> lock(proxy.proxyMutex_);
        proxy.proxyTimers_.erase(GetProxyKey(R2P_UID, R2P_PID));
    }
    EXPECT_FALSE(proxy.IsProxy(R2P_UID, R2P_PID));
}

// ---------------------------------------------------------------------------
// Settings-bundle authorization cases: the calling identity is switched to a
// hap token whose bundleName matches the checkedBundles_ whitelist, so
// CheckAuthorization walks the real authorization decision path.
// ---------------------------------------------------------------------------

/**
* @tc.name: IsAppNeedsAuthCheckSettings001
* @tc.desc: A caller token from the settings bundle passes the whitelist check
* @tc.precon: A hap token with bundleName "settings" is set as the self token
* @tc.step: 1. Allocate and set the settings-bundle hap token
*           2. Call IsAppNeedsAuthCheck
* @tc.expect: Returns true (bundle matches the checkedBundles_ whitelist)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, IsAppNeedsAuthCheckSettings001, TestSize.Level1)
{
    SetSettingsBundleToken();
    EXPECT_TRUE(TimePermission::IsAppNeedsAuthCheck());
}

/**
* @tc.name: CheckAuthorizationSettingsAllowed001
* @tc.desc: A settings-bundle caller with an authorized mock passes the check
* @tc.precon: Settings bundle token set; mock returns ERR_OK + authorized
* @tc.step: 1. Set the settings-bundle hap token
*           2. Inject a mock returning (ERR_OK, isAuthorized=true)
*           3. Call CheckAuthorization
* @tc.expect: Returns true (both conditions of the deny guard are false)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, CheckAuthorizationSettingsAllowed001, TestSize.Level1)
{
    SetSettingsBundleToken();
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);
    EXPECT_TRUE(TimePermission::CheckAuthorization(TimePermission::setTimePrivilege));
}

/**
* @tc.name: CheckAuthorizationSettingsErr001
* @tc.desc: A settings-bundle caller fails the check when the client errors
* @tc.precon: Settings bundle token set; mock returns a non-ERR_OK code
* @tc.step: 1. Set the settings-bundle hap token
*           2. Inject a mock returning (E_TIME_NO_PERMISSION, isAuthorized=true)
*           3. Call CheckAuthorization
* @tc.expect: Returns false (first condition of the deny guard trips)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, CheckAuthorizationSettingsErr001, TestSize.Level1)
{
    SetSettingsBundleToken();
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(true);
    mockClient->SetErrCode(E_TIME_NO_PERMISSION);
    TimePermission::SetAuthorizationClient(mockClient);
    EXPECT_FALSE(TimePermission::CheckAuthorization(TimePermission::setTimePrivilege));
}

/**
* @tc.name: CheckAuthorizationSettingsDenied001
* @tc.desc: A settings-bundle caller fails the check when the client denies
* @tc.precon: Settings bundle token set; mock returns ERR_OK + not authorized
* @tc.step: 1. Set the settings-bundle hap token
*           2. Inject a mock returning (ERR_OK, isAuthorized=false)
*           3. Call CheckAuthorization
* @tc.expect: Returns false (second condition of the deny guard trips)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, CheckAuthorizationSettingsDenied001, TestSize.Level1)
{
    SetSettingsBundleToken();
    auto mockClient = std::make_shared<MockAuthorizationClient>();
    mockClient->SetAuthorized(false);
    mockClient->SetErrCode(E_TIME_OK);
    TimePermission::SetAuthorizationClient(mockClient);
    EXPECT_FALSE(TimePermission::CheckAuthorization(TimePermission::setTimePrivilege));
}

/**
* @tc.name: CheckAuthorizationSettingsRealClient001
* @tc.desc: A settings-bundle caller goes through the real account authorization
* @tc.precon: Settings bundle token set; no mock injected (default client)
* @tc.step: 1. Set the settings-bundle hap token
*           2. Call CheckAuthorization with the real AuthorizationClient
* @tc.expect: Returns false (a test pid holds no modify_system_time
*             authorization grant on the device)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerProxyBranchTest, CheckAuthorizationSettingsRealClient001, TestSize.Level1)
{
    SetSettingsBundleToken();
    TimePermission::ResetAuthorizationClient();
    EXPECT_FALSE(TimePermission::CheckAuthorization(TimePermission::setTimePrivilege));
}
} // namespace MiscServices
} // namespace OHOS
