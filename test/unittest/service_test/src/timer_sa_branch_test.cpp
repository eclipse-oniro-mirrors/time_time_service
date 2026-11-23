/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

// Branch-targeted cases for the SA entry layer and the timer manager paths
// that only white-box direct calls can reach: the ITimerInfo parameter
// validation branch arms, the type-mask mapping (IDLE / INEXACT flags), the
// wantAgent branch inside TimerManager::InsertTimerEntryLocked, the
// stop-vs-destroy (needDestroy) arms, and the not-found timerId paths.
// All calls go through TimeSystemAbility public methods in-process, so the
// service-side logic executes inside the instrumented test binary.

#include <memory>

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#include "want_agent.h"
#include "itimer_info.h"
#include "time_system_ability.h"
#include "timer_call_back.h"
#include "time_service_client.h"
#include "time_common.h"

namespace OHOS {
namespace MiscServices {
namespace {
using namespace testing::ext;

// Type masks mirrored from time_system_ability.cpp (JS timer type bits).
constexpr int TIMER_TYPE_RTC = 0;
constexpr int TIMER_TYPE_IDLE_MASK = 1 << 3;
constexpr int TIMER_TYPE_INEXACT_REMINDER_MASK = 1 << 4;
constexpr uint64_t TEST_INTERVAL_MS = 60000;

// Local ITimerInfo implementation: timer_info_test.h defines its methods in
// the header, so including it from a second TU of the same target duplicates
// the symbols; this local class keeps everything inside this TU.
class SaBranchTimerInfo : public ITimerInfo {
public:
    SaBranchTimerInfo() = default;
    ~SaBranchTimerInfo() override = default;
    void SetType(const int &type) override
    {
        this->type = type;
    }
    void SetRepeat(bool repeat) override
    {
        this->repeat = repeat;
    }
    void SetInterval(const uint64_t &interval) override
    {
        this->interval = interval;
    }
    void SetWantAgent(std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent) override
    {
        this->wantAgent = wantAgent;
    }
    void OnTrigger() override {}
};

// Local callback stub: the ITimerCallback IDL stub is linked in the test
// binary through the SA static lib closure (same pattern as the misc branch
// suite), so an IRemoteStub subclass is safe to pass as the callback object.
class LocalCallbackStub : public IRemoteStub<ITimerCallback> {
public:
    LocalCallbackStub() = default;
    ~LocalCallbackStub() override = default;
    int32_t NotifyTimer(uint64_t timerId) override
    {
        return ERR_OK;
    }
    int32_t OnRemoteRequest(uint32_t code, OHOS::MessageParcel &data, OHOS::MessageParcel &reply,
        OHOS::MessageOption &option) override
    {
        return OHOS::ERR_NONE;
    }
};

sptr<IRemoteObject> MakeCallbackObject()
{
    sptr<LocalCallbackStub> callback = new (std::nothrow) LocalCallbackStub();
    return callback;
}

std::shared_ptr<ITimerInfo> MakeTimerInfo(int type)
{
    auto info = std::make_shared<SaBranchTimerInfo>();
    if (info != nullptr) {
        info->SetType(type);
        info->SetRepeat(false);
        info->SetInterval(0);
    }
    return info;
}

int32_t CreateTimerInSandbox(const std::shared_ptr<ITimerInfo> &options, uint64_t &timerId)
{
    return TimeSystemAbility::GetInstance()->CreateTimer(options, MakeCallbackObject(), timerId);
}
} // namespace

class TimerSaBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp() {};
    void TearDown() {};
};

/**
* @tc.name: CreateTimerOptionsNullptr001
* @tc.desc: CreateTimer with a null options pointer is rejected
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, CreateTimerOptionsNullptr001, TestSize.Level1)
{
    uint64_t timerId = 0;
    auto ret = TimeSystemAbility::GetInstance()->CreateTimer(nullptr, MakeCallbackObject(), timerId);
    EXPECT_EQ(ret, E_TIME_NULLPTR);
    EXPECT_EQ(timerId, 0);
}

/**
* @tc.name: CreateTimerCallbackNullptr001
* @tc.desc: CreateTimer with a null callback object is rejected
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, CreateTimerCallbackNullptr001, TestSize.Level1)
{
    auto info = MakeTimerInfo(TIMER_TYPE_RTC);
    ASSERT_NE(info, nullptr);
    uint64_t timerId = 0;
    auto ret = TimeSystemAbility::GetInstance()->CreateTimer(info, nullptr, timerId);
    EXPECT_EQ(ret, E_TIME_NULLPTR);
    EXPECT_EQ(timerId, 0);
}

/**
* @tc.name: CreateTimerIdleFlagPath001
* @tc.desc: A timer type carrying the IDLE bit maps to the IDLE_UNTIL flag and
*           takes the idle insertion path; the follow-up start/stop/destroy
*           cycle walks both needDestroy arms and the removal path
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, CreateTimerIdleFlagPath001, TestSize.Level1)
{
    auto info = MakeTimerInfo(TIMER_TYPE_RTC | TIMER_TYPE_IDLE_MASK);
    ASSERT_NE(info, nullptr);
    uint64_t timerId = 0;
    auto ret = CreateTimerInSandbox(info, timerId);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        EXPECT_EQ(TimeSystemAbility::GetInstance()->StartTimer(timerId, 0), E_TIME_OK);
        // Stop walks the needDestroy=false arm, destroy the true arm.
        EXPECT_EQ(TimeSystemAbility::GetInstance()->StopTimer(timerId), E_TIME_OK);
        EXPECT_EQ(TimeSystemAbility::GetInstance()->DestroyTimer(timerId), E_TIME_OK);
    }
}

/**
* @tc.name: CreateTimerInexactReminderFlagPath001
* @tc.desc: A timer type carrying the INEXACT_REMINDER bit sets the
*           INEXACT_REMINDER flag on the create path
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, CreateTimerInexactReminderFlagPath001, TestSize.Level1)
{
    auto info = MakeTimerInfo(TIMER_TYPE_RTC | TIMER_TYPE_INEXACT_REMINDER_MASK);
    ASSERT_NE(info, nullptr);
    uint64_t timerId = 0;
    auto ret = CreateTimerInSandbox(info, timerId);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        EXPECT_EQ(TimeSystemAbility::GetInstance()->DestroyTimer(timerId), E_TIME_OK);
    }
}

/**
* @tc.name: CreateTimerWithWantAgentPath001
* @tc.desc: A timer created with a (shared, non-null) want agent walks the
*           wantAgent branch in the timer entry insertion (the on-reboot
*           table selection), unlike the plain timer path
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, CreateTimerWithWantAgentPath001, TestSize.Level1)
{
    auto info = MakeTimerInfo(TIMER_TYPE_RTC);
    ASSERT_NE(info, nullptr);
    info->SetInterval(TEST_INTERVAL_MS);
    info->SetRepeat(true);
    // A default-constructed agent object keeps the shared pointer non-null,
    // which is what drives the wantAgent branch on the service side.
    info->SetWantAgent(std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>());
    uint64_t timerId = 0;
    auto ret = CreateTimerInSandbox(info, timerId);
    EXPECT_EQ(ret, E_TIME_OK);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        EXPECT_EQ(TimeSystemAbility::GetInstance()->DestroyTimer(timerId), E_TIME_OK);
    }
}

/**
* @tc.name: StartTimerNonExistId001
* @tc.desc: Starting a timer id that does not exist returns the not-found error
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, StartTimerNonExistId001, TestSize.Level1)
{
    // An id that was never handed out walks the not-found branch in the
    // timer manager lookup.
    uint64_t nonExistId = 0xFFFFFFFFFFFFFFFF;
    auto ret = TimeSystemAbility::GetInstance()->StartTimer(nonExistId, 0);
    EXPECT_NE(ret, E_TIME_OK);
}

/**
* @tc.name: StopDestroyTimerNonExistId001
* @tc.desc: Stopping and destroying a non-existent timer id both fail
* @tc.type: FUNC
* @tc.level: level1
*/
HWTEST_F(TimerSaBranchTest, StopDestroyTimerNonExistId001, TestSize.Level1)
{
    uint64_t nonExistId = 0xFFFFFFFFFFFFFFFF;
    EXPECT_NE(TimeSystemAbility::GetInstance()->StopTimer(nonExistId), E_TIME_OK);
    EXPECT_NE(TimeSystemAbility::GetInstance()->DestroyTimer(nonExistId), E_TIME_OK);
}
} // namespace MiscServices
} // namespace OHOS
