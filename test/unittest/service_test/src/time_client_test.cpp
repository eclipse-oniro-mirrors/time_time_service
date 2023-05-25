/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "time_service_test.h"

#include <chrono>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <fstream>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "json/json.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "timer_info_test.h"
#include "token_setproc.h"
#include "want_agent.h"

#define private public
#include "time_system_ability.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;
using namespace OHOS::Security::AccessToken;

static HapPolicyParams g_policyA = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .bundleName = "ohos.permission_test.demoB",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        },
        {
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .bundleName = "ohos.permission_test.demoB",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        }
    },
    .permStateList = {
        {
            .permissionName = "ohos.permission.SET_TIME",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

HapInfoParams g_systemInfoParams = { .userID = 1,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true };

static HapPolicyParams g_policyB = { .apl = APL_NORMAL, .domain = "test.domain" };

HapInfoParams g_notSystemInfoParams = {
    .userID = 100,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 9,
    .isSystemApp = false
};

class TimeClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void AddPermission();
    void DeletePermission();
};

void TimeClientTest::AddPermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeClientTest::DeletePermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_notSystemInfoParams, g_policyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeClientTest::SetUpTestCase(void)
{
}

void TimeClientTest::TearDownTestCase(void)
{
}

void TimeClientTest::SetUp(void)
{
}

void TimeClientTest::TearDown(void)
{
}

/**
* @tc.name: SetTime001
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTime001, TestSize.Level1)
{
    AddPermission();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_TRUE(result == TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTime002
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTime002, TestSize.Level1)
{
    AddPermission();
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(-1);
    EXPECT_TRUE(result != TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTime003
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTime003, TestSize.Level1)
{
    AddPermission();
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(LLONG_MAX);
    EXPECT_TRUE(result != TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTime004
* @tc.desc: set system time.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTime004, TestSize.Level1)
{
    DeletePermission();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_TRUE(result != TimeError::E_TIME_OK);
    int32_t code;
    bool ret = TimeServiceClient::GetInstance()->SetTime(time, code);
    EXPECT_EQ(ret, false);
    EXPECT_TRUE(code != TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTimeZone001
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTimeZone001, TestSize.Level1)
{
    AddPermission();
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());
    std::string timeZoneNicosia("Asia/Nicosia");
    int32_t result = TimeServiceClient::GetInstance()->SetTimeZoneV9(timeZoneNicosia);
    EXPECT_TRUE(result == TimeError::E_TIME_OK);
    std::string getTimeZoneNicosia;
    int32_t getTimeZoneResult = TimeServiceClient::GetInstance()->GetTimeZone(getTimeZoneNicosia);
    EXPECT_TRUE(getTimeZoneResult == TimeError::E_TIME_OK);;
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);
    int32_t ret = TimeServiceClient::GetInstance()->SetTimeZoneV9(getCurrentTimeZone);
    EXPECT_TRUE(ret == TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTimeZone002
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTimeZone002, TestSize.Level1)
{
    AddPermission();
    int32_t result = TimeServiceClient::GetInstance()->SetTimeZoneV9("123");
    EXPECT_TRUE(result != TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTimeZone003
* @tc.desc: set system time zone.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, SetTimeZone003, TestSize.Level1)
{
    DeletePermission();
    int32_t result = TimeServiceClient::GetInstance()->SetTimeZoneV9("Asia/Shanghai");
    EXPECT_TRUE(result != TimeError::E_TIME_OK);
    bool ret = TimeServiceClient::GetInstance()->SetTimeZone("Asia/Shanghai");
    EXPECT_FALSE(ret);
}

/**
* @tc.name: GetWallTimeMs001
* @tc.desc: get wall time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetWallTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetWallTimeMs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetWallTimeNs001
* @tc.desc: get wall time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetWallTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetWallTimeNs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetBootTimeNs001
* @tc.desc: get boot time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetBootTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetBootTimeNs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetBootTimeMs001
* @tc.desc: get boot time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetBootTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetMonotonicTimeMs001
* @tc.desc: get monotonic time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetMonotonicTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetMonotonicTimeMs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetMonotonicTimeNs001
* @tc.desc: get monotonic time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetMonotonicTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetMonotonicTimeNs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetThreadTimeMs001
* @tc.desc: get thread time (ms).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetThreadTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetThreadTimeMs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: GetThreadTimeNs001
* @tc.desc: get thread time (ns).
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, GetThreadTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetThreadTimeNs(time);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer001
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer001, TestSize.Level1)
{
    AddPermission();
    uint64_t timerId = 0;
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    auto ret = TimeServiceClient::GetInstance()->StartTimerV9(timerId, 5);
    EXPECT_TRUE(ret != TimeError::E_TIME_OK);
    ret = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_TRUE(ret != TimeError::E_TIME_OK);
    ret = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_TRUE(ret != TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer002
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer002, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    auto ret = TimeServiceClient::GetInstance()->StartTimerV9(timerId, 2000);
    EXPECT_TRUE(ret == TimeError::E_TIME_OK);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    ret = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_TRUE(ret == TimeError::E_TIME_OK);
    ret = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_TRUE(ret == TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer003
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer003, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    auto ability = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(ability);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer004
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer004, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    auto bootTimeNano = system_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILESECOND;
    errCode = TimeServiceClient::GetInstance()->StartTimerV9(timerId, bootTimeMilli + 2000);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_TRUE(g_data1 == 0);
    errCode = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_TRUE(errCode != TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer005
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer005, TestSize.Level1)
{
    AddPermission();
    g_data1 = 1;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(0);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);

    struct timeval timeOfDay {};
    gettimeofday(&timeOfDay, NULL);
    int64_t currentTime = (timeOfDay.tv_sec + 100) * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);

    errCode = TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(currentTime));
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_TRUE(g_data1 == 1);
    errCode = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_TRUE(errCode != TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer006
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer006, TestSize.Level1)
{
    AddPermission();
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(nullptr, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode != TimeError::E_TIME_OK);
    EXPECT_EQ(timerId, ret);
}

/**
* @tc.name: CreateTimer007
* @tc.desc: Create system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, CreateTimer007, TestSize.Level1)
{
    DeletePermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(0);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);

    struct timeval timeOfDay {};
    gettimeofday(&timeOfDay, nullptr);
    int64_t currentTime = (timeOfDay.tv_sec + 100) * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    uint64_t ret = 0;
    EXPECT_EQ(timerId, ret);
    auto codeCreateTimer = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_TRUE(codeCreateTimer != TimeError::E_TIME_OK);
    auto codeStartTimer = TimeServiceClient::GetInstance()->StartTimerV9(timerId, currentTime + 1000);
    EXPECT_TRUE(codeStartTimer != TimeError::E_TIME_OK);
    auto codeStopTimer = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_TRUE(codeStopTimer != TimeError::E_TIME_OK);
    auto codeDestroyTimer = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_TRUE(codeDestroyTimer != TimeError::E_TIME_OK);
}

/**
* @tc.name: StartTimer001
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer001, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1<<2);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 1000);
    sleep(2);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer002
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer002, TestSize.Level1)
{
    AddPermission();
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1<<2);
    timerInfo->SetRepeat(false);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    auto result = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 1000);
    EXPECT_EQ(result, TimeError::E_TIME_OK);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer003
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer003, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1<<2 | 1<<1);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 1000);
    sleep(3);
    EXPECT_GT(g_data1, 1);
}

/**
* @tc.name: StartTimer004
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer004, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(4);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 1000);
    sleep(3);
    EXPECT_GT(g_data1, 1);
}

/**
* @tc.name: StartTimer005
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer005, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(4);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 2000);
    pid_t uid = IPCSkeleton::GetCallingUid();
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    sleep(2);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, false, true);
    EXPECT_GT(g_data1, 0);
}

/**
* @tc.name: StartTimer006
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer006, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1<<2);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 2000);
    pid_t uid = IPCSkeleton::GetCallingUid();
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    sleep(2);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    EXPECT_GT(g_data1, 0);
}
} // namespace