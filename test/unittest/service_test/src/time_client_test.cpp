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

#include <chrono>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <thread>
#include <unordered_set>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "timer_info_test.h"
#include "token_setproc.h"
#include "want_agent.h"
#include "time_service_test.h"

#define private public
#include "time_system_ability.h"
#include "time_service_client.h"
#include "timer_database.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;
using namespace OHOS::Security::AccessToken;

constexpr int ONE_HUNDRED = 100;
constexpr int FIVE_HUNDRED = 500;
constexpr uint64_t MICRO_TO_MILLISECOND = 1000;

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

static HapInfoParams g_systemInfoParams = {
    .userID = 1,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true
};

static HapPolicyParams g_policyB = { .apl = APL_NORMAL, .domain = "test.domain" };

static HapInfoParams g_notSystemInfoParams = {
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
    // Prevent timers are adjusted before.
    AddPermission();
    TimeServiceClient::GetInstance()->AdjustTimer(false, 0);
}

void TimeClientTest::TearDown(void)
{
}

/**
 * @brief Wait for timer trigger
 * @param data the global variable that callback function changes
 * @param interval the time need to wait
 */
void WaitForAlarm(std::atomic<int> * data, int interval)
{
    int i = 0;
    if (interval > 0) {
        usleep(interval);
    }
    while (*data == 0 && i < ONE_HUNDRED) {
        ++i;
        usleep(ONE_HUNDRED);
    }
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
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    sleep(2);
    EXPECT_GT(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    sleep(2);
    EXPECT_GT(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    pid_t uid = IPCSkeleton::GetCallingUid();
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, false, true);
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    pid_t uid = IPCSkeleton::GetCallingUid();
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer007
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer007, TestSize.Level1)
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    pid_t uid = IPCSkeleton::GetCallingUid();
    TimeServiceClient::GetInstance()->ProxyTimer(uid, true, true);
    sleep(1);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer008
* @tc.desc: Start system timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer008, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    g_data2 = 0;
    uint64_t timerId1;
    auto timerInfo1 = std::make_shared<TimerInfoTest>();
    timerInfo1->SetType(1<<2);
    timerInfo1->SetRepeat(false);
    timerInfo1->SetCallbackInfo(TimeOutCallback1);
    auto errCode1 = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo1, timerId1);
    uint64_t ret1 = 0;
    EXPECT_TRUE(errCode1 == TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, ret1);
    auto triggerTime1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId1, triggerTime1 + FIVE_HUNDRED);
    pid_t uid1 = IPCSkeleton::GetCallingUid();
    TimeServiceClient::GetInstance()->ProxyTimer(uid1, true, true);

    uint64_t timerId2;
    auto timerInfo2 = std::make_shared<TimerInfoTest>();
    timerInfo2->SetType(1<<2);
    timerInfo2->SetRepeat(false);
    timerInfo2->SetCallbackInfo(TimeOutCallback2);
    auto errCode2 = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo2, timerId2);
    uint64_t ret2 = 0;
    EXPECT_TRUE(errCode2 == TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, ret2);
    auto triggerTime2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId2, triggerTime2 + FIVE_HUNDRED);
    pid_t uid2 = IPCSkeleton::GetCallingUid();
    TimeServiceClient::GetInstance()->ProxyTimer(uid2, true, true);
    sleep(1);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    WaitForAlarm(&g_data1, 0);
    WaitForAlarm(&g_data2, 0);
    EXPECT_EQ(g_data1, 1);
    EXPECT_EQ(g_data2, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId2);
}

/**
* @tc.name: StartTimer009
* @tc.desc: Start a system time, then use the pid of this timer to start a proxy.
            Cancel the proxy by this pid.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer009, TestSize.Level1)
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    pid_t pid = IPCSkeleton::GetCallingPid();
    std::set<int> pidList;
    pidList.insert(pid);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, true);
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, false, true);
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer010
* @tc.desc: Start system timer, then use the pid of this timer to start a proxy.
            Cancel all the proxy.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer010, TestSize.Level1)
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    pid_t pid = IPCSkeleton::GetCallingPid();
    std::set<int> pidList;
    pidList.insert(pid);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, true);
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer011
* @tc.desc: Start system timer, then use the pid of this timer to start a proxy.
            Cancel all the proxy.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer011, TestSize.Level1)
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    pid_t pid = IPCSkeleton::GetCallingPid();
    std::set<int> pidList;
    pidList.insert(pid);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, true);
    sleep(1);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer012
* @tc.desc: Start two system timers, record two pids, then start a proxy by two pids.
            Cancel all the proxy.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, StartTimer012, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    g_data2 = 0;
    uint64_t timerId1;
    auto timerInfo1 = std::make_shared<TimerInfoTest>();
    timerInfo1->SetType(1<<2);
    timerInfo1->SetRepeat(false);
    timerInfo1->SetCallbackInfo(TimeOutCallback1);
    auto errCode1 = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo1, timerId1);
    uint64_t ret1 = 0;
    EXPECT_TRUE(errCode1 == TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, ret1);
    auto triggerTime1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId1, triggerTime1 + FIVE_HUNDRED);
    pid_t pid1 = IPCSkeleton::GetCallingPid();

    uint64_t timerId2;
    auto timerInfo2 = std::make_shared<TimerInfoTest>();
    timerInfo2->SetType(1<<2);
    timerInfo2->SetRepeat(false);
    timerInfo2->SetCallbackInfo(TimeOutCallback2);
    auto errCode2 = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo2, timerId2);
    uint64_t ret2 = 0;
    EXPECT_TRUE(errCode2 == TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, ret2);
    auto triggerTime2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId2, triggerTime2 + FIVE_HUNDRED);
    pid_t pid2 = IPCSkeleton::GetCallingUid();

    std::set<int> pidList;
    pidList.insert(pid1);
    pidList.insert(pid2);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, true);
    
    sleep(1);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->ResetAllProxy();
    WaitForAlarm(&g_data1, 0);
    WaitForAlarm(&g_data2, 0);
    EXPECT_EQ(g_data1, 1);
    EXPECT_EQ(g_data2, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId2);
}

/**
* @tc.name: RecoverTimer001
* @tc.desc: Create system timer, check whether the corresponding data is recorded when the timer is created.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, RecoverTimer001, TestSize.Level1)
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
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_TRUE(info != TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_TRUE(info->second->timerInfo != nullptr);
        EXPECT_TRUE(info->second->state == 0);
        EXPECT_TRUE(info->second->triggerTime == 0);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer002
* @tc.desc: Create system timer, then start it,
*           check whether the corresponding data is recorded when the timer is started.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, RecoverTimer002, TestSize.Level1)
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
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime);
    EXPECT_TRUE(startRet == TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_TRUE(info != TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_TRUE(info->second->timerInfo != nullptr);
        EXPECT_TRUE(info->second->state == 1);
        EXPECT_TRUE(info->second->triggerTime == triggerTime);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer003
* @tc.desc: Create system timer, then start it, then stop it,
*           check whether the corresponding data is recorded when the timer is stoped.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, RecoverTimer003, TestSize.Level1)
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
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    EXPECT_TRUE(startRet == TimeError::E_TIME_OK);
    auto stopRet = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_TRUE(stopRet == TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_TRUE(info != TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_TRUE(info->second->timerInfo != nullptr);
        EXPECT_TRUE(info->second->state == 0);
        EXPECT_TRUE(info->second->triggerTime == triggerTime + FIVE_HUNDRED);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer004
* @tc.desc: Create system timer, then start it, then destroy it,
*           check whether the corresponding data is recorded when the timer is destroyed.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, RecoverTimer004, TestSize.Level1)
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
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    EXPECT_TRUE(startRet == TimeError::E_TIME_OK);
    auto destroyRet = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_TRUE(destroyRet == TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_TRUE(info == TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer005
* @tc.desc: Create and start system timer, kill timer_service process, recover it.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, RecoverTimer005, TestSize.Level1)
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
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    // Kill time_service by hand.
    sleep(5);
    WaitForAlarm(&g_data1, 0);
    EXPECT_GT(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer006
* @tc.desc: Create system timer, kill timer_service process, and start it.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, RecoverTimer006, TestSize.Level1)
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
    // Kill time_service by hand.
    sleep(5);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: AdjustTimer001
* @tc.desc: adjust timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, AdjustTimer001, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId1;
    auto timerInfo1 = std::make_shared<TimerInfoTest>();
    timerInfo1->SetType(1<<2);
    timerInfo1->SetRepeat(false);
    timerInfo1->SetCallbackInfo(TimeOutCallback1);
    auto errCode1 = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo1, timerId1);
    uint64_t ret1 = 0;
    EXPECT_TRUE(errCode1 == TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, ret1);
    auto triggerTime1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId1, triggerTime1 + FIVE_HUNDRED);
    TimeServiceClient::GetInstance()->AdjustTimer(true, 5);
    TimeServiceClient::GetInstance()->AdjustTimer(false, 0);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId1);
}
 
/**
* @tc.name: AdjustTimer002
* @tc.desc: adjust timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, AdjustTimer002, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    std::unordered_set<std::string> nameArr{"timer"};
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    TimeSystemAbility::GetInstance()->timerManagerHandler_ = nullptr;
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    uint64_t timerId1;
    auto timerInfo1 = std::make_shared<TimerInfoTest>();
    timerInfo1->SetType(1<<2);
    timerInfo1->SetRepeat(false);
    timerInfo1->SetCallbackInfo(TimeOutCallback1);
    auto errCode1 = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo1, timerId1);
    uint64_t ret1 = 0;
    EXPECT_TRUE(errCode1 == TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, ret1);
    auto triggerTime1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId1, triggerTime1 + FIVE_HUNDRED);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId1);
}

/**
* @tc.name: AdjustTimer003
* @tc.desc: Create system timer and start it, after adjust system time, check whether it will be successful.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, AdjustTimer003, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(1<<2 | 1<<1);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    uint64_t ret = 0;
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    EXPECT_NE(timerId, ret);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);

    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 3600) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_TRUE(result == TimeError::E_TIME_OK);
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: ReBatchAllTimers001
* @tc.desc: Start a long-time timer, then start a proxy of this timer.
            Cancel the proxy of the timer, and then rebatch it.
            Expect this timer does not trigger.
* @tc.type: FUNC
*/
HWTEST_F(TimeClientTest, ReBatchAllTimers001, TestSize.Level1)
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
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_TRUE(errCode == TimeError::E_TIME_OK);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 300000);
    EXPECT_TRUE(startRet == TimeError::E_TIME_OK);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);

    pid_t pid = IPCSkeleton::GetCallingPid();
    std::set<int> pidList;
    pidList.insert(pid);
    TimeServiceClient::GetInstance()->ProxyTimer(pidList, true, true);
    TimeSystemAbility::GetInstance()->ProxyTimer(pidList, false, true);

    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 10) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_TRUE(time > 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_TRUE(result == TimeError::E_TIME_OK);
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 0);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}
} // namespace