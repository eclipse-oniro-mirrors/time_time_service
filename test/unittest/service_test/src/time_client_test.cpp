/**
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
#include "ntp_trusted_time.h"

#define private public
#include "time_system_ability.h"
#include "time_service_client.h"

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

/* push_managere_service is in the exemption list of adjust timer */
/* use push_manager_service to prevent timers from being adjusted */
static HapInfoParams g_systemInfoParams = {
    .userID = 1,
    .bundleName = "push_manager_service",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true
};

static HapPolicyParams g_policyB = { .apl = APL_NORMAL, .domain = "test.domain" };

static HapInfoParams g_notSystemInfoParams = {
    .userID = 100,
    .bundleName = "push_manager_service",
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
    static void AddPermission();
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
    AddPermission();
}

void TimeClientTest::TearDown(void)
{
}

void TestNtpThread(const char *name)
{
    int64_t time;
    auto errCodeNtpTime = TimeServiceClient::GetInstance()->GetNtpTimeMs(time);
    EXPECT_EQ(errCodeNtpTime, TimeError::E_TIME_OK);
    int64_t timeLater;
    auto errCodeRealTime = TimeServiceClient::GetInstance()->GetRealTimeMs(timeLater);
    EXPECT_EQ(errCodeRealTime, TimeError::E_TIME_OK);
    EXPECT_GE(timeLater, time);
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
* @tc.name: GetNtpTimeMs001
* @tc.desc: Test basic NTP time retrieval functionality
* @tc.precon: Time service is available and NTP server is accessible
* @tc.step: 1. Call GetNtpTimeMs method
*           2. Verify return code and time value
* @tc.expect: Return code is E_TIME_OK, time value is valid
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetNtpTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetNtpTimeMs(time);
    TIME_HILOGI(TIME_MODULE_CLIENT, "time now : %{public}" PRId64 "", time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetNtpTimeMsAndGetRealTimeMs001
* @tc.desc: Test NTP time and real time retrieval in multi-thread environment
* @tc.precon: Time service is available
* @tc.step: 1. Create 4 threads to concurrently call TestNtpThread
*           2. Each thread gets NTP time and real time
*           3. Verify time consistency across threads
* @tc.expect: All threads complete successfully, time values are consistent
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetNtpTimeMsAndGetRealTimeMs001, TestSize.Level1)
{
    std::thread thread1(TestNtpThread, "thread1");
    std::thread thread2(TestNtpThread, "thread2");
    std::thread thread3(TestNtpThread, "thread3");
    std::thread thread4(TestNtpThread, "thread4");
    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();
}

/**
* @tc.name: SetTime001
* @tc.desc: Test setting system time with valid future time
* @tc.precon: Application has system time setting permission
* @tc.step: 1. Get current time and add 1000 seconds
*           2. Call SetTimeV9 with the future time
*           3. Verify return code
* @tc.expect: Return code is E_TIME_OK, time is set successfully
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTime001, TestSize.Level1)
{
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_EQ(result, TimeError::E_TIME_OK);
}

/**
* @tc.name: ut_time_service_set_time_002
* @tc.desc: Test setting system time with negative value (invalid input)
* @tc.precon: Application has system time setting permission
* @tc.step: 1. Call SetTimeV9 with negative value (-1)
*           2. Verify return code
* @tc.expect: Return code is E_TIME_DEAL_FAILED, operation fails
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTime002, TestSize.Level1)
{
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(-1);
    EXPECT_EQ(result, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: SetTime003
* @tc.desc: Test setting system time with maximum long value (LLONG_MAX)
* @tc.precon: Application has system time setting permission
* @tc.step: 1. Call SetTimeV9 with LLONG_MAX
*           2. Verify return code
* @tc.expect: Return code is E_TIME_DEAL_FAILED, operation fails
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTime003, TestSize.Level1)
{
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(LLONG_MAX);
    EXPECT_EQ(result, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: SetTime004
* @tc.desc: Test setting system time without required permissions
* @tc.precon: Application permissions have been revoked
* @tc.step: 1. Delete system permissions
*           2. Attempt to set time with valid future time
*           3. Verify return codes for both V9 and legacy APIs
* @tc.expect: V9 API returns E_TIME_NOT_SYSTEM_APP, legacy API returns false with E_TIME_NO_PERMISSION
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTime004, TestSize.Level1)
{
    DeletePermission();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_EQ(result, TimeError::E_TIME_NOT_SYSTEM_APP);
    int32_t code;
    bool ret = TimeServiceClient::GetInstance()->SetTime(time, code);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(code, TimeError::E_TIME_NO_PERMISSION);
}

/**
// @tc.name: SetTimeZone001
// @tc.desc: Test setting and restoring system timezone
// @tc.precon: Application has timezone setting permission
// @tc.step: 1. Get current timezone
//           2. Set timezone to "Asia/Nicosia"
//           3. Verify new timezone is set
//           4. Restore original timezone
// @tc.expect: All operations succeed, timezone changes are applied correctly
// @tc.type: FUNC
// @tc.require: issue#842
// @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTimeZone001, TestSize.Level1)
{
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());
    std::string timeZoneNicosia("Asia/Nicosia");
    int32_t result = TimeServiceClient::GetInstance()->SetTimeZoneV9(timeZoneNicosia);
    EXPECT_EQ(result, TimeError::E_TIME_OK);
    std::string getTimeZoneNicosia;
    int32_t getTimeZoneResult = TimeServiceClient::GetInstance()->GetTimeZone(getTimeZoneNicosia);
    EXPECT_EQ(getTimeZoneResult, TimeError::E_TIME_OK);;
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);
    int32_t ret = TimeServiceClient::GetInstance()->SetTimeZoneV9(getCurrentTimeZone);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
}

/**
* @tc.name: SetTimeZone002
* @tc.desc: Test setting system timezone with invalid timezone ID
* @tc.precon: Application has timezone setting permission
* @tc.step: 1. Call SetTimeZoneV9 with invalid timezone "123"
*           2. Verify return code
* @tc.expect: Return code is E_TIME_DEAL_FAILED, operation fails
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTimeZone002, TestSize.Level1)
{
    int32_t result = TimeServiceClient::GetInstance()->SetTimeZoneV9("123");
    EXPECT_EQ(result, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: SetTimeZone003
* @tc.desc: Test setting system timezone without required permissions
* @tc.precon: Application permissions have been revoked
* @tc.step: 1. Delete system permissions
*           2. Attempt to set timezone to "Asia/Shanghai"
*           3. Verify return codes for both V9 and legacy APIs
* @tc.expect: V9 API returns E_TIME_NOT_SYSTEM_APP, legacy API returns false
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetTimeZone003, TestSize.Level1)
{
    DeletePermission();
    int32_t result = TimeServiceClient::GetInstance()->SetTimeZoneV9("Asia/Shanghai");
    EXPECT_EQ(result, TimeError::E_TIME_NOT_SYSTEM_APP);
    bool ret = TimeServiceClient::GetInstance()->SetTimeZone("Asia/Shanghai");
    EXPECT_FALSE(ret);
}

/**
* @tc.name: GetWallTimeMs001
* @tc.desc: Test retrieving wall time in milliseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetWallTimeMs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetWallTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetWallTimeMs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetWallTimeNs001
* @tc.desc: Test retrieving wall time in nanoseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetWallTimeNs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetWallTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetWallTimeNs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetBootTimeNs001
* @tc.desc: Test retrieving boot time in nanoseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetBootTimeNs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetBootTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetBootTimeNs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetBootTimeMs001
* @tc.desc: Test retrieving boot time in milliseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetBootTimeMs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetBootTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetMonotonicTimeMs001
* @tc.desc: Test retrieving monotonic time in milliseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetMonotonicTimeMs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetMonotonicTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetMonotonicTimeMs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetMonotonicTimeNs001
* @tc.desc: Test retrieving monotonic time in nanoseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetMonotonicTimeNs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetMonotonicTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetMonotonicTimeNs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetThreadTimeMs001
* @tc.desc: Test retrieving thread time in milliseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetThreadTimeMs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetThreadTimeMs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetThreadTimeMs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: GetThreadTimeNs001
* @tc.desc: Test retrieving thread time in nanoseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetThreadTimeNs method
*           2. Verify return code
* @tc.expect: Return code is E_TIME_OK, time value is retrieved
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, GetThreadTimeNs001, TestSize.Level1)
{
    int64_t time;
    auto errCode = TimeServiceClient::GetInstance()->GetThreadTimeNs(time);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer001
* @tc.desc: Test timer operations with invalid timer ID
* @tc.precon: Timer service is available
* @tc.step: 1. Use timer ID 0 (invalid) for start, stop, and destroy operations
*           2. Verify return codes for each operation
* @tc.expect: All operations return E_TIME_DEAL_FAILED with invalid timer ID
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer001, TestSize.Level1)
{
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->StartTimerV9(timerId, 5);
    EXPECT_EQ(ret, TimeError::E_TIME_DEAL_FAILED);
    ret = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_EQ(ret, TimeError::E_TIME_DEAL_FAILED);
    ret = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(ret, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: CreateTimer002
* @tc.desc: Test complete timer lifecycle (create, start, stop, destroy)
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with realtime type and callback
*           2. Start timer with 2000ms delay
*           3. Stop timer before it triggers
*           4. Destroy timer
* @tc.expect: All operations return E_TIME_OK, timer lifecycle completes successfully
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer002, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    auto ret = TimeServiceClient::GetInstance()->StartTimerV9(timerId, 2000);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    ret = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
    ret = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(ret, TimeError::E_TIME_OK);
}

/**
* @tc.name: CreateTimer003
* @tc.desc: Test timer creation with WantAgent (nullptr scenario)
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with realtime type and null WantAgent
*           2. Verify timer creation succeeds
*           3. Destroy timer
* @tc.expect: Timer creation returns E_TIME_OK, destruction succeeds
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer003, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    auto ability = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(ability);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: CreateTimer004
* @tc.desc: Test timer destruction before trigger time
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with realtime type
*           2. Start timer with future boot time
*           3. Destroy timer immediately
*           4. Verify callback is not invoked
*           5. Attempt to stop destroyed timer
* @tc.expect: Timer destruction succeeds, callback not invoked, stop operation fails on destroyed timer
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer004, TestSize.Level1)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    errCode = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + 2000);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_EQ(g_data1, 0);
    errCode = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: CreateTimer005
* @tc.desc: Test timer with absolute time trigger
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with type 0 (absolute time)
*           2. Start timer with calculated absolute time
*           3. Destroy timer immediately
*           4. Verify callback is not invoked
*           5. Attempt to stop destroyed timer
* @tc.expect: Timer operations succeed, callback not invoked due to immediate destruction
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer005, TestSize.Level1)
{
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
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(currentTime));
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_EQ(g_data1, 1);
    errCode = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: CreateTimer006
* @tc.desc: Test timer creation with null timer info
* @tc.precon: Timer service is available
* @tc.step: 1. Attempt to create timer with nullptr timer info
*           2. Verify return code and timer ID
* @tc.expect: Return code is E_TIME_NULLPTR, timer ID is 0
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer006, TestSize.Level1)
{
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(nullptr, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_NULLPTR);
    EXPECT_EQ(timerId, 0);
}

/**
* @tc.name: CreateTimer007
* @tc.desc: Test timer operations without required permissions
* @tc.precon: Application permissions have been revoked
* @tc.step: 1. Delete system permissions
*           2. Attempt to create, start, stop, and destroy timer
*           3. Verify return codes for all operations
* @tc.expect: All operations return E_TIME_NOT_SYSTEM_APP or indicate failure
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
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
    EXPECT_EQ(timerId, 0);
    auto codeCreateTimer = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(codeCreateTimer, TimeError::E_TIME_NOT_SYSTEM_APP);
    auto codeStartTimer = TimeServiceClient::GetInstance()->StartTimerV9(timerId, currentTime + 1000);
    EXPECT_EQ(codeStartTimer, TimeError::E_TIME_NOT_SYSTEM_APP);
    auto codeStopTimer = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_EQ(codeStopTimer, TimeError::E_TIME_NOT_SYSTEM_APP);
    auto codeDestroyTimer = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(codeDestroyTimer, TimeError::E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: CreateTimer008
* @tc.desc: Test timer creation with auto-restore flag under different timer types
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with type 0 and auto-restore true
*           2. Create timer with realtime type and auto-restore true
*           3. Create timer with realtime+wakeup type and auto-restore true
* @tc.expect: All timer creations return E_TIME_DEAL_FAILED due to auto-restore incompatibility
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer008, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(0);
    timerInfo->SetRepeat(false);
    timerInfo->SetAutoRestore(true);
    timerInfo->SetWantAgent(nullptr);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);

    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);

    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME | timerInfo->TIMER_TYPE_WAKEUP);
    errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: CreateTimer009
* @tc.desc: Test timer creation with excessively long name
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with 70-character name (exceeds limit)
*           2. Set exact timer type with callback
*           3. Verify return code
* @tc.expect: Timer creation returns E_TIME_DEAL_FAILED due to name length violation
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer009, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetName("0123456789012345678901234567890123456789012345678901234567890123456789");
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);
    TIME_HILOGI(TIME_MODULE_CLIENT, "test timer id: %{public}" PRId64 "", timerId);
}

/**
* @tc.name: CreateTimer010
* @tc.desc: Test timer creation with duplicate names (first timer gets replaced)
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create first timer with name "testname"
*           2. Verify timer is in name list
*           3. Create second timer with same name
*           4. Verify first timer is destroyed and replaced
*           5. Clean up second timer
* @tc.expect: Second timer creation succeeds, first timer is automatically destroyed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer010, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId1;
    uint64_t timerId2;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetName("testname");
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId1);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, 0);
    auto nameList = TimeServiceClient::GetInstance()->timerNameList_;
    auto name = std::find(nameList.begin(), nameList.end(), "testname");
    EXPECT_NE(name, nameList.end());

    errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId2);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId2, 0);

    auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId1);
    EXPECT_EQ(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());

    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId1);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);

    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId2);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);

    nameList = TimeServiceClient::GetInstance()->timerNameList_;
    name = std::find(nameList.begin(), nameList.end(), "testname");
    EXPECT_EQ(name, nameList.end());
}

/**
* @tc.name: CreateTimer011
* @tc.desc: Test timer name reuse after destruction
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create timer with name "testname" and destroy it
*           2. Create new timer with same name "testname"
*           3. Verify second creation succeeds
*           4. Destroy second timer
* @tc.expect: Both timer creations succeed, name can be reused after destruction
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, CreateTimer011, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId1;
    uint64_t timerId2;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetName("testname");
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId1);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId1, 0);

    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId1);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);

    errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId2);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId2, 0);

    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId2);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: StartTimer001
* @tc.desc: Test starting exact type timer and verify callback execution
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact type timer with callback
*           2. Start timer with 500ms delay
*           3. Wait for timer trigger
*           4. Verify callback is executed
*           5. Destroy timer
* @tc.expect: Timer starts successfully, callback is triggered (g_data1 becomes 1), timer is destroyed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer001, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer002
* @tc.desc: Test starting exact type timer with WantAgent
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact type timer with WantAgent
*           2. Start timer with 1000ms delay
*           3. Verify start operation succeeds
*           4. Destroy timer
* @tc.expect: Timer creation and start operations return E_TIME_OK, timer is properly destroyed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer002, TestSize.Level1)
{
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    auto wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    auto result = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + 1000);
    EXPECT_EQ(result, TimeError::E_TIME_OK);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer003
* @tc.desc: Test starting repeat wakeup timer and verify multiple triggers
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact+wakeup type repeat timer with 1000ms interval
*           2. Start timer with 500ms initial delay
*           3. Wait for 2 seconds
*           4. Verify callback is triggered multiple times
*           5. Destroy timer
* @tc.expect: Timer starts successfully, callback is triggered more than once within 2 seconds
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer003, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT | timerInfo->TIMER_TYPE_WAKEUP);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    sleep(2);
    EXPECT_GT(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer004
* @tc.desc: Test starting repeat exact timer and verify multiple triggers
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact type repeat timer with 1000ms interval
*           2. Start timer with 500ms initial delay
*           3. Wait for 2 seconds
*           4. Verify callback is triggered multiple times
*           5. Destroy timer
* @tc.expect: Timer starts successfully, callback is triggered more than once within 2 seconds
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer004, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    sleep(2);
    EXPECT_GT(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: StartTimer005
* @tc.desc: Test disposable non-repeat timer auto-destruction after trigger
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact type disposable non-repeat timer
*           2. Start timer with 500ms delay
*           3. Wait for timer trigger
*           4. Attempt to destroy timer (should fail as already auto-destroyed)
* @tc.expect: Timer triggers successfully, destruction fails indicating timer was auto-destroyed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer005, TestSize.Level1)
{
    TIME_HILOGI(TIME_MODULE_CLIENT, "StartTimer013 start");
    g_data1 = 0;
    g_data2 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetDisposable(true);
    timerInfo->SetAutoRestore(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    errCode = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    sleep(1);
    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_DEAL_FAILED);
}

/**
* @tc.name: StartTimer006
* @tc.desc: Test disposable repeat timer does not auto-destroy
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact type disposable repeat timer with 1000ms interval
*           2. Start timer with 500ms initial delay
*           3. Wait for timer trigger
*           4. Destroy timer manually
* @tc.expect: Timer starts successfully, manual destruction succeeds (repeat timers not auto-destroyed)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer006, TestSize.Level1)
{
    TIME_HILOGI(TIME_MODULE_CLIENT, "StartTimer014 start");
    g_data1 = 0;
    g_data2 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetDisposable(true);
    timerInfo->SetAutoRestore(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    errCode = TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    sleep(1);
    errCode = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: StartTimer007
* @tc.desc: Test timer rearrangement after system time adjustment
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact+wakeup repeat timer with 1-hour interval
*           2. Set system time to 1 day ago
*           3. Start timer with future trigger time
*           4. Adjust system time forward to trigger timer
*           5. Verify timer triggers once
*           6. Adjust system time again and verify no additional trigger
* @tc.expect: Timer triggers only once after first time adjustment, rearrangement prevents duplicate triggers
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, StartTimer007, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT | timerInfo->TIMER_TYPE_WAKEUP);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(3600000);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    auto time = TimeServiceClient::GetInstance()->GetWallTimeMs() - 86400000;
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + 100000);
    // First trigger
    time += 86400000;
    result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    //Trigger a rearrangement
    time += 10000;
    result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer001
* @tc.desc: Test timer recovery data recording after timer creation
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime type timer
*           2. Verify recovery info map contains timer entry
*           3. Check timer state and trigger time in recovery data
*           4. Destroy timer
* @tc.expect: Recovery info map contains timer with state 0 and trigger time 0 after creation
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, RecoverTimer001, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_NE(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_NE(info->second->timerInfo, nullptr);
        EXPECT_EQ(info->second->state, 0);
        EXPECT_EQ(info->second->triggerTime, 0);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer002
* @tc.desc: Test timer recovery data recording after timer start
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime type timer
*           2. Start timer with 500ms boot time delay
*           3. Verify recovery info map contains updated timer state and trigger time
*           4. Destroy timer
* @tc.expect: Recovery info shows timer state 1 (started) with correct trigger time after start
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, RecoverTimer002, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + FIVE_HUNDRED);
    EXPECT_EQ(startRet, TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_NE(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_NE(info->second->timerInfo, nullptr);
        EXPECT_EQ(info->second->state, 1);
        EXPECT_EQ(info->second->triggerTime, time + FIVE_HUNDRED);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer003
* @tc.desc: Test timer recovery data recording after timer stop
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime type timer
*           2. Start timer with 500ms boot time delay
*           3. Stop timer
*           4. Verify recovery info map contains updated timer state
*           5. Destroy timer
* @tc.expect: Recovery info shows timer state 0 (stopped) but retains trigger time after stop
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, RecoverTimer003, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + FIVE_HUNDRED);
    EXPECT_EQ(startRet, TimeError::E_TIME_OK);
    auto stopRet = TimeServiceClient::GetInstance()->StopTimerV9(timerId);
    EXPECT_EQ(stopRet, TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_NE(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_NE(info->second->timerInfo, nullptr);
        EXPECT_EQ(info->second->state, 0);
        
        EXPECT_EQ(info->second->triggerTime, time + FIVE_HUNDRED);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer004
* @tc.desc: Test timer recovery data removal after timer destruction
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime type timer
*           2. Start timer with 500ms boot time delay
*           3. Destroy timer
*           4. Verify recovery info map no longer contains timer entry
* @tc.expect: Recovery info map is empty after timer destruction
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, RecoverTimer004, TestSize.Level1)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + FIVE_HUNDRED);
    EXPECT_EQ(startRet, TimeError::E_TIME_OK);
    auto destroyRet = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(destroyRet, TimeError::E_TIME_OK);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_EQ(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
    }
}

/**
* @tc.name: RecoverTimer005
* @tc.desc: Test non-repeat timer state in recovery data after trigger
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime non-repeat timer
*           2. Start timer with 500ms boot time delay
*           3. Wait for timer trigger
*           4. Verify recovery info shows timer state 0 (stopped) after trigger
*           5. Destroy timer
* @tc.expect: Timer triggers successfully, recovery info shows state 0 after completion
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, RecoverTimer005, TestSize.Level1)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + FIVE_HUNDRED);
    EXPECT_EQ(startRet, TimeError::E_TIME_OK);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_NE(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
        EXPECT_NE(info->second->timerInfo, nullptr);
        EXPECT_EQ(info->second->state, 0);
    }
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: RecoverTimer006
* @tc.desc: Test disposable non-repeat timer removal from recovery data after trigger
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime disposable non-repeat timer
*           2. Start timer with 500ms boot time delay
*           3. Wait for timer trigger
*           4. Verify recovery info map no longer contains timer entry
*           5. Attempt to destroy timer (should fail)
* @tc.expect: Timer auto-removes from recovery data after trigger, destruction fails
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, RecoverTimer006, TestSize.Level1)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetDisposable(true);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + FIVE_HUNDRED);
    EXPECT_EQ(startRet, TimeError::E_TIME_OK);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    {
        std::lock_guard<std::mutex> lock(TimeServiceClient::GetInstance()->recoverTimerInfoLock_);
        auto info = TimeServiceClient::GetInstance()->recoverTimerInfoMap_.find(timerId);
        EXPECT_EQ(info, TimeServiceClient::GetInstance()->recoverTimerInfoMap_.end());
    }
    auto ret = TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
    EXPECT_EQ(ret, E_TIME_DEAL_FAILED);
}

/**
* @tc.name: AdjustTimer001
* @tc.desc: Test timer adjustment functionality with system time changes
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact type timer
*           2. Start timer with 500ms delay
*           3. Call AdjustTimer to modify timer behavior
*           4. Wait for timer trigger
*           5. Verify callback execution
*           6. Destroy timer
* @tc.expect: Timer triggers successfully despite time adjustments, callback is executed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, AdjustTimer001, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    TimeServiceClient::GetInstance()->AdjustTimer(true, 5, 0);
    TimeServiceClient::GetInstance()->AdjustTimer(false, 0, 0);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: AdjustTimer002
* @tc.desc: Test timer exemption functionality
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Set timer exemption for specific timer names
*           2. Create exact type timer
*           3. Start timer with 500ms delay
*           4. Wait for timer trigger
*           5. Verify callback execution
*           6. Destroy timer
* @tc.expect: Timer triggers successfully with exemption settings, callback is executed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, AdjustTimer002, TestSize.Level1)
{
    g_data1 = 0;
    std::unordered_set<std::string> nameArr{"timer"};
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: AdjustTimer003
* @tc.desc: Test timer behavior after significant system time adjustment
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create exact+wakeup type timer
*           2. Start timer with 500ms delay
*           3. Adjust system time forward by 1 hour
*           4. Verify timer triggers immediately
*           5. Destroy timer
* @tc.expect: Timer triggers immediately after significant time adjustment, callback is executed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, AdjustTimer003, TestSize.Level1)
{
    g_data1 = 0;
    uint64_t timerId;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT | timerInfo->TIMER_TYPE_WAKEUP);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    EXPECT_NE(timerId, 0);
    auto triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, triggerTime + FIVE_HUNDRED);

    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = (currentTime.tv_sec + 3600) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time);
    EXPECT_EQ(result, TimeError::E_TIME_OK);
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: ReBatchAllTimers001
* @tc.desc: Test timer proxy functionality and rebatching after cancellation
* @tc.precon: Timer service is available, application has timer permissions
* @tc.step: 1. Create realtime type long-duration timer
*           2. Start timer with 5-minute delay
*           3. Set up timer proxy for current process
*           4. Cancel timer proxy
*           5. Adjust system time forward
*           6. Verify timer does not trigger due to proxy cancellation
*           7. Destroy timer
* @tc.expect: Timer does not trigger after proxy cancellation and time adjustment
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, ReBatchAllTimers001, TestSize.Level1)
{
    g_data1 = 0;

    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId;
    auto errCode = TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    int64_t time = 0;
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    auto startRet = TimeServiceClient::GetInstance()->StartTimerV9(timerId, time + 300000);
    EXPECT_EQ(startRet, TimeError::E_TIME_OK);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    pid_t pid = IPCSkeleton::GetCallingPid();
    pid_t uid = IPCSkeleton::GetCallingUid();
    std::set<int> pidList;
    pidList.insert(pid);
    TimeServiceClient::GetInstance()->ProxyTimer(uid, pidList, true, true);
    std::vector<int> pidVector;
    pidVector.push_back(pid);
    TimeSystemAbility::GetInstance()->ProxyTimer(uid, pidVector, false, true);

    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time1 = (currentTime.tv_sec + 10) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time1, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time1);
    int32_t result = TimeServiceClient::GetInstance()->SetTimeV9(time1);
    EXPECT_EQ(result, TimeError::E_TIME_OK);
    WaitForAlarm(&g_data1, 0);
    EXPECT_EQ(g_data1, 0);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: SetAutoTime001
* @tc.desc: Test setting auto time synchronization functionality
* @tc.precon: Time service is available, application has time setting permissions
* @tc.step: 1. Call SetAutoTime with true to enable auto time sync
*           2. Verify operation returns success (0)
*           3. Call SetAutoTime with false to disable auto time sync
*           4. Verify operation returns success (0)
* @tc.expect: Both enable and disable operations return 0 indicating success
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeClientTest, SetAutoTime001, TestSize.Level1)
{
    auto res = TimeServiceClient::GetInstance()->SetAutoTime(true);
    EXPECT_EQ(res, 0);
    res = TimeServiceClient::GetInstance()->SetAutoTime(false);
    EXPECT_EQ(res, 0);
}
} // namespace