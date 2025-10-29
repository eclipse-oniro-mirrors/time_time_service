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
#include "time_service_test.h"

#include <chrono>
#include <climits>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sys/stat.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "timer_info_test.h"
#include "token_setproc.h"
#include "want_agent.h"
#include "timer_call_back.h"
#include "time_common.h"
#include "event_manager.h"
#include "ntp_update_time.h"
#include "cjson_helper.h"

#define private public
#define protected public
#include "sntp_client.h"
#include "ntp_update_time.h"
#include "time_system_ability.h"
#include "ntp_trusted_time.h"
#include "time_tick_notify.h"
#include "timer_proxy.h"
#include "time_service_test.h"

namespace {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::MiscServices;
using namespace std::chrono;
using namespace OHOS::Security::AccessToken;

std::set<int> RESERVED_PIDLIST = {1111, 2222};
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NETWORK_TIME_STATUS_ON = "ON";
const std::string AUTO_TIME_STATUS_ON = "ON";
const std::string NTP_SERVER_A = "A";
const std::string NTP_SERVER_B = "B";
const std::string NTP_SERVER_C = "C";
const std::string NTP_SERVER_D = "D";
constexpr int64_t MIN_NTP_RETRY_INTERVAL = 10000;
constexpr int64_t MAX_NTP_RETRY_INTERVAL = 43200000;
const uint64_t TIMER_ID = 88888;
constexpr int64_t MINUTE_TO_MILLISECOND = 60000;
constexpr char BYTE_SNTP_MESSAGE = 0xD8;
constexpr int64_t MAX_TIME_DRIFT_IN_ONE_DAY = 2000;
constexpr int64_t MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS = 100;
constexpr int64_t ONE_DAY = 86400000;
constexpr int64_t ONE_HOUR = 3600000;
constexpr int64_t TWO_SECOND = 2000;
constexpr int64_t ONE_SECOND = 1000;

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
        },
        {
            .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
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
        },
        {
            .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

static HapPolicyParams g_policyC = {
    .apl = APL_SYSTEM_CORE,
    .domain = "test.domain",
    .permList = {
        {
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .bundleName = "ohos.permission_test.demoB",
            .grantMode = 1,
            .availableLevel = APL_NORMAL,
            .label = "label",
            .labelId = 1,
            .description = "test",
            .descriptionId = 1
        },
        {
            .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
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
            .permissionName = "ohos.permission.SET_TIME_ZONE",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.MANAGE_LOCAL_ACCOUNTS",
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
    .apiVersion = 8,
    .isSystemApp = false
};

class TimeServiceTimeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    void AddPermission();
    void DeletePermission();
    void StartIdleTimer();
    void DestroyIdleTimer();
};

void TimeServiceTimeTest::SetUpTestCase(void)
{
}

void TimeServiceTimeTest::TearDownTestCase(void)
{
}

void TimeServiceTimeTest::SetUp(void)
{
}

void TimeServiceTimeTest::TearDown(void)
{
}

void TimeServiceTimeTest::AddPermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServiceTimeTest::DeletePermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_notSystemInfoParams, g_policyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TestNtpThread(const char *name)
{
    {
        std::lock_guard<std::mutex> autoLock(NtpUpdateTime::requestMutex_);
    }
    NtpUpdateTime::SetSystemTime(NtpUpdateSource::INIT);
}

/**
* @tc.name: SetTime001
* @tc.desc: Test setting system time with valid future time value
* @tc.precon: Application has system time setting permission
* @tc.step: 1. Add required permissions
*           2. Get current time and calculate future time (1000 seconds later)
*           3. Call SetTime method with future time
*           4. Verify operation returns true indicating success
*           5. Remove permissions
* @tc.expect: SetTime operation succeeds and returns true
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTime001, TestSize.Level1)
{
    AddPermission();
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    DeletePermission();
}

/**
* @tc.name: SetTime002
* @tc.desc: Test setting system time with negative value (invalid input)
* @tc.precon: Time service is available
* @tc.step: 1. Call SetTime method with negative value (-1)
*           2. Verify operation returns false indicating failure
* @tc.expect: SetTime operation fails and returns false for negative input
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTime002, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTime(-1);
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTime003
* @tc.desc: Test setting system time with maximum long value (LLONG_MAX)
* @tc.precon: Time service is available
* @tc.step: 1. Call SetTime method with LLONG_MAX value
*           2. Verify operation returns false indicating failure
* @tc.expect: SetTime operation fails and returns false for LLONG_MAX input
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTime003, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTime(LLONG_MAX);
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTime004
* @tc.desc: Test setting system time with return code parameter
* @tc.precon: Application has system time setting permission
* @tc.step: 1. Add required permissions
*           2. Get current time and calculate future time (1000 seconds later)
*           3. Call SetTime method with time and code parameters
*           4. Verify operation returns true and code is 0
*           5. Remove permissions
*           6. Test system ability SetTime without permission
* @tc.expect: SetTime operation succeeds with code 0, system ability returns permission error
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTime004, TestSize.Level1)
{
    AddPermission();
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    int32_t code;
    bool result = TimeServiceClient::GetInstance()->SetTime(time, code);
    EXPECT_TRUE(result);
    EXPECT_EQ(code, 0);
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->SetTime(0, 0);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetTimeInner001
* @tc.desc: Test internal system time setting functionality
* @tc.precon: Time system ability is available
* @tc.step: 1. Get current time and calculate future time (1000 seconds later)
*           2. Call SetTimeInner method with future time
*           3. Verify operation returns E_TIME_OK
* @tc.expect: SetTimeInner operation succeeds and returns E_TIME_OK
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTimeInner001, TestSize.Level1)
{
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    int64_t time = (currentTime.tv_sec + 1000) * 1000 + currentTime.tv_usec / 1000;
    ASSERT_GT(time, 0);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    auto result = TimeSystemAbility::GetInstance()->SetTimeInner(time);
    EXPECT_EQ(result, E_TIME_OK);
}

/**
* @tc.name: SetTimeZone001
* @tc.desc: Test setting and restoring system timezone
* @tc.precon: Application has timezone setting permission
* @tc.step: 1. Add required permissions
*           2. Get current timezone
*           3. Set timezone to "Asia/Nicosia"
*           4. Verify new timezone is set
*           5. Restore original timezone
*           6. Remove permissions
* @tc.expect: All timezone operations succeed, timezone changes are applied correctly
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZone001, TestSize.Level1)
{
    AddPermission();
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());

    std::string timeZoneNicosia("Asia/Nicosia");
    bool result = TimeServiceClient::GetInstance()->SetTimeZone(timeZoneNicosia);
    EXPECT_TRUE(result);
    auto getTimeZoneNicosia = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);
    bool ret = TimeServiceClient::GetInstance()->SetTimeZone(getCurrentTimeZone);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: SetTimeZone002
* @tc.desc: Test setting system timezone with invalid timezone ID
* @tc.precon: Time service is available
* @tc.step: 1. Call SetTimeZone method with invalid timezone "123"
*           2. Verify operation returns false indicating failure
* @tc.expect: SetTimeZone operation fails and returns false for invalid timezone
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZone002, TestSize.Level1)
{
    bool result = TimeServiceClient::GetInstance()->SetTimeZone("123");
    EXPECT_FALSE(result);
}

/**
* @tc.name: SetTimeZone003
* @tc.desc: Test setting system timezone with return code parameter
* @tc.precon: Application has timezone setting permission
* @tc.step: 1. Add required permissions
*           2. Get current timezone
*           3. Set timezone to "Asia/Shanghai" with code parameter
*           4. Verify operation returns true and code is 0
*           5. Restore original timezone
*           6. Remove permissions
*           7. Test system ability SetTimeZone without permission
* @tc.expect: Timezone operations succeed with code 0, system ability returns permission error
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZone003, TestSize.Level1)
{
    AddPermission();
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());

    std::string timeZoneShanghai("Asia/Shanghai");
    int32_t code;
    bool result = TimeServiceClient::GetInstance()->SetTimeZone(timeZoneShanghai, code);
    EXPECT_TRUE(result);
    EXPECT_EQ(code, 0);
    auto getTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(getTimeZone, timeZoneShanghai);
    bool ret = TimeServiceClient::GetInstance()->SetTimeZone(getCurrentTimeZone);
    EXPECT_TRUE(ret);
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->SetTimeZone("", 0);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetTimeZoneInner001
* @tc.desc: Test internal system timezone setting functionality
* @tc.precon: Time system ability is available
* @tc.step: 1. Get current timezone
*           2. Set timezone to "Asia/Shanghai" using SetTimeZoneInner
*           3. Verify new timezone is set
*           4. Restore original timezone
* @tc.expect: All SetTimeZoneInner operations succeed and return E_TIME_OK
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetTimeZoneInner001, TestSize.Level1)
{
    time_t t;
    (void)time(&t);
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time before: %{public}s", asctime(localtime(&t)));
    auto getCurrentTimeZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(getCurrentTimeZone.empty());

    std::string timeZoneNicosia("Asia/Shanghai");
    bool result = TimeSystemAbility::GetInstance()->SetTimeZoneInner(timeZoneNicosia);
    EXPECT_EQ(result, E_TIME_OK);
    auto getTimeZoneNicosia = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(timeZoneNicosia, getTimeZoneNicosia);
    auto ret = TimeSystemAbility::GetInstance()->SetTimeZoneInner(getCurrentTimeZone);
    EXPECT_EQ(ret, E_TIME_OK);
}

/**
* @tc.name: GetWallTimeMs001
* @tc.desc: Test retrieving wall time in milliseconds and verify time progression
* @tc.precon: Time service is available
* @tc.step: 1. Get first wall time measurement
*           2. Get second wall time measurement
*           3. Verify both measurements are valid and second is not less than first
* @tc.expect: Both time measurements are valid (not -1) and time progresses forward
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetWallTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetWallTimeNs001
* @tc.desc: Test retrieving wall time in nanoseconds and verify time progression
* @tc.precon: Time service is available
* @tc.step: 1. Get first wall time measurement in nanoseconds
*           2. Get second wall time measurement in nanoseconds
*           3. Verify both measurements are valid and second is not less than first
* @tc.expect: Both time measurements are valid (not -1) and time progresses forward
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetWallTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetWallTimeNs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetBootTimeNs001
* @tc.desc: Test retrieving boot time in nanoseconds and verify time progression
* @tc.precon: Time service is available
* @tc.step: 1. Get first boot time measurement in nanoseconds
*           2. Get second boot time measurement in nanoseconds
*           3. Verify both measurements are valid and second is not less than first
* @tc.expect: Both time measurements are valid (not -1) and time progresses forward
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetBootTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetBootTimeNs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetMonotonicTimeMs001
* @tc.desc: Test retrieving monotonic time in milliseconds and verify time progression
* @tc.precon: Time service is available
* @tc.step: 1. Get first monotonic time measurement in milliseconds
*           2. Get second monotonic time measurement in milliseconds
*           3. Verify both measurements are valid and second is not less than first
* @tc.expect: Both time measurements are valid (not -1) and time progresses forward
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetMonotonicTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetMonotonicTimeNs001
* @tc.desc: Test retrieving monotonic time in nanoseconds and verify time progression
* @tc.precon: Time service is available
* @tc.step: 1. Get first monotonic time measurement in nanoseconds
*           2. Get second monotonic time measurement in nanoseconds
*           3. Verify both measurements are valid and second is not less than first
* @tc.expect: Both time measurements are valid (not -1) and time progresses forward
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetMonotonicTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_NE(time1, -1);
    auto time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeNs();
    EXPECT_GE(time2, time1);
}

/**
* @tc.name: GetThreadTimeMs001
* @tc.desc: Test retrieving thread time in milliseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetThreadTimeMs method
*           2. Verify returned time value is valid
* @tc.expect: Thread time measurement is valid (not -1)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetThreadTimeMs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_NE(time1, -1);
}

/**
* @tc.name: GetThreadTimeNs001
* @tc.desc: Test retrieving thread time in nanoseconds
* @tc.precon: Time service is available
* @tc.step: 1. Call GetThreadTimeNs method
*           2. Verify returned time value is valid
* @tc.expect: Thread time measurement is valid (not -1)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, GetThreadTimeNs001, TestSize.Level1)
{
    auto time1 = TimeServiceClient::GetInstance()->GetThreadTimeNs();
    EXPECT_NE(time1, -1);
}

/**
* @tc.name: SntpClient001
* @tc.desc: Test SNTP client GetNtpTimestamp64 functionality with valid input
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call GetNtpTimestamp64 with valid buffer
*           3. Verify returned timestamp is positive
* @tc.expect: GetNtpTimestamp64 returns positive timestamp value
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient001, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto buffer = std::string("31234114451");
    auto millisecond = ntpClient->GetNtpTimestamp64(0, buffer.c_str());
    EXPECT_GT(millisecond, 0);
}

/**
* @tc.name: SntpClient002
* @tc.desc: Test SNTP client GetNtpField32 functionality with valid input
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call GetNtpField32 with valid buffer
*           3. Verify returned time value is positive
* @tc.expect: GetNtpField32 returns positive time value
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient002, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto buffer = std::string("31234114451");
    auto millisecond = ntpClient->GetNtpField32(0, buffer.c_str());
    EXPECT_GT(millisecond, 0);
}

/**
* @tc.name: SntpClient003
* @tc.desc: Test SNTP client ConvertNtpToStamp functionality with invalid inputs
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call ConvertNtpToStamp with various invalid values (0, 100, 2147483648, 31234114451)
*           3. Verify all conversions return 0 indicating failure
* @tc.expect: ConvertNtpToStamp returns 0 for all invalid input values
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient003, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto timeStamp = ntpClient->ConvertNtpToStamp(0);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(100);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(2147483648);
    EXPECT_EQ(timeStamp, 0);
    timeStamp = ntpClient->ConvertNtpToStamp(31234114451);
    EXPECT_EQ(timeStamp, 0);
}

/**
* @tc.name: SntpClient004
* @tc.desc: Test SNTP client ConvertNtpToStamp functionality with valid input
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call ConvertNtpToStamp with valid NTP timestamp
*           3. Verify conversion returns expected Unix timestamp
* @tc.expect: ConvertNtpToStamp returns correct Unix timestamp (1358598439000)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient004, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    uint64_t time = 999999999911;
    auto timeStamp = ntpClient->ConvertNtpToStamp(time << 32);
    EXPECT_EQ(timeStamp, 1358598439000);
}

/**
* @tc.name: SntpClient005
* @tc.desc: Test SNTP client RequestTime functionality with empty server string
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call RequestTime with empty server string
*           3. Verify operation returns false
* @tc.expect: RequestTime returns false for empty server string
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient005, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    auto res = ntpClient -> RequestTime("");
    EXPECT_FALSE(res);
}

/**
* @tc.name: SntpClient006
* @tc.desc: Test SNTP client SetClockOffset functionality
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call SetClockOffset with value 1
*           3. Verify clock offset is set correctly
* @tc.expect: Clock offset is successfully set to 1
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient006, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    ntpClient -> SetClockOffset(1);
    EXPECT_EQ(ntpClient -> m_clockOffset, 1);
}

/**
* @tc.name: SntpClient007
* @tc.desc: Test SNTP client ConvertUnixToNtp functionality
* @tc.precon: SNTP client is properly initialized, system time is available
* @tc.step: 1. Create SNTP client instance
*           2. Get current Unix time
*           3. Call ConvertUnixToNtp to convert to NTP timestamp
*           4. Verify NTP timestamp fields are populated
* @tc.expect: ConvertUnixToNtp successfully populates NTP timestamp fields
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient007, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    OHOS::MiscServices::SNTPClient::ntp_timestamp ntp{.second = 0, .fraction = 0};
    struct timeval unix;
    gettimeofday(&unix, nullptr);
    ntpClient -> ConvertUnixToNtp(&ntp, &unix);
    EXPECT_NE(ntp.second, 0);
    EXPECT_NE(ntp.fraction, 0);
}

/**
* @tc.name: SntpClient008
* @tc.desc: Test SNTP client CreateMessage functionality
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Call CreateMessage to generate NTP message buffer
*           3. Verify message header byte is correctly set
* @tc.expect: CreateMessage generates valid NTP message with correct header byte (0x1B)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient008, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    char sendBuf[48] = { 0 };
    ntpClient -> CreateMessage(sendBuf);
    EXPECT_EQ(sendBuf[0], '\x1B');
}

/**
* @tc.name: SntpClient009
* @tc.desc: Test SNTP client ReceivedMessage functionality with valid message
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Prepare valid NTP message buffer with required bytes set
*           3. Call ReceivedMessage with valid buffer
*           4. Verify operation returns true
* @tc.expect: ReceivedMessage returns true for valid NTP message
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient009, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    char buf[48] = {0};
    buf[32] = BYTE_SNTP_MESSAGE;
    buf[40] = BYTE_SNTP_MESSAGE;
    auto res = ntpClient -> ReceivedMessage(buf);
    EXPECT_TRUE(res);
}

/**
* @tc.name: SntpClient010
* @tc.desc: Test SNTP client ReceivedMessage functionality with invalid messages
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Test ReceivedMessage with empty buffer
*           3. Test with only first required byte set
*           4. Test with only second required byte set
*           5. Verify all invalid cases return false
* @tc.expect: ReceivedMessage returns false for all invalid message formats
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient010, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    char buf[48] = {0};
    auto res = ntpClient -> ReceivedMessage(buf);
    EXPECT_FALSE(res);
    buf[32] = BYTE_SNTP_MESSAGE;
    buf[40] = 0;
    res = ntpClient -> ReceivedMessage(buf);
    EXPECT_FALSE(res);
    buf[32] = 0;
    buf[40] = BYTE_SNTP_MESSAGE;
    res = ntpClient -> ReceivedMessage(buf);
    EXPECT_FALSE(res);
}

/**
* @tc.name: SntpClient011
* @tc.desc: Test SNTP client GetReferenceId functionality
* @tc.precon: SNTP client is properly initialized
* @tc.step: 1. Create SNTP client instance
*           2. Prepare test buffer with known values
*           3. Call GetReferenceId to extract reference ID
*           4. Verify first array element matches buffer content
* @tc.expect: GetReferenceId correctly extracts reference ID from buffer
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient011, TestSize.Level0)
{
    char buf[5] = {'1', '2', '3', '4', '5'};
    int array[5] = {0};
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    ntpClient -> GetReferenceId(0, buf, array);
    EXPECT_EQ(array[0], '1');
}

/**
* @tc.name: SntpClient012
* @tc.desc: Test SNTP client getter methods for time properties
* @tc.precon: SNTP client is properly initialized with time values set
* @tc.step: 1. Create SNTP client instance and SNTP message
*           2. Set NTP time properties (mNtpTime, mNtpTimeReference, mRoundTripTime)
*           3. Verify getter methods return correct values
* @tc.expect: All getter methods return the expected time property values
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SntpClient012, TestSize.Level0)
{
    std::shared_ptr<SNTPClient> ntpClient = std::make_shared<SNTPClient>();
    std::shared_ptr<SNTPClient::SNTPMessage> sntpMessage = std::make_shared<SNTPClient::SNTPMessage>();
    sntpMessage -> clear();
    ntpClient -> mNtpTime = 1;
    ntpClient -> mNtpTimeReference = 2;
    ntpClient -> mRoundTripTime = 3;
    EXPECT_EQ(ntpClient -> getNtpTime(), 1);
    EXPECT_EQ(ntpClient -> getNtpTimeReference(), 2);
    EXPECT_EQ(ntpClient -> getRoundTripTime(), 3);
}

/**
* @tc.name: NtpTrustedTime001
* @tc.desc: Test NtpTrustedTime functionality with null time result
* @tc.precon: NtpTrustedTime class is available
* @tc.step: 1. Create NtpTrustedTime instance with null time result
*           2. Call CurrentTimeMillis method
*           3. Call GetCacheAge method
*           4. Verify both methods return error values
* @tc.expect: CurrentTimeMillis returns -1, GetCacheAge returns INT_MAX when time result is null
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime001, TestSize.Level0)
{
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = nullptr;
    int64_t errCode = ntpTrustedTime->CurrentTimeMillis();
    EXPECT_EQ(errCode, -1);
    errCode = ntpTrustedTime->GetCacheAge();
    EXPECT_EQ(errCode, INT_MAX);
}

/**
* @tc.name: NtpTrustedTime002
* @tc.desc: Test NtpTrustedTime functionality with valid time result
* @tc.precon: NtpTrustedTime class is available
* @tc.step: 1. Create NtpTrustedTime instance with valid time result
*           2. Call CurrentTimeMillis method
*           3. Call GetCacheAge method
*           4. Verify both methods return positive values
* @tc.expect: CurrentTimeMillis and GetCacheAge return positive values with valid time result
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime002, TestSize.Level0)
{
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(1, 1, 0, NTP_SERVER_A);
    int64_t time = ntpTrustedTime->CurrentTimeMillis();
    EXPECT_GT(time, 0);
    int64_t cacheAge = ntpTrustedTime->GetCacheAge();
    EXPECT_GT(cacheAge, 0);
}

/**
* @tc.name: NtpTrustedTime003
* @tc.desc: Test TimeResult Clear functionality
* @tc.precon: TimeResult class is available
* @tc.step: 1. Create TimeResult instance
*           2. Call Clear method
*           3. Verify all time fields are reset to 0
* @tc.expect: All time fields (mTimeMillis, mElapsedRealtimeMillis, mCertaintyMillis) are set to 0 after clear
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime003, TestSize.Level0)
{
    auto TimeResult = std::make_shared<OHOS::MiscServices::NtpTrustedTime::TimeResult>();
    TimeResult->Clear();
    EXPECT_EQ(TimeResult->mTimeMillis, 0);
    EXPECT_EQ(TimeResult->mElapsedRealtimeMillis, 0);
    EXPECT_EQ(TimeResult->mCertaintyMillis, 0);
}

/**
* @tc.name: NtpTrustedTime004
* @tc.desc: Test TimeResult GetTimeMillis functionality after clear
* @tc.precon: TimeResult class is available
* @tc.step: 1. Create TimeResult instance
*           2. Call Clear method to reset all fields
*           3. Call GetTimeMillis method
*           4. Verify returned value is 0
* @tc.expect: GetTimeMillis returns 0 after TimeResult is cleared
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime004, TestSize.Level0)
{
    auto TimeResult = std::make_shared<OHOS::MiscServices::NtpTrustedTime::TimeResult>();
    TimeResult->Clear();
    auto res = TimeResult->GetTimeMillis();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name: NtpTrustedTime005
* @tc.desc: Test NtpTrustedTime time result trust verification under different scenarios
* @tc.precon: NtpTrustedTime class is available, time utilities work correctly
* @tc.step: 1. Test with null current time result - should not trust new result
*           2. Test with outdated current time result - should not trust new result
*           3. Test with current result within error margin - should trust new result and update
*           4. Test with current result at upper error margin - should trust new result and update
* @tc.expect: Time result is trusted only when within acceptable time drift margin, candidates list is properly managed
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime005, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    // test mTimeResult is nullptr
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    ntpTrustedTime->mTimeResult = nullptr;
    auto timeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    bool ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 1);

    // test mTimeResult is unavailable due to time out
    auto wallTime1 = wallTime - 2 * ONE_DAY;
    auto bootTime1 = bootTime - 2 * ONE_DAY;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime1, bootTime1, 0, NTP_SERVER_B);
    ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 2);

    // test new result Within the margin of error
    auto wallTime2 = wallTime - ONE_HOUR - MAX_TIME_DRIFT_IN_ONE_DAY;
    auto bootTime2 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0, NTP_SERVER_C);
    ret = false;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);

    auto wallTime3 = wallTime - ONE_HOUR + MAX_TIME_DRIFT_IN_ONE_DAY;
    auto bootTime3 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0, NTP_SERVER_D);
    ret = false;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime006
* @tc.desc: Test NtpTrustedTime time result trust verification with results outside error margin
* @tc.precon: NtpTrustedTime class is available, time utilities work correctly
* @tc.step: 1. Test with new result below lower error margin - should not trust and keep current result
*           2. Test with new result above upper error margin - should not trust and keep current result
* @tc.expect: Time results outside acceptable drift margin are not trusted, current result remains unchanged
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime006, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    // test mTimeResult is nullptr
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();
    auto timeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    
    // test new result out of the margin of error
    auto wallTime1 = wallTime - ONE_HOUR - MAX_TIME_DRIFT_IN_ONE_DAY - TWO_SECOND;
    auto bootTime1 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime1, bootTime1, 0, NTP_SERVER_B);
    auto ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime1);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime1);
    EXPECT_EQ(ret, false);

    auto wallTime2 = wallTime - ONE_HOUR + MAX_TIME_DRIFT_IN_ONE_DAY + TWO_SECOND;
    auto bootTime2 = bootTime - ONE_HOUR;
    ntpTrustedTime->mTimeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0, NTP_SERVER_C);
    ret = true;
    ret = ntpTrustedTime->IsTimeResultTrusted(timeResult);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetTimeMillis(), wallTime2);
    EXPECT_EQ(ntpTrustedTime->mTimeResult->GetElapsedRealtimeMillis(), bootTime2);
}

/**
* @tc.name: NtpTrustedTime007
* @tc.desc: Test FindBestTimeResult with 3 similar time candidates (consensus scenario)
* @tc.precon: NtpTrustedTime class is available, time utilities work correctly
* @tc.step: 1. Create 3 time results with similar timestamps within tolerance
*           2. Add all candidates to candidates list
*           3. Call FindBestTimeResult method
*           4. Verify method returns true and clears candidates list
* @tc.expect: FindBestTimeResult returns true when 3 candidates reach consensus, candidates list is cleared
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime007, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // three time is similar, vote for 3 candidate
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    auto wallTime2 = wallTime + ONE_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0, NTP_SERVER_B);
    auto wallTime3 = wallTime + TWO_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS / 2;
    auto bootTime3 = bootTime + TWO_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0, NTP_SERVER_C);
    bool ret = true;
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime008
* @tc.desc: Test FindBestTimeResult with 2 similar time candidates (majority scenario)
* @tc.precon: NtpTrustedTime class is available, time utilities work correctly
* @tc.step: 1. Create 3 time results with 2 having similar timestamps
*           2. Add all candidates to candidates list
*           3. Call FindBestTimeResult method
*           4. Verify method returns true and clears candidates list
* @tc.expect: FindBestTimeResult returns true when 2 out of 3 candidates agree, candidates list is cleared
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime008, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // two time is similar, vote for 3 candidate
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    auto wallTime2 = wallTime + TWO_SECOND;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0, NTP_SERVER_B);
    auto wallTime3 = wallTime + TWO_SECOND;
    auto bootTime3 = bootTime + TWO_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0, NTP_SERVER_C);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    bool ret = false;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, true);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime009
* @tc.desc: Test FindBestTimeResult with no consensus among time candidates
* @tc.precon: NtpTrustedTime class is available, time utilities work correctly
* @tc.step: 1. Create 3 time results with significantly different timestamps
*           2. Add all candidates to candidates list
*           3. Call FindBestTimeResult method
*           4. Verify method returns false and clears candidates list
* @tc.expect: FindBestTimeResult returns false when no consensus is reached, candidates list is cleared
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime009, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // test 3 timeResult got different time
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    auto wallTime2 = wallTime + TWO_SECOND;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0, NTP_SERVER_B);
    auto wallTime3 = wallTime + TWO_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS * 2;
    auto bootTime3 = bootTime + TWO_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0, NTP_SERVER_C);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    bool ret = true;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: NtpTrustedTime010
* @tc.desc: Test FindBestTimeResult with insufficient candidate count
* @tc.precon: NtpTrustedTime class is available
* @tc.step: 1. Test with empty candidates list
*           2. Test with only 1 candidate in the list
*           3. Verify both cases return false
* @tc.expect: FindBestTimeResult returns false when candidates count is less than 2
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime010, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    bool ret = true;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);

    auto timeResult = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult);
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);
}

/**
* @tc.name: NtpTrustedTime011
* @tc.desc: Test FindBestTimeResult with tie scenario (2 vs 2 candidates)
* @tc.precon: NtpTrustedTime class is available, time utilities work correctly
* @tc.step: 1. Create 4 time results forming two distinct groups
*           2. Add all candidates to candidates list
*           3. Call FindBestTimeResult method
*           4. Verify method returns false and clears candidates list
* @tc.expect: FindBestTimeResult returns false when no clear majority exists (tie scenario)
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTrustedTime011, TestSize.Level0)
{
    int64_t wallTime = 0;
    TimeUtils::GetWallTimeMs(wallTime);
    int64_t bootTime = 0;
    TimeUtils::GetBootTimeMs(bootTime);
    std::shared_ptr<NtpTrustedTime> ntpTrustedTime = std::make_shared<NtpTrustedTime>();

    // two time is similar, vote for 3 candidate
    auto timeResult1 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime, bootTime, 0, NTP_SERVER_A);
    auto wallTime2 = wallTime + ONE_SECOND;
    auto bootTime2 = bootTime + ONE_SECOND;
    auto timeResult2 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime2, bootTime2, 0, NTP_SERVER_B);
    auto wallTime3 = wallTime + ONE_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS * 2;
    auto bootTime3 = bootTime + ONE_SECOND;
    auto timeResult3 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime3, bootTime3, 0, NTP_SERVER_C);
    auto wallTime4 = wallTime + TWO_SECOND + MAX_TIME_TOLERANCE_BETWEEN_NTP_SERVERS * 2;
    auto bootTime4 = bootTime + TWO_SECOND;
    auto timeResult4 = std::make_shared<NtpTrustedTime::TimeResult>(wallTime4, bootTime4, 0, NTP_SERVER_C);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult1);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult2);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult3);
    ntpTrustedTime->TimeResultCandidates_.push_back(timeResult4);
    bool ret = true;
    ret = ntpTrustedTime->FindBestTimeResult();
    EXPECT_EQ(ret, false);
    EXPECT_EQ(ntpTrustedTime->TimeResultCandidates_.size(), 0);
}

/**
* @tc.name: TimeTick001
* @tc.desc: Test TimeTickNotify RefreshNextTriggerTime functionality
* @tc.precon: Time service is available, application has time setting permission
* @tc.step: 1. Add required permissions
*           2. Get current wall time and align to minute boundary
*           3. Set system time to aligned time
*           4. Call RefreshNextTriggerTime method
*           5. Verify next trigger time is correctly calculated
*           6. Remove permissions
* @tc.expect: Next trigger time is correctly calculated as current time plus one minute
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, TimeTick001, TestSize.Level0)
{
    AddPermission();
    int64_t time = 0;
    TimeUtils::GetWallTimeMs(time);
    time = (time / MINUTE_TO_MILLISECOND) * MINUTE_TO_MILLISECOND;
    bool result = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(result);
    auto pair = TimeTickNotify::GetInstance().RefreshNextTriggerTime();
    EXPECT_EQ(pair.first, time + MINUTE_TO_MILLISECOND);
    EXPECT_TRUE(pair.second);
    DeletePermission();
}

/**
* @tc.name: SetSystemTime001
* @tc.desc: Test multi-threaded NTP time retrieval with auto time enabled
* @tc.precon: NtpUpdateTime service is initialized, auto time feature is available
* @tc.step: 1. Initialize NtpUpdateTime and save current auto time status
*           2. Enable auto time status
*           3. Create 4 threads to concurrently retrieve NTP time
*           4. Wait for all threads to complete
*           5. Restore original auto time status
* @tc.expect: All threads complete NTP time retrieval successfully in multi-threaded environment
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimeTest, SetSystemTime001, TestSize.Level1)
{
    NtpUpdateTime::GetInstance().Init();
    std::string tmp = NtpUpdateTime::autoTimeInfo_.status;
    NtpUpdateTime::autoTimeInfo_.status = AUTO_TIME_STATUS_ON;

    std::thread thread1(TestNtpThread, "thread1");
    std::thread thread2(TestNtpThread, "thread2");
    std::thread thread3(TestNtpThread, "thread3");
    std::thread thread4(TestNtpThread, "thread4");
    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();

    NtpUpdateTime::autoTimeInfo_.status = tmp;
}

/**
* @tc.name: NtpTime001
* @tc.desc: Test NTP address string splitting with maximum size limit
* @tc.precon: NtpUpdateTime service is available
* @tc.step: 1. Create NTP address string with 6 comma-separated values
*           2. Call SplitNtpAddrs method
*           3. Verify returned list contains maximum 5 addresses
* @tc.expect: SplitNtpAddrs returns maximum 5 addresses even when input contains more
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTime001, TestSize.Level0)
{
    const std::string ntpStr = "aaa,bbb,ccc,ddd,eee,fff";
    auto res = NtpUpdateTime::GetInstance().SplitNtpAddrs(ntpStr);
    EXPECT_EQ(res.size(), 5);
}

/**
* @tc.name: NtpTime002
* @tc.desc: Test network time refresh functionality under different status conditions
* @tc.precon: NtpUpdateTime service is available
* @tc.step: 1. Save current auto time status
*           2. Test RefreshNetworkTimeByTimer with network time off
*           3. Test RefreshNetworkTimeByTimer with network time on
*           4. Test NITZ time validation before and after update
*           5. Restore original auto time status
* @tc.expect: Network time refresh behaves correctly based on status, NITZ time validation works as expected
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTime002, TestSize.Level0)
{
    auto status = NtpUpdateTime::GetInstance().autoTimeInfo_.status;

    NtpUpdateTime::GetInstance().autoTimeInfo_.status = NETWORK_TIME_STATUS_OFF;
    NtpUpdateTime::GetInstance().RefreshNetworkTimeByTimer(TIMER_ID);

    NtpUpdateTime::GetInstance().autoTimeInfo_.status = NETWORK_TIME_STATUS_ON;
    NtpUpdateTime::GetInstance().RefreshNetworkTimeByTimer(TIMER_ID);

    NtpUpdateTime::GetInstance().nitzUpdateTimeMilli_ = 0;
    auto res = NtpUpdateTime::GetInstance().IsValidNITZTime();
    EXPECT_FALSE(res);

    NtpUpdateTime::GetInstance().UpdateNITZSetTime();
    res = NtpUpdateTime::GetInstance().IsValidNITZTime();
    EXPECT_TRUE(res);
    NtpUpdateTime::GetInstance().RefreshNetworkTimeByTimer(TIMER_ID);

    NtpUpdateTime::GetInstance().autoTimeInfo_.status = status;
}

/**
* @tc.name: NtpUpdateTime001
* @tc.desc: Test system time setting with network time switch off
* @tc.precon: NtpUpdateTime service is available
* @tc.step: 1. Set network time status to off
*           2. Call SetSystemTime with retry by timer source
*           3. Verify NTP retry interval remains at maximum value
* @tc.expect: NTP retry interval stays at maximum when network time is disabled
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpUpdateTime001, TestSize.Level0)
{
    NtpUpdateTime::GetInstance().autoTimeInfo_.status = NETWORK_TIME_STATUS_OFF;
    NtpUpdateTime::SetSystemTime(NtpUpdateSource::RETRY_BY_TIMER);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MAX_NTP_RETRY_INTERVAL);
}

/**
* @tc.name: NtpUpdateTime002
* @tc.desc: Test NTP retry interval adjustment based on different trigger sources
* @tc.precon: NtpUpdateTime service is available
* @tc.step: 1. Set initial retry interval to maximum
*           2. Test RefreshNextTriggerTime with various trigger sources
*           3. Verify retry interval is adjusted correctly for each scenario
* @tc.expect: Retry interval is minimized for normal operations, remains maximum for retry scenarios
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpUpdateTime002, TestSize.Level0)
{
    NtpUpdateTime::ntpRetryInterval_ = MAX_NTP_RETRY_INTERVAL;
    NtpUpdateTime::RefreshNextTriggerTime(RETRY_BY_TIMER, false, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MAX_NTP_RETRY_INTERVAL);
    
    NtpUpdateTime::RefreshNextTriggerTime(REGISTER_SUBSCRIBER, false, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MIN_NTP_RETRY_INTERVAL);

    NtpUpdateTime::RefreshNextTriggerTime(NET_CONNECTED, false, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MIN_NTP_RETRY_INTERVAL);

    NtpUpdateTime::RefreshNextTriggerTime(NTP_SERVER_CHANGE, false, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MIN_NTP_RETRY_INTERVAL);

    NtpUpdateTime::RefreshNextTriggerTime(AUTO_TIME_CHANGE, false, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MIN_NTP_RETRY_INTERVAL);

    NtpUpdateTime::RefreshNextTriggerTime(INIT, false, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MIN_NTP_RETRY_INTERVAL);

    NtpUpdateTime::RefreshNextTriggerTime(INIT, true, true);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MAX_NTP_RETRY_INTERVAL);

    NtpUpdateTime::RefreshNextTriggerTime(INIT, true, false);
    EXPECT_EQ(NtpUpdateTime::ntpRetryInterval_, MAX_NTP_RETRY_INTERVAL);
}

/**
* @tc.name: SetAutoTime001
* @tc.desc: Test auto time setting functionality with proper permissions
* @tc.precon: Time system ability is available, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Call SetAutoTime to enable auto time
*           3. Call SetAutoTime to disable auto time
*           4. Verify both operations return success
*           5. Remove permissions
* @tc.expect: Both enable and disable auto time operations return E_TIME_OK
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SetAutoTime001, TestSize.Level0)
{
    AddPermission();
    auto res = TimeSystemAbility::GetInstance()->SetAutoTime(true);
    EXPECT_EQ(res, E_TIME_OK);
    res = TimeSystemAbility::GetInstance()->SetAutoTime(false);
    EXPECT_EQ(res, E_TIME_OK);
}

/**
* @tc.name: GetNtpTimeMsWithNoPermission001
* @tc.desc: Test NTP time retrieval without system application permission
* @tc.precon: Time system ability is available
* @tc.step: 1. Remove system application permissions
*           2. Call GetNtpTimeMs method
*           3. Verify operation returns permission error
* @tc.expect: GetNtpTimeMs returns E_TIME_NOT_SYSTEM_APP without proper permissions
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, GetNtpTimeMsWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    int64_t time = 0;
    auto res = TimeSystemAbility::GetInstance()->GetNtpTimeMs(time);
    EXPECT_EQ(res, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: GetRealTimeMsWithNoPermission001
* @tc.desc: Test real time retrieval without system application permission
* @tc.precon: Time system ability is available
* @tc.step: 1. Remove system application permissions
*           2. Call GetRealTimeMs method
*           3. Verify operation returns permission error
* @tc.expect: GetRealTimeMs returns E_TIME_NOT_SYSTEM_APP without proper permissions
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, GetRealTimeMsWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    int64_t time = 0;
    auto res = TimeSystemAbility::GetInstance()->GetRealTimeMs(time);
    EXPECT_EQ(res, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: SetAutoTimeWithNoPermission001
* @tc.desc: Test auto time setting without system application permission
* @tc.precon: Time system ability is available
* @tc.step: 1. Remove system application permissions
*           2. Call SetAutoTime to enable auto time
*           3. Verify operation returns permission error
* @tc.expect: SetAutoTime returns E_TIME_NOT_SYSTEM_APP without proper permissions
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SetAutoTimeWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->SetAutoTime(true);
    EXPECT_EQ(res, E_TIME_NOT_SYSTEM_APP);
}

/**
* @tc.name: SetAutoTimeWithNoPermission002
* @tc.desc: Test auto time setting with HAP token but insufficient permissions
* @tc.precon: Time system ability is available, access token kit works
* @tc.step: 1. Remove system application permissions
*           2. Allocate HAP token with insufficient permissions
*           3. Set self token ID to allocated token
*           4. Call SetAutoTime to enable auto time
*           5. Verify operation returns permission error
* @tc.expect: SetAutoTime returns E_TIME_NO_PERMISSION with insufficient HAP token permissions
* @tc.type: FUNC
* @tc.require: issue#842
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, SetAutoTimeWithNoPermission002, TestSize.Level0)
{
    DeletePermission();
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyC);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    auto res = TimeSystemAbility::GetInstance()->SetAutoTime(true);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

} // namespace