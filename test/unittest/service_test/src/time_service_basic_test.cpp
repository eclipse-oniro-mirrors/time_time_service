/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include <sys/stat.h>
#include <atomic>
#include <thread>
#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "time_common.h"
#include "timer_info_test.h"
#include "token_setproc.h"
#include "want_agent.h"
#include "timer_call_back.h"
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

namespace OHOS {
namespace MiscServices {
namespace TimeTest {

using namespace std::chrono;
using namespace OHOS::Security::AccessToken;
using namespace testing::ext;

constexpr int64_t MINUTE_TO_MILLISECOND = 60000;
constexpr int64_t ONE_DAY = 86400000;
constexpr int64_t ONE_HOUR = 3600000;
constexpr int64_t ONE_SECOND = 1000;

// Timer types
constexpr int TIMER_TYPE_REALTIME = 1;
constexpr int TIMER_TYPE_WAKEUP = 2;
constexpr int TIMER_TYPE_EXACT = 4;
constexpr int TIMER_TYPE_IDLE = 8;
constexpr int TIMER_TYPE_COMBINED_WAKEUP_EXACT = TIMER_TYPE_WAKEUP | TIMER_TYPE_EXACT;

// Timer intervals (milliseconds)
constexpr uint32_t INTERVAL_100_MS = 100;
constexpr uint32_t INTERVAL_200_MS = 200;
constexpr uint32_t INTERVAL_500_MS = 500;
constexpr uint32_t INTERVAL_1000_MS = 1000;
constexpr uint32_t INTERVAL_2000_MS = 2000;
constexpr uint32_t INTERVAL_5000_MS = 5000;
constexpr uint32_t INTERVAL_10000_MS = 10000;
constexpr uint32_t INTERVAL_30000_MS = 30000;
constexpr uint32_t INTERVAL_60000_MS = 60000;
constexpr uint32_t INTERVAL_300000_MS = 300000;
constexpr uint32_t INTERVAL_600000_MS = 600000;
constexpr uint32_t INTERVAL_120000_MS = 120000;
constexpr int64_t TRIGGER_TIME_OFFSET_60S = 60000;

// Loop counts
constexpr int LOOP_COUNT_SMALL = 10;
constexpr int LOOP_COUNT_MEDIUM = 20;
constexpr int LOOP_COUNT_LARGE = 50;
constexpr int LOOP_COUNT_XLARGE = 100;
constexpr int LOOP_COUNT_XXLARGE = 200;
constexpr int LOOP_COUNT_MAX = 500;
constexpr int LOOP_COUNT_EXTREME = 1000;
constexpr int LOOP_COUNT_BATCH_SMALL = 30;
constexpr int LOOP_COUNT_BATCH_MEDIUM = 50;
constexpr int LOOP_COUNT_BATCH_LARGE = 100;
constexpr int LOOP_COUNT_BATCH_XLARGE = 500;
constexpr int LOOP_COUNT_BATCH_MAX = 5000;
constexpr int LOOP_COUNT_BATCH_EXTREME = 50000;
constexpr int LOOP_COUNT_STABILITY = 5000;
constexpr int LOOP_COUNT_TIME_QUERY = 10000;
constexpr int TIMER_TYPE_ITERATIONS = 7;

// Thread counts
constexpr int THREAD_COUNT_SMALL = 4;
constexpr int THREAD_COUNT_MEDIUM = 8;
constexpr int THREAD_COUNT_LARGE = 10;

// Success thresholds
constexpr int SUCCESS_THRESHOLD_80 = 80;
constexpr int SUCCESS_THRESHOLD_90 = 90;
constexpr int SUCCESS_COUNT_80 = 80;
constexpr int SUCCESS_COUNT_ALL = 1000;
constexpr int SUCCESS_COUNT_BATCH = 200;

// Time values
constexpr int64_t TIME_VALUE_ZERO = 0;
constexpr int64_t TIME_VALUE_LARGE = 4102444800000;
constexpr int64_t TIME_VALUE_INVALID = 999999;
constexpr int TIMEZONE_SWITCH_ALTERNATE = 2;
constexpr int TIMEZONE_SWITCH_CYCLE = 3;
constexpr int TIMER_CREATE_BATCH = 10;
constexpr int TIMER_CREATE_DIVISOR = 2;

// Timezone name lengths
constexpr int TIMEZONE_NAME_MAX_LENGTH = 200;

// Sleep durations (milliseconds)
constexpr int SLEEP_DURATION_SHORT_MS = 10;


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

static HapPolicyParams g_policyB = { .apl = APL_NORMAL, .domain = "test.domain" };

static HapInfoParams g_systemInfoParams = {
    .userID = 1,
    .bundleName = "timer",
    .instIndex = 0,
    .appIDDesc = "test",
    .apiVersion = 8,
    .isSystemApp = true
};

inline void AddPermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

// ==================== Timer Basic Tests ====================

class TimeServiceTimerBasicTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: TimerCreateDestroy001
 * @tc.desc: Test basic timer creation and destruction
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerCreateDestroy001, TestSize.Level0)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->DestroyTimer(timerId));
    }
}

/**
 * @tc.name: TimerCreateDestroy002
 * @tc.desc: Test timer with different types
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerCreateDestroy002, TestSize.Level0)
{
    AddPermission();
    for (int type = TIMER_TYPE_REALTIME; type <= TIMER_TYPE_EXACT; type++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(type);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        EXPECT_NE(timerId, 0) << "Failed for type: " << type;
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

/**
 * @tc.name: TimerCreateDestroy003
 * @tc.desc: Test timer with repeat flag
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerCreateDestroy003, TestSize.Level0)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(INTERVAL_1000_MS);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: TimerStartStop001
 * @tc.desc: Test timer start and stop operations
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerStartStop001, TestSize.Level0)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + TRIGGER_TIME_OFFSET_60S;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime));
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StopTimer(timerId));
    EXPECT_TRUE(TimeServiceClient::GetInstance()->DestroyTimer(timerId));
}

/**
 * @tc.name: TimerStartStop002
 * @tc.desc: Test timer start with different trigger times
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerStartStop002, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t baseTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t intervals[] = {INTERVAL_1000_MS, INTERVAL_60000_MS, INTERVAL_300000_MS, INTERVAL_600000_MS};
    for (auto interval : intervals) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->StartTimer(timerId, baseTime + interval));
        EXPECT_TRUE(TimeServiceClient::GetInstance()->StopTimer(timerId));
    }
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

/**
 * @tc.name: TimerTypeVariations001
 * @tc.desc: Test timer creation with all valid type combinations
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerTypeVariations001, TestSize.Level1)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    for (int type = TIMER_TYPE_REALTIME; type <= TIMER_TYPE_ITERATIONS; type++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(type);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        EXPECT_NE(timerId, 0) << "Failed to create timer with type: " << type;
        if (timerId != 0) timerIds.push_back(timerId);
    }
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

/**
 * @tc.name: TimerRepeatIntervals001
 * @tc.desc: Test timer with various repeat intervals
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerRepeatIntervals001, TestSize.Level1)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    uint32_t intervals[] = {
        INTERVAL_1000_MS, INTERVAL_2000_MS, INTERVAL_5000_MS,
        INTERVAL_10000_MS, INTERVAL_30000_MS, INTERVAL_60000_MS
    };
    for (auto interval : intervals) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        timerInfo->SetRepeat(true);
        timerInfo->SetInterval(interval);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        EXPECT_NE(timerId, 0) << "Failed with interval: " << interval;
        if (timerId != 0) timerIds.push_back(timerId);
    }
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

/**
 * @tc.name: TimerRapidCreateDestroy001
 * @tc.desc: Test rapid timer creation and destruction cycles
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerRapidCreateDestroy001, TestSize.Level1)
{
    AddPermission();
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        EXPECT_NE(timerId, 0);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

/**
 * @tc.name: TimerAlternatingOperations001
 * @tc.desc: Test alternating start/stop operations
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerAlternatingOperations001, TestSize.Level2)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + TRIGGER_TIME_OFFSET_60S;
    for (int i = 0; i < LOOP_COUNT_MEDIUM; i++) {
        TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime + i * INTERVAL_1000_MS);
        TimeServiceClient::GetInstance()->StopTimer(timerId);
    }
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

/**
 * @tc.name: TimerMassCreation001
 * @tc.desc: Test creating large number of timers
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimerBasicTest, TimerMassCreation001, TestSize.Level2)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    for (int i = 0; i < LOOP_COUNT_XLARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME + (i % TIMER_TYPE_ITERATIONS));
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) timerIds.push_back(timerId);
    }
    EXPECT_GE(timerIds.size(), SUCCESS_THRESHOLD_90);
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

// ==================== Timer Advanced Tests ====================

class TimeServiceTimerAdvancedTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: TimerLifecycle001
 * @tc.desc: Complete timer lifecycle test
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerLifecycle001, TestSize.Level0)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + TRIGGER_TIME_OFFSET_60S;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime));
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StopTimer(timerId));
    EXPECT_TRUE(TimeServiceClient::GetInstance()->DestroyTimer(timerId));
}

/**
 * @tc.name: TimerMultipleTypes001
 * @tc.desc: Test creating multiple timers with different types
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerMultipleTypes001, TestSize.Level1)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    for (int type = TIMER_TYPE_REALTIME; type <= TIMER_TYPE_ITERATIONS; type++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(type);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            timerIds.push_back(timerId);
            int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + 60000;
            TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime);
        }
    }
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->StopTimer(id);
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

/**
 * @tc.name: TimerOperationsSequence001
 * @tc.desc: Test various operation sequences
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerOperationsSequence001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + TRIGGER_TIME_OFFSET_60S;
    TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime);
    TimeServiceClient::GetInstance()->StopTimer(timerId);
    triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + 120000;
    TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime);
    TimeServiceClient::GetInstance()->StopTimer(timerId);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

/**
 * @tc.name: TimerRepeatOperations001
 * @tc.desc: Test repeating timer operations
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerRepeatOperations001, TestSize.Level1)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    uint32_t intervals[] = {
        INTERVAL_1000_MS, INTERVAL_2000_MS, INTERVAL_5000_MS, INTERVAL_10000_MS
    };
    for (auto interval : intervals) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        timerInfo->SetRepeat(true);
        timerInfo->SetInterval(interval);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) timerIds.push_back(timerId);
    }
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + 60000;
    for (size_t i = 0; i < timerIds.size(); i++) {
        TimeServiceClient::GetInstance()->StartTimer(timerIds[i], triggerTime + i * INTERVAL_1000_MS);
    }
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->StopTimer(id);
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

/**
 * @tc.name: TimerBulkOperations001
 * @tc.desc: Test bulk timer operations
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerBulkOperations001, TestSize.Level1)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) timerIds.push_back(timerId);
    }
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + 60000;
    for (size_t i = 0; i < timerIds.size(); i++) {
        TimeServiceClient::GetInstance()->StartTimer(timerIds[i], triggerTime + i * INTERVAL_100_MS);
    }
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->StopTimer(id);
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

/**
 * @tc.name: TimerRapidLifecycle001
 * @tc.desc: Test rapid timer lifecycle operations
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerRapidLifecycle001, TestSize.Level2)
{
    AddPermission();
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + 60000;
            TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime);
            TimeServiceClient::GetInstance()->StopTimer(timerId);
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

/**
 * @tc.name: TimerCreateDestroyStress001
 * @tc.desc: Stress test for timer creation/destruction
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimerAdvancedTest, TimerCreateDestroyStress001, TestSize.Level2)
{
    AddPermission();
    for (int i = 0; i < LOOP_COUNT_XLARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

// ==================== Timezone Tests ====================

class TimeServiceTimezoneBasicTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: TimezoneSetGet001
 * @tc.desc: Test basic timezone set and get
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneSetGet001, TestSize.Level0)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone("Asia/Shanghai"));
    EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), "Asia/Shanghai");
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneSetGet002
 * @tc.desc: Test setting UTC timezone
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneSetGet002, TestSize.Level0)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone("Etc/UTC"));
    EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), "Etc/UTC");
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneSwitchMultiple001
 * @tc.desc: Test switching between multiple timezones
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneSwitchMultiple001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {"Asia/Shanghai", "America/New_York", "Europe/London", "Asia/Tokyo", "Australia/Sydney"};
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneAsiaCities001
 * @tc.desc: Test Asia timezone cities
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneAsiaCities001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {"Asia/Shanghai", "Asia/Tokyo", "Asia/Singapore", "Asia/Hong_Kong", "Asia/Bangkok"};
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneEuropeCities001
 * @tc.desc: Test Europe timezone cities
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneEuropeCities001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {
        "Europe/London", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
        "Europe/Rome", "Europe/Madrid", "Europe/Amsterdam"
    };
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneAmericasCities001
 * @tc.desc: Test Americas timezone cities
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneAmericasCities001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {
        "America/New_York", "America/Los_Angeles", "America/Chicago",
        "America/Toronto", "America/Vancouver", "America/Sao_Paulo"
    };
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezonePacificCities001
 * @tc.desc: Test Pacific timezone cities
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezonePacificCities001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {"Australia/Sydney", "Pacific/Auckland", "Pacific/Honolulu", "Pacific/Fiji"};
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneAfricaCities001
 * @tc.desc: Test Africa timezone cities
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneAfricaCities001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {"Africa/Cairo", "Africa/Johannesburg", "Africa/Lagos", "Africa/Nairobi"};
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneRapidSwitch001
 * @tc.desc: Test rapid timezone switching
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneRapidSwitch001, TestSize.Level2)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {"Asia/Shanghai", "America/New_York", "Europe/London"};
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        TimeServiceClient::GetInstance()->SetTimeZone(zones[i % TIMEZONE_SWITCH_CYCLE]);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: TimezoneSameZoneRepeated001
 * @tc.desc: Test setting same timezone repeatedly
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimezoneBasicTest, TimezoneSameZoneRepeated001, TestSize.Level2)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    for (int i = 0; i < LOOP_COUNT_MEDIUM; i++) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone("Asia/Shanghai"));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), "Asia/Shanghai");
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

// ==================== Performance Tests ====================

class TimeServicePerformanceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: PerformanceTimeQuery001
 * @tc.desc: Performance test for time queries
 * @tc.type: PERF
 * @tc.level: level2
 */
HWTEST_F(TimeServicePerformanceTest, PerformanceTimeQuery001, TestSize.Level2)
{
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < LOOP_COUNT_TIME_QUERY; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 5000);
}

/**
 * @tc.name: PerformanceMixedOperations001
 * @tc.desc: Performance test for mixed operations
 * @tc.type: PERF
 * @tc.level: level2
 */
HWTEST_F(TimeServicePerformanceTest, PerformanceMixedOperations001, TestSize.Level2)
{
    AddPermission();
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < LOOP_COUNT_XLARGE; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
        TimeServiceClient::GetInstance()->GetBootTimeMs();
        TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 5000);
}

/**
 * @tc.name: PerformanceTimerCreation001
 * @tc.desc: Performance test for timer creation
 * @tc.type: PERF
 * @tc.level: level2
 */
HWTEST_F(TimeServicePerformanceTest, PerformanceTimerCreation001, TestSize.Level2)
{
    AddPermission();
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < LOOP_COUNT_XLARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 5000);
}

/**
 * @tc.name: PerformanceTimezoneSwitching001
 * @tc.desc: Performance test for timezone switching
 * @tc.type: PERF
 * @tc.level: level2
 */
HWTEST_F(TimeServicePerformanceTest, PerformanceTimezoneSwitching001, TestSize.Level2)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        std::string zone = (i % TIMEZONE_SWITCH_ALTERNATE == 0) ? "Asia/Shanghai" : "America/New_York";
        TimeServiceClient::GetInstance()->SetTimeZone(zone);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 30000);
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: PerformanceTimeQueryBatch001
 * @tc.desc: Batch time query performance test
 * @tc.type: PERF
 * @tc.level: level2
 */
HWTEST_F(TimeServicePerformanceTest, PerformanceTimeQueryBatch001, TestSize.Level2)
{
    std::vector<int64_t> times;
    times.reserve(1000);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < LOOP_COUNT_EXTREME; i++) {
        times.push_back(TimeServiceClient::GetInstance()->GetWallTimeMs());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 5000);
    EXPECT_EQ(times.size(), LOOP_COUNT_EXTREME);
}

/**
 * @tc.name: PerformanceComprehensive001
 * @tc.desc: Comprehensive performance test
 * @tc.type: PERF
 * @tc.level: level2
 */
HWTEST_F(TimeServicePerformanceTest, PerformanceComprehensive001, TestSize.Level2)
{
    AddPermission();
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        std::string zone = (i % TIMEZONE_SWITCH_ALTERNATE == 0) ? "Asia/Shanghai" : "Etc/UTC";
        TimeServiceClient::GetInstance()->SetTimeZone(zone);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    EXPECT_LT(duration.count(), 30000);
}

// ==================== Concurrent Tests ====================

class TimeServiceConcurrentTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

static void CreateTimerBatchTask(std::atomic<int>& successCount)
{
    for (int j = 0; j < TIMER_CREATE_BATCH; j++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            successCount++;
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

/**
 * @tc.name: ConcurrentTimerCreation001
 * @tc.desc: Concurrent timer creation from multiple threads
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceConcurrentTest, ConcurrentTimerCreation001, TestSize.Level3)
{
    AddPermission();
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    for (int i = 0; i < THREAD_COUNT_MEDIUM; i++) {
        threads.emplace_back(CreateTimerBatchTask, std::ref(successCount));
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(successCount.load(), SUCCESS_COUNT_80);
}

/**
 * @tc.name: ConcurrentTimezoneSwitching001
 * @tc.desc: Concurrent timezone switching from multiple threads
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceConcurrentTest, ConcurrentTimezoneSwitching001, TestSize.Level3)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::vector<std::thread> threads;
    for (int i = 0; i < THREAD_COUNT_SMALL; i++) {
        threads.emplace_back([i]() {
            for (int j = 0; j < LOOP_COUNT_BATCH_SMALL; j++) {
                std::string zone = (i % TIMEZONE_SWITCH_ALTERNATE == 0) ? "Asia/Shanghai" : "Etc/UTC";
                TimeServiceClient::GetInstance()->SetTimeZone(zone);
            }
        });
    }
    for (auto& t : threads) t.join();
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

static void MixedOperationsTask(std::atomic<int>& queryCount, std::atomic<int>& timerCount)
{
    for (int j = 0; j < LOOP_COUNT_LARGE; j++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
        queryCount++;
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            timerCount++;
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

/**
 * @tc.name: ConcurrentMixedOperations001
 * @tc.desc: Concurrent mixed operations from multiple threads
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceConcurrentTest, ConcurrentMixedOperations001, TestSize.Level3)
{
    AddPermission();
    std::vector<std::thread> threads;
    std::atomic<int> queryCount{0};
    std::atomic<int> timerCount{0};
    for (int i = 0; i < THREAD_COUNT_SMALL; i++) {
        threads.emplace_back(MixedOperationsTask, std::ref(queryCount), std::ref(timerCount));
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(queryCount.load(), SUCCESS_COUNT_BATCH);
}

static void TimeQueryBatchTask(std::atomic<int>& successCount)
{
    for (int j = 0; j < LOOP_COUNT_XLARGE; j++) {
        int64_t time = TimeServiceClient::GetInstance()->GetWallTimeMs();
        if (time > TIME_VALUE_ZERO) {
            successCount++;
        }
    }
}

/**
 * @tc.name: ConcurrentTimeQuery001
 * @tc.desc: Concurrent time queries from multiple threads
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceConcurrentTest, ConcurrentTimeQuery001, TestSize.Level2)
{
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    for (int i = 0; i < THREAD_COUNT_LARGE; i++) {
        threads.emplace_back(TimeQueryBatchTask, std::ref(successCount));
    }
    for (auto& t : threads) {
        t.join();
    }
    EXPECT_EQ(successCount.load(), SUCCESS_COUNT_ALL);
}

// ==================== Edge Case Tests ====================

class TimeServiceEdgeCaseTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: EdgeCaseInvalidTimerId001
 * @tc.desc: Test operations with invalid timer ID
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseInvalidTimerId001, TestSize.Level1)
{
    AddPermission();
    EXPECT_FALSE(TimeServiceClient::GetInstance()->StartTimer(TIME_VALUE_INVALID, INTERVAL_1000_MS));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->StopTimer(999999));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->DestroyTimer(999999));
}

/**
 * @tc.name: EdgeCaseZeroTimerId001
 * @tc.desc: Test operations with zero timer ID
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseZeroTimerId001, TestSize.Level1)
{
    AddPermission();
    EXPECT_FALSE(TimeServiceClient::GetInstance()->StartTimer(TIME_VALUE_ZERO, INTERVAL_1000_MS));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->StopTimer(0));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->DestroyTimer(0));
}

/**
 * @tc.name: EdgeCaseMaxTimerId001
 * @tc.desc: Test operations with max timer ID
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseMaxTimerId001, TestSize.Level1)
{
    AddPermission();
    EXPECT_FALSE(TimeServiceClient::GetInstance()->StartTimer(ULONG_MAX, 1000));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->StopTimer(ULONG_MAX));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->DestroyTimer(ULONG_MAX));
}

/**
 * @tc.name: EdgeCaseEmptyTimezone001
 * @tc.desc: Test setting empty timezone
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseEmptyTimezone001, TestSize.Level1)
{
    AddPermission();
    EXPECT_FALSE(TimeServiceClient::GetInstance()->SetTimeZone(""));
}

/**
 * @tc.name: EdgeCaseInvalidTimezone001
 * @tc.desc: Test setting invalid timezone
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseInvalidTimezone001, TestSize.Level1)
{
    AddPermission();
    EXPECT_FALSE(TimeServiceClient::GetInstance()->SetTimeZone("Invalid/Zone"));
}

/**
 * @tc.name: EdgeCaseSpecialCharactersTimezone001
 * @tc.desc: Test timezone with special characters
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseSpecialCharactersTimezone001, TestSize.Level1)
{
    AddPermission();
    EXPECT_FALSE(TimeServiceClient::GetInstance()->SetTimeZone("Asia@Shanghai"));
    EXPECT_FALSE(TimeServiceClient::GetInstance()->SetTimeZone("America#NewYork"));
}

/**
 * @tc.name: EdgeCaseLongTimezoneName001
 * @tc.desc: Test very long timezone name
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseLongTimezoneName001, TestSize.Level1)
{
    AddPermission();
    std::string longName(TIMEZONE_NAME_MAX_LENGTH, 'A');
    EXPECT_FALSE(TimeServiceClient::GetInstance()->SetTimeZone(longName));
}

/**
 * @tc.name: EdgeCaseLargeTriggerTime001
 * @tc.desc: Test timer with large trigger time
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCaseLargeTriggerTime001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StartTimer(timerId, LLONG_MAX));
    TimeServiceClient::GetInstance()->StopTimer(timerId);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

/**
 * @tc.name: EdgeCasePastTriggerTime001
 * @tc.desc: Test timer with past trigger time
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceEdgeCaseTest, EdgeCasePastTriggerTime001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t pastTime = TimeServiceClient::GetInstance()->GetWallTimeMs() - INTERVAL_60000_MS;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StartTimer(timerId, pastTime));
    TimeServiceClient::GetInstance()->StopTimer(timerId);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

// ==================== Stability Tests ====================

class TimeServiceStabilityTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: StabilityTimerCreateDestroy001
 * @tc.desc: Stability test for timer creation/destruction
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceStabilityTest, StabilityTimerCreateDestroy001, TestSize.Level3)
{
    AddPermission();
    for (int round = 0; round < TIMER_CREATE_BATCH; round++) {
        std::vector<uint64_t> timerIds;
        for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
            auto timerInfo = std::make_shared<TimerInfoTest>();
            timerInfo->SetType(TIMER_TYPE_REALTIME);
            uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
            if (timerId != 0) timerIds.push_back(timerId);
        }
        for (auto id : timerIds) {
            TimeServiceClient::GetInstance()->DestroyTimer(id);
        }
    }
}

/**
 * @tc.name: StabilityTimezoneSwitching001
 * @tc.desc: Stability test for timezone switching
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceStabilityTest, StabilityTimezoneSwitching001, TestSize.Level3)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zones[] = {"Asia/Shanghai", "America/New_York", "Europe/London", "Etc/UTC"};
    for (int round = 0; round < LOOP_COUNT_SMALL; round++) {
        for (const auto& zone : zones) {
            TimeServiceClient::GetInstance()->SetTimeZone(zone);
        }
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: StabilityMixedOperations001
 * @tc.desc: Stability test for mixed operations
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceStabilityTest, StabilityMixedOperations001, TestSize.Level3)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
        std::string zone = (i % TIMEZONE_SWITCH_ALTERNATE == 0) ? "Asia/Shanghai" : "Etc/UTC";
        TimeServiceClient::GetInstance()->SetTimeZone(zone);
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: StabilityTimerStartStop001
 * @tc.desc: Stability test for timer start/stop
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceStabilityTest, StabilityTimerStartStop001, TestSize.Level3)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t baseTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    for (int i = 0; i < LOOP_COUNT_LARGE; i++) {
        int64_t triggerTime = baseTime + INTERVAL_60000_MS + i * INTERVAL_1000_MS;
        TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime);
        TimeServiceClient::GetInstance()->StopTimer(timerId);
    }
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
}

/**
 * @tc.name: StabilityTimeQuery001
 * @tc.desc: Stability test for time queries
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceStabilityTest, StabilityTimeQuery001, TestSize.Level2)
{
    for (int i = 0; i < LOOP_COUNT_STABILITY; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
        TimeServiceClient::GetInstance()->GetBootTimeMs();
        TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    }
}

// ==================== Resource Management Tests ====================

class TimeServiceResourceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ResourceTimerCleanup001
 * @tc.desc: Test timer resource cleanup
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceResourceTest, ResourceTimerCleanup001, TestSize.Level1)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    for (int i = 0; i < LOOP_COUNT_XLARGE; i++) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        if (timerId != 0) timerIds.push_back(timerId);
    }
    size_t created = timerIds.size();
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
    EXPECT_GE(created, SUCCESS_THRESHOLD_90);
}

/**
 * @tc.name: ResourceMultipleCleanup001
 * @tc.desc: Test multiple cleanup operations
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceResourceTest, ResourceMultipleCleanup001, TestSize.Level2)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_FALSE(TimeServiceClient::GetInstance()->DestroyTimer(timerId));
}

/**
 * @tc.name: ResourceMemoryPressure001
 * @tc.desc: Test under memory pressure simulation
 * @tc.type: FUNC
 * @tc.level: level3
 */
HWTEST_F(TimeServiceResourceTest, ResourceMemoryPressure001, TestSize.Level3)
{
    AddPermission();
    std::vector<uint64_t> timerIds;
    for (int batch = 0; batch < TIMER_CREATE_BATCH; batch++) {
        for (int i = 0; i < LOOP_COUNT_BATCH_SMALL; i++) {
            auto timerInfo = std::make_shared<TimerInfoTest>();
            timerInfo->SetType(TIMER_TYPE_REALTIME);
            uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
            if (timerId != 0) timerIds.push_back(timerId);
        }
        for (size_t i = 0; i < timerIds.size() / TIMER_CREATE_DIVISOR; i++) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerIds[i]);
        }
        timerIds.erase(timerIds.begin(), timerIds.begin() + timerIds.size() / TIMER_CREATE_DIVISOR);
    }
    for (auto id : timerIds) {
        TimeServiceClient::GetInstance()->DestroyTimer(id);
    }
}

// ==================== Extended Timer Type Tests ====================

class TimeServiceTimerTypeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: TimerTypeRealtime001
 * @tc.desc: Test timer with REALTIME type
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerTypeTest, TimerTypeRealtime001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: TimerTypeWakeup001
 * @tc.desc: Test timer with WAKEUP type
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerTypeTest, TimerTypeWakeup001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_WAKEUP);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: TimerTypeExact001
 * @tc.desc: Test timer with EXACT type
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerTypeTest, TimerTypeExact001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_EXACT);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: TimerTypeIdle001
 * @tc.desc: Test timer with IDLE type
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerTypeTest, TimerTypeIdle001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_IDLE);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: TimerTypeCombination001
 * @tc.desc: Test timer with combined types
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceTimerTypeTest, TimerTypeCombination001, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_COMBINED_WAKEUP_EXACT);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: TimerTypeAllCombinations001
 * @tc.desc: Test all timer type combinations
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceTimerTypeTest, TimerTypeAllCombinations001, TestSize.Level2)
{
    AddPermission();
    int timerTypes[] = {
        TIMER_TYPE_REALTIME,
        TIMER_TYPE_WAKEUP,
        TIMER_TYPE_EXACT,
        TIMER_TYPE_REALTIME | TIMER_TYPE_WAKEUP,
        TIMER_TYPE_REALTIME | TIMER_TYPE_EXACT,
        TIMER_TYPE_COMBINED_WAKEUP_EXACT,
    };
    for (auto type : timerTypes) {
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(type);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        EXPECT_NE(timerId, 0);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
}

// ==================== Integration Tests ====================

class TimeServiceIntegrationTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: IntegrationTimeOperations001
 * @tc.desc: Integration test for time operations
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceIntegrationTest, IntegrationTimeOperations001, TestSize.Level0)
{
    int64_t wallTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t bootTime = TimeServiceClient::GetInstance()->GetBootTimeMs();
    int64_t monoTime = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_GT(wallTime, 0);
    EXPECT_GE(bootTime, 0);
    EXPECT_GT(monoTime, 0);
}

/**
 * @tc.name: IntegrationTimezoneOperations001
 * @tc.desc: Integration test for timezone operations
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceIntegrationTest, IntegrationTimezoneOperations001, TestSize.Level0)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone("Asia/Shanghai"));
    EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), "Asia/Shanghai");
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone("Etc/UTC"));
    EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), "Etc/UTC");
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: IntegrationTimerOperations001
 * @tc.desc: Integration test for timer operations
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceIntegrationTest, IntegrationTimerOperations001, TestSize.Level0)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    ASSERT_NE(timerId, 0);
    int64_t triggerTime = TimeServiceClient::GetInstance()->GetWallTimeMs() + TRIGGER_TIME_OFFSET_60S;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StartTimer(timerId, triggerTime));
    EXPECT_TRUE(TimeServiceClient::GetInstance()->StopTimer(timerId));
    EXPECT_TRUE(TimeServiceClient::GetInstance()->DestroyTimer(timerId));
}

/**
 * @tc.name: IntegrationMixedWorkload001
 * @tc.desc: Integration test with mixed workload
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceIntegrationTest, IntegrationMixedWorkload001, TestSize.Level0)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    for (int i = 0; i < LOOP_COUNT_MEDIUM; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
        auto timerInfo = std::make_shared<TimerInfoTest>();
        timerInfo->SetType(TIMER_TYPE_REALTIME);
        uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
        std::string zone = (i % TIMEZONE_SWITCH_ALTERNATE == 0) ? "Asia/Shanghai" : "Etc/UTC";
        TimeServiceClient::GetInstance()->SetTimeZone(zone);
        if (timerId != 0) {
            TimeServiceClient::GetInstance()->DestroyTimer(timerId);
        }
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: IntegrationSystemValidation001
 * @tc.desc: System validation integration test
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceIntegrationTest, IntegrationSystemValidation001, TestSize.Level0)
{
    AddPermission();
    EXPECT_GT(TimeServiceClient::GetInstance()->GetWallTimeMs(), TIME_VALUE_ZERO);
    EXPECT_GE(TimeServiceClient::GetInstance()->GetBootTimeMs(), TIME_VALUE_ZERO);
    EXPECT_GT(TimeServiceClient::GetInstance()->GetMonotonicTimeMs(), TIME_VALUE_ZERO);
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(TIMER_TYPE_REALTIME);
    uint64_t timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_NE(timerId, 0);
    if (timerId != 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

/**
 * @tc.name: IntegrationFinalValidation001
 * @tc.desc: Final validation integration test
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceIntegrationTest, IntegrationFinalValidation001, TestSize.Level0)
{
    std::string zone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(zone.empty());
    EXPECT_GT(TimeServiceClient::GetInstance()->GetWallTimeMs(), 0);
    EXPECT_GE(TimeServiceClient::GetInstance()->GetBootTimeMs(), 0);
    EXPECT_GT(TimeServiceClient::GetInstance()->GetMonotonicTimeMs(), 0);
}

// ==================== SetTime Tests ====================

class TimeServiceSetTimeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: SetTimeBasic001
 * @tc.desc: Test basic SetTime operation
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeBasic001, TestSize.Level1)
{
    AddPermission();
    int64_t currentTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t newTime = currentTime + ONE_HOUR;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTime(newTime));
    int64_t afterSet = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GE(afterSet, newTime - ONE_SECOND);
    EXPECT_LE(afterSet, newTime + ONE_SECOND * 10);
    TimeServiceClient::GetInstance()->SetTime(currentTime);
}

/**
 * @tc.name: SetTimeFuture001
 * @tc.desc: Test setting time to future
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeFuture001, TestSize.Level1)
{
    AddPermission();
    int64_t currentTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t futureTime = currentTime + ONE_DAY;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTime(futureTime));
    int64_t afterSet = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GE(afterSet, futureTime - ONE_SECOND);
    TimeServiceClient::GetInstance()->SetTime(currentTime);
}

/**
 * @tc.name: SetTimePast001
 * @tc.desc: Test setting time to past
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimePast001, TestSize.Level1)
{
    AddPermission();
    int64_t currentTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t pastTime = currentTime - ONE_HOUR;
    EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTime(pastTime));
    int64_t afterSet = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GE(afterSet, pastTime - ONE_SECOND);
    EXPECT_LE(afterSet, pastTime + ONE_SECOND * 10);
    TimeServiceClient::GetInstance()->SetTime(currentTime);
}

/**
 * @tc.name: SetTimeZero001
 * @tc.desc: Test setting time to zero (epoch)
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeZero001, TestSize.Level2)
{
    AddPermission();
    int64_t currentTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    bool result = TimeServiceClient::GetInstance()->SetTime(TIME_VALUE_ZERO);
    if (result) {
        int64_t afterSet = TimeServiceClient::GetInstance()->GetWallTimeMs();
        EXPECT_GE(afterSet, 0);
        EXPECT_LE(afterSet, MINUTE_TO_MILLISECOND);
    }
    TimeServiceClient::GetInstance()->SetTime(currentTime);
}

/**
 * @tc.name: SetTimeLargeValue001
 * @tc.desc: Test setting time to large value
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeLargeValue001, TestSize.Level2)
{
    AddPermission();
    int64_t currentTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t largeTime = TIME_VALUE_LARGE;
    bool result = TimeServiceClient::GetInstance()->SetTime(largeTime);
    if (result) {
        int64_t afterSet = TimeServiceClient::GetInstance()->GetWallTimeMs();
        EXPECT_GE(afterSet, largeTime - ONE_SECOND);
    }
    TimeServiceClient::GetInstance()->SetTime(currentTime);
}

/**
 * @tc.name: SetTimeRapid001
 * @tc.desc: Test rapid time setting
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeRapid001, TestSize.Level2)
{
    AddPermission();
    int64_t baseTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    for (int i = 0; i < LOOP_COUNT_MEDIUM; i++) {
        int64_t newTime = baseTime + i * MINUTE_TO_MILLISECOND;
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTime(newTime));
    }
    TimeServiceClient::GetInstance()->SetTime(baseTime);
}

/**
 * @tc.name: SetTimeZoneBasic001
 * @tc.desc: Test SetTimeZone with various zones
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeZoneBasic001, TestSize.Level1)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::vector<std::string> zones = {
        "Asia/Shanghai", "America/New_York", "Europe/London",
        "Asia/Tokyo", "Australia/Sydney", "Etc/UTC"
    };
    for (const auto& zone : zones) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
        EXPECT_EQ(TimeServiceClient::GetInstance()->GetTimeZone(), zone);
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

/**
 * @tc.name: SetTimeZoneInvalid001
 * @tc.desc: Test SetTimeZone with invalid zones
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeZoneInvalid001, TestSize.Level1)
{
    AddPermission();
    std::vector<std::string> invalidZones = {
        "", "Invalid", "Not/A/Zone", "Asia", "Test123"
    };
    for (const auto& zone : invalidZones) {
        EXPECT_FALSE(TimeServiceClient::GetInstance()->SetTimeZone(zone));
    }
}

/**
 * @tc.name: SetTimeZoneRapid001
 * @tc.desc: Test rapid timezone switching
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceSetTimeTest, SetTimeZoneRapid001, TestSize.Level2)
{
    AddPermission();
    std::string originalZone = TimeServiceClient::GetInstance()->GetTimeZone();
    std::vector<std::string> zones = {"Asia/Shanghai", "Etc/UTC", "America/New_York"};
    for (int i = 0; i < LOOP_COUNT_BATCH_SMALL; i++) {
        EXPECT_TRUE(TimeServiceClient::GetInstance()->SetTimeZone(zones[i % zones.size()]));
    }
    TimeServiceClient::GetInstance()->SetTimeZone(originalZone);
}

// ==================== GetTime Tests ====================

class TimeServiceGetTimeTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetWallTimeMs001
 * @tc.desc: Test GetWallTimeMs basic functionality
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetWallTimeMs001, TestSize.Level0)
{
    int64_t time1 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GT(time1, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_DURATION_SHORT_MS));
    int64_t time2 = TimeServiceClient::GetInstance()->GetWallTimeMs();
    EXPECT_GT(time2, time1);
}

/**
 * @tc.name: GetWallTimeMsConsistency001
 * @tc.desc: Test GetWallTimeMs consistency
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetWallTimeMsConsistency001, TestSize.Level0)
{
    std::vector<int64_t> times;
    for (int i = 0; i < LOOP_COUNT_XLARGE; i++) {
        times.push_back(TimeServiceClient::GetInstance()->GetWallTimeMs());
    }
    for (size_t i = 1; i < times.size(); i++) {
        EXPECT_GE(times[i], times[i-1]);
        EXPECT_LE(times[i] - times[i-1], INTERVAL_100_MS);
    }
}

/**
 * @tc.name: GetBootTimeMs001
 * @tc.desc: Test GetBootTimeMs basic functionality
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetBootTimeMs001, TestSize.Level0)
{
    int64_t time1 = TimeServiceClient::GetInstance()->GetBootTimeMs();
    EXPECT_GE(time1, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_DURATION_SHORT_MS));
    int64_t time2 = TimeServiceClient::GetInstance()->GetBootTimeMs();
    EXPECT_GE(time2, time1);
}

/**
 * @tc.name: GetMonotonicTimeMs001
 * @tc.desc: Test GetMonotonicTimeMs basic functionality
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetMonotonicTimeMs001, TestSize.Level0)
{
    int64_t time1 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_GT(time1, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_DURATION_SHORT_MS));
    int64_t time2 = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_GT(time2, time1);
}

/**
 * @tc.name: GetThreadTimeMs001
 * @tc.desc: Test GetThreadTimeMs basic functionality
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetThreadTimeMs001, TestSize.Level0)
{
    int64_t time1 = TimeServiceClient::GetInstance()->GetThreadTimeMs();
    EXPECT_GE(time1, 0);
}

/**
 * @tc.name: GetTimeComparison001
 * @tc.desc: Compare different time sources
 * @tc.type: FUNC
 * @tc.level: level1
 */
HWTEST_F(TimeServiceGetTimeTest, GetTimeComparison001, TestSize.Level1)
{
    int64_t wallTime = TimeServiceClient::GetInstance()->GetWallTimeMs();
    int64_t bootTime = TimeServiceClient::GetInstance()->GetBootTimeMs();
    int64_t monoTime = TimeServiceClient::GetInstance()->GetMonotonicTimeMs();
    EXPECT_GT(wallTime, 0);
    EXPECT_GE(bootTime, 0);
    EXPECT_GT(monoTime, 0);
    EXPECT_GT(wallTime, bootTime);
}

/**
 * @tc.name: GetTimeHighFrequency001
 * @tc.desc: Test high frequency time queries
 * @tc.type: FUNC
 * @tc.level: level2
 */
HWTEST_F(TimeServiceGetTimeTest, GetTimeHighFrequency001, TestSize.Level2)
{
    for (int i = 0; i < LOOP_COUNT_BATCH_EXTREME; i++) {
        TimeServiceClient::GetInstance()->GetWallTimeMs();
    }
}

/**
 * @tc.name: GetTimeZoneBasic001
 * @tc.desc: Test GetTimeZone basic functionality
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetTimeZoneBasic001, TestSize.Level0)
{
    std::string zone = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_FALSE(zone.empty());
}

/**
 * @tc.name: GetTimeZoneConsistency001
 * @tc.desc: Test GetTimeZone consistency
 * @tc.type: FUNC
 * @tc.level: level0
 */
HWTEST_F(TimeServiceGetTimeTest, GetTimeZoneConsistency001, TestSize.Level0)
{
    std::string zone1 = TimeServiceClient::GetInstance()->GetTimeZone();
    std::string zone2 = TimeServiceClient::GetInstance()->GetTimeZone();
    EXPECT_EQ(zone1, zone2);
}

} // namespace TimeTest
} // namespace MiscServices
} // namespace OHOS
