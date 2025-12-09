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

const int32_t RESERVED_UID = 99999;
std::set<int> RESERVED_PIDLIST = {1111, 2222};
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NETWORK_TIME_STATUS_ON = "ON";
const std::string AUTO_TIME_STATUS_ON = "ON";
uint64_t g_idleTimerId = 0;
const uint64_t TIMER_ID = 88888;
const uint32_t MAX_EXEMPTION_SIZE = 1000;
const int UID = 999998;
const int PID = 999999;
constexpr int ONE_HUNDRED = 100;
constexpr int FIVE_HUNDRED = 500;
constexpr uint64_t MICRO_TO_MILLISECOND = 1000;
constexpr int TIMER_ALARM_COUNT = 50;
static const int MAX_PID_LIST_SIZE = 1024;
constexpr uint64_t NANO_TO_MILLISECOND = 1000000;
#ifdef SET_AUTO_REBOOT_ENABLE
static const int POWER_ON_ALARM = 6;
constexpr int64_t TEN_YEARS_TO_SECOND = 10 * 365 * 24 * 60 * 60;
constexpr uint64_t SECOND_TO_MILLISECOND = 1000;
constexpr uint64_t TWO_MINUTES_TO_MILLI = 120000;
#endif

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

class TimeServiceTimerTest : public testing::Test {
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

void TimeServiceTimerTest::SetUpTestCase(void)
{
}

void TimeServiceTimerTest::TearDownTestCase(void)
{
}

void TimeServiceTimerTest::SetUp(void)
{
}

void TimeServiceTimerTest::TearDown(void)
{
}

void TimeServiceTimerTest::AddPermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_systemInfoParams, g_policyA);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServiceTimerTest::DeletePermission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(g_notSystemInfoParams, g_policyB);
    SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void TimeServiceTimerTest::StartIdleTimer()
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_IDLE);
    timerInfo->SetRepeat(false);
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, g_idleTimerId);
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    // 5000 means timer triggers after 5s
    TimeServiceClient::GetInstance()->StartTimerV9(g_idleTimerId, time + 5000);
}

void TimeServiceTimerTest::DestroyIdleTimer()
{
    TimeServiceClient::GetInstance()->DestroyTimerV9(g_idleTimerId);
}

/**
 * @brief Check timeId in json table
 * @param tableName the tableName
 * @param timerId the timerId need check
 */
bool CheckInJson(std::string tableName, uint64_t timerId)
{
    bool flag = false;
    cJSON* db1 = NULL;
    cJSON* data1 = CjsonHelper::GetInstance().QueryTable(tableName, &db1);
    if (data1 != NULL) {
        int size = cJSON_GetArraySize(data1);
        for (int i = 0; i < size; ++i) {
            cJSON* obj = cJSON_GetArrayItem(data1, i);

            if (cJSON_GetObjectItem(obj, "timerId")->valuestring == std::to_string(timerId)) {
                flag = true;
                break;
            }
        }
    }
    cJSON_Delete(db1);
    return flag;
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
        usleep(ONE_HUNDRED*MICRO_TO_MILLISECOND);
    }
}

/**
* @tc.name: Batch001
* @tc.desc: Test Batch class default initialization values
* @tc.precon: Batch class is properly implemented
* @tc.step: 1. Create Batch instance with default constructor
*           2. Verify start time is set to minimum time point
*           3. Verify end time is set to maximum time point
*           4. Verify flags are initialized to 0
* @tc.expect: Batch instance is initialized with expected default values
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Batch001, TestSize.Level0)
{
    Batch batch;
    EXPECT_EQ(batch.GetStart(), std::chrono::steady_clock::time_point::min());
    EXPECT_EQ(batch.GetEnd(), std::chrono::steady_clock::time_point::max());
    EXPECT_EQ(batch.GetFlags(), 0);
}

/**
* @tc.name: SystemAbility001
* @tc.desc: Test TimeSystemAbility OnStop functionality
* @tc.precon: TimeSystemAbility is properly initialized and running
* @tc.step: 1. Call OnStop method on TimeSystemAbility instance
*           2. Verify service state transitions to NOT_START state
* @tc.expect: OnStop method successfully stops the service and updates state to NOT_START
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility001, TestSize.Level0)
{
    TimeSystemAbility::GetInstance()->OnStop();
    EXPECT_EQ(TimeSystemAbility::GetInstance()->state_, ServiceRunningState::STATE_NOT_START);
}

#ifdef RDB_ENABLE
/**
* @tc.name: SystemAbility002
* @tc.desc: Test timer recovery functionality from database
* @tc.precon: RDB is enabled, TimeDatabase is properly initialized
* @tc.step: 1. Clean up existing timer entries from timer map
*           2. Insert test timer entries into both HOLD_ON_REBOOT and DROP_ON_REBOOT tables
*           3. Call RecoverTimer method to restore timers
*           4. Verify timer entries are not restored (expected behavior)
*           5. Clean up test data from database
* @tc.expect: RecoverTimer does not restore test timer entries, database operations succeed
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility002, TestSize.Level0)
{
    uint64_t timerId1 = TIMER_ID;
    uint64_t timerId2 = TIMER_ID + 1;

    auto map = TimerManager::GetInstance()->timerEntryMap_;
    auto it = map.find(timerId1);
    if (it != map.end()) {
        map.erase(it);
    }
    it = map.find(timerId2);
    if (it != map.end()) {
        map.erase(it);
    }

    OHOS::NativeRdb::ValuesBucket insertValues1;
    insertValues1.PutLong("timerId", timerId1);
    insertValues1.PutInt("type", 0);
    insertValues1.PutInt("flag", 0);
    insertValues1.PutLong("windowLength", 0);
    insertValues1.PutLong("interval", 0);
    insertValues1.PutInt("uid", 0);
    insertValues1.PutString("bundleName", "");
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    insertValues1.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues1.PutInt("state", 0);
    insertValues1.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues1);

    OHOS::NativeRdb::ValuesBucket insertValues2;
    insertValues2.PutLong("timerId", timerId2);
    insertValues2.PutInt("type", 0);
    insertValues2.PutInt("flag", 0);
    insertValues2.PutLong("windowLength", 0);
    insertValues2.PutLong("interval", 0);
    insertValues2.PutInt("uid", 0);
    insertValues2.PutString("bundleName", "");
    wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    insertValues2.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues2.PutInt("state", 0);
    insertValues2.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(DROP_ON_REBOOT, insertValues2);

    TimeSystemAbility::GetInstance()->RecoverTimer();

    it = map.find(timerId1);
    EXPECT_EQ(it, map.end());
    it = map.find(timerId2);
    EXPECT_EQ(it, map.end());

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete1(HOLD_ON_REBOOT);
    rdbPredicatesDelete1.EqualTo("timerId", static_cast<int64_t>(timerId1));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete1);

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete2(DROP_ON_REBOOT);
    rdbPredicatesDelete2.EqualTo("timerId", static_cast<int64_t>(timerId2));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete2);
}
#endif

/**
* @tc.name: SystemAbility005
* @tc.desc: Test SetRealTime functionality with invalid negative value
* @tc.precon: TimeSystemAbility is properly initialized
* @tc.step: 1. Call SetRealTime method with negative value (-1)
*           2. Verify operation returns false indicating failure
* @tc.expect: SetRealTime returns false for negative time values
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility003, TestSize.Level0)
{
    auto res = TimeSystemAbility::GetInstance()->SetRealTime(-1);
    EXPECT_FALSE(res);
}

#ifdef RDB_ENABLE
/**
* @tc.name: TimeDatabase001
* @tc.desc: Test TimeDatabase Insert functionality with invalid column
* @tc.precon: RDB is enabled, TimeDatabase is properly initialized
* @tc.step: 1. Prepare ValuesBucket with invalid column name "something"
*           2. Call Insert method on DROP_ON_REBOOT table
*           3. Verify operation returns false indicating failure
* @tc.expect: Insert operation fails when using invalid column names
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, TimeDatabase001, TestSize.Level0)
{
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutLong("something", 0);
    auto res = TimeDatabase::GetInstance().Insert(DROP_ON_REBOOT, insertValues);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimeDatabase002
* @tc.desc: Test TimeDatabase Update functionality with invalid predicates
* @tc.precon: RDB is enabled, TimeDatabase is properly initialized
* @tc.step: 1. Prepare ValuesBucket with invalid column name "something"
*           2. Create RdbPredicates with invalid conditions
*           3. Call Update method on DROP_ON_REBOOT table
*           4. Verify operation returns false indicating failure
* @tc.expect: Update operation fails when using invalid column names and predicates
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, TimeDatabase002, TestSize.Level0)
{
    OHOS::NativeRdb::ValuesBucket values;
    values.PutInt("something", 1);
    OHOS::NativeRdb::RdbPredicates rdbPredicates(DROP_ON_REBOOT);
    rdbPredicates.EqualTo("something", 0)->And()->EqualTo("something", static_cast<int64_t>(0));
    auto res = TimeDatabase::GetInstance().Update(values, rdbPredicates);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimeDatabase003
* @tc.desc: Test TimeDatabase Delete functionality with invalid predicates
* @tc.precon: RDB is enabled, TimeDatabase is properly initialized
* @tc.step: 1. Create RdbPredicates with invalid column condition
*           2. Call Delete method on DROP_ON_REBOOT table
*           3. Verify operation returns false indicating failure
* @tc.expect: Delete operation fails when using invalid column names in predicates
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, TimeDatabase003, TestSize.Level0)
{
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(DROP_ON_REBOOT);
    rdbPredicatesDelete.EqualTo("something", static_cast<int64_t>(0));
    auto res = TimeDatabase::GetInstance().Delete(rdbPredicatesDelete);
    EXPECT_FALSE(res);
}
#endif

/**
* @tc.name: Cjson001
* @tc.desc: Test CjsonHelper Delete functionality for timer entries
* @tc.precon: CjsonHelper is properly initialized
* @tc.step: 1. Insert test timer entries into both DROP_ON_REBOOT and HOLD_ON_REBOOT tables
*           2. Verify entries are successfully inserted
*           3. Delete entries from both tables
*           4. Verify entries are successfully removed
* @tc.expect: Timer entries are properly inserted and deleted from JSON storage
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson001, TestSize.Level0)
{
    auto timerId2 = TIMER_ID + 1;

    auto entry1 = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 1, 1, 1, 1, false, nullptr, nullptr, 1, 1, "bundleName1"});
    auto ret = CjsonHelper::GetInstance().Insert(std::string(DROP_ON_REBOOT), entry1);
    EXPECT_TRUE(ret);
    auto entry2 = std::make_shared<TimerEntry>(
            TimerEntry{"", timerId2, 2, 2, 2, 2, true, nullptr, nullptr, 2, 2, "bundleName2"});
    ret = CjsonHelper::GetInstance().Insert(std::string(HOLD_ON_REBOOT), entry2);
    EXPECT_TRUE(ret);

    EXPECT_TRUE(CheckInJson(DROP_ON_REBOOT, TIMER_ID));
    EXPECT_TRUE(CheckInJson(HOLD_ON_REBOOT, timerId2));

    CjsonHelper::GetInstance().Delete(std::string(DROP_ON_REBOOT), TIMER_ID);
    CjsonHelper::GetInstance().Delete(std::string(HOLD_ON_REBOOT), timerId2);

    EXPECT_FALSE(CheckInJson(DROP_ON_REBOOT, TIMER_ID));
    EXPECT_FALSE(CheckInJson(HOLD_ON_REBOOT, timerId2));
}

/**
* @tc.name: Cjson002
* @tc.desc: Test CjsonHelper Clear functionality for entire tables
* @tc.precon: CjsonHelper is properly initialized
* @tc.step: 1. Insert test timer entries into both DROP_ON_REBOOT and HOLD_ON_REBOOT tables
*           2. Verify entries are successfully inserted
*           3. Clear entire contents of both tables
*           4. Verify all entries are successfully removed
* @tc.expect: Entire table contents are properly cleared from JSON storage
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson002, TestSize.Level0)
{
    auto timerId2 = TIMER_ID + 1;

    auto entry1 = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 1, 1, 1, 1, false, nullptr, nullptr, 1, 1, "bundleName1"});
    auto ret = CjsonHelper::GetInstance().Insert(std::string(DROP_ON_REBOOT), entry1);
    EXPECT_TRUE(ret);
    auto entry2 = std::make_shared<TimerEntry>(
            TimerEntry{"", timerId2, 2, 2, 2, 2, true, nullptr, nullptr, 2, 2, "bundleName2"});
    ret = CjsonHelper::GetInstance().Insert(std::string(HOLD_ON_REBOOT), entry2);
    EXPECT_TRUE(ret);

    EXPECT_TRUE(CheckInJson(DROP_ON_REBOOT, TIMER_ID));
    EXPECT_TRUE(CheckInJson(HOLD_ON_REBOOT, timerId2));

    CjsonHelper::GetInstance().Clear(std::string(DROP_ON_REBOOT));
    CjsonHelper::GetInstance().Clear(std::string(HOLD_ON_REBOOT));

    EXPECT_FALSE(CheckInJson(DROP_ON_REBOOT, TIMER_ID));
    EXPECT_FALSE(CheckInJson(HOLD_ON_REBOOT, timerId2));
}

/**
* @tc.name: Cjson003
* @tc.desc: Test CjsonHelper QueryTable and update functionality
* @tc.precon: CjsonHelper is properly initialized
* @tc.step: 1. Insert test timer entry into DROP_ON_REBOOT table
*           2. Update trigger time and verify update
*           3. Update timer state and verify update
*           4. Query table and verify all changes
*           5. Clean up test entry
* @tc.expect: Timer entry updates (trigger time and state) are properly reflected in JSON storage
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson003, TestSize.Level0)
{
    auto triggerTime = 200;
    auto entry1 = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 1, 1, 1, 1, false, nullptr, nullptr, 1, 1, "bundleName1"});
    CjsonHelper::GetInstance().Insert(std::string(DROP_ON_REBOOT), entry1);

    CjsonHelper::GetInstance().UpdateTrigger(std::string(DROP_ON_REBOOT), TIMER_ID, triggerTime);

    bool flag = false;
    cJSON* db1 = NULL;
    cJSON* data1 = CjsonHelper::GetInstance().QueryTable(DROP_ON_REBOOT, &db1);
    if (data1 != NULL) {
        int size = cJSON_GetArraySize(data1);
        for (int i = 0; i < size; ++i) {
            cJSON* obj = cJSON_GetArrayItem(data1, i);

            if (cJSON_GetObjectItem(obj, "timerId")->valuestring == std::to_string(TIMER_ID)) {
                auto state = cJSON_GetObjectItem(obj, "state")->valueint;
                EXPECT_EQ(state, 1);
                string triggerTimeStr = cJSON_GetObjectItem(obj, "triggerTime")->valuestring;
                EXPECT_EQ(triggerTimeStr, std::to_string(triggerTime));
                flag = true;
                break;
            }
        }
    }
    cJSON_Delete(db1);
    EXPECT_TRUE(flag);
    CjsonHelper::GetInstance().UpdateState(std::string(DROP_ON_REBOOT), TIMER_ID);
    flag = false;
    db1 = NULL;
    data1 = CjsonHelper::GetInstance().QueryTable(DROP_ON_REBOOT, &db1);
    if (data1 != NULL) {
        int size = cJSON_GetArraySize(data1);
        for (int i = 0; i < size; ++i) {
            cJSON* obj = cJSON_GetArrayItem(data1, i);

            if (cJSON_GetObjectItem(obj, "timerId")->valuestring == std::to_string(TIMER_ID)) {
                auto state = cJSON_GetObjectItem(obj, "state")->valueint;
                EXPECT_EQ(state, 0);
                flag = true;
                break;
            }
        }
    }
    cJSON_Delete(db1);
    EXPECT_TRUE(flag);

    CjsonHelper::GetInstance().Delete(std::string(DROP_ON_REBOOT), TIMER_ID);
}

/**
* @tc.name: Cjson004
* @tc.desc: Test CjsonHelper QueryWant functionality
* @tc.precon: CjsonHelper is properly initialized
* @tc.step: 1. Insert test timer entry with null WantAgent into DROP_ON_REBOOT table
*           2. Query WantAgent string for the timer entry
*           3. Verify empty string is returned for null WantAgent
*           4. Clean up test entry
* @tc.expect: QueryWant returns empty string for timer entries with null WantAgent
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson004, TestSize.Level0)
{
    auto entry1 = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 1, 1, 1, 1, false, nullptr, nullptr, 1, 1, "bundleName1"});
    CjsonHelper::GetInstance().Insert(std::string(DROP_ON_REBOOT), entry1);
    std::string want1 = CjsonHelper::GetInstance().QueryWant(std::string(DROP_ON_REBOOT), TIMER_ID);
    EXPECT_EQ(want1, "");
    CjsonHelper::GetInstance().Delete(std::string(DROP_ON_REBOOT), TIMER_ID);
}

/**
* @tc.name: Cjson005
* @tc.desc: Test CjsonHelper QueryAutoReboot functionality
* @tc.precon: CjsonHelper is properly initialized
* @tc.step: 1. Insert auto reboot timer entry into HOLD_ON_REBOOT table
*           2. Update trigger time for the entry
*           3. Query auto reboot data
*           4. Verify data is returned successfully
*           5. Clean up test entry
* @tc.expect: QueryAutoReboot returns non-empty data for auto reboot timer entries
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson005, TestSize.Level0)
{
    auto entry1 = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 1, 1, 1, 1, true, nullptr, nullptr, 1, 1, "bundleName1"});
    CjsonHelper::GetInstance().Insert(std::string(HOLD_ON_REBOOT), entry1);
    CjsonHelper::GetInstance().UpdateTrigger(std::string(HOLD_ON_REBOOT), TIMER_ID, 200);
    auto data = CjsonHelper::GetInstance().QueryAutoReboot();
    EXPECT_TRUE(data.size() > 0);
    CjsonHelper::GetInstance().Delete(std::string(HOLD_ON_REBOOT), TIMER_ID);
}

/**
* @tc.name: Cjson006
* @tc.desc: Test GetEntry functionality with incomplete JSON objects
* @tc.precon: TimeSystemAbility is properly initialized
* @tc.step: 1. Create empty JSON object and test GetEntry
*           2. Gradually add required fields one by one
*           3. Test GetEntry after each field addition
*           4. Verify GetEntry returns nullptr until all required fields are present
* @tc.expect: GetEntry returns nullptr for incomplete JSON objects, valid object only when all fields are present
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson006, TestSize.Level0)
{
    cJSON* obj = cJSON_CreateObject();
    auto res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddStringToObject(obj, "name", "");
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddStringToObject(obj, "timerId", "timerId");
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON *new_item = cJSON_CreateString(std::to_string(TIMER_ID).c_str());
    cJSON_ReplaceItemInObject(obj, "timerId", new_item);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddNumberToObject(obj, "type", 1);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddNumberToObject(obj, "windowLength", 1);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddNumberToObject(obj, "interval", 1);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddNumberToObject(obj, "flag", 1);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddStringToObject(obj, "wantAgent",
        OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(nullptr).c_str());
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddNumberToObject(obj, "uid", 1);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddNumberToObject(obj, "pid", 1);
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_EQ(res, nullptr);
    cJSON_AddStringToObject(obj, "bundleName", "bundleName1");
    res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_NE(res, nullptr);
    cJSON_Delete(obj);
}

/**
* @tc.name: Cjson007
* @tc.desc: Test GetEntry functionality with complete JSON object
* @tc.precon: TimeSystemAbility is properly initialized
* @tc.step: 1. Create complete JSON object with all required timer fields
*           2. Call GetEntry method with the complete object
*           3. Verify valid TimerEntry is returned
* @tc.expect: GetEntry returns valid TimerEntry pointer for complete JSON objects
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson007, TestSize.Level0)
{
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", "");
    cJSON_AddStringToObject(obj, "timerId", std::to_string(TIMER_ID).c_str());
    cJSON_AddNumberToObject(obj, "type", 1);
    cJSON_AddNumberToObject(obj, "windowLength", 1);
    cJSON_AddNumberToObject(obj, "interval", 1);
    cJSON_AddNumberToObject(obj, "flag", 1);
    cJSON_AddStringToObject(obj, "wantAgent",
        OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(nullptr).c_str());
    cJSON_AddNumberToObject(obj, "uid", 1);
    cJSON_AddNumberToObject(obj, "pid", 1);
    cJSON_AddStringToObject(obj, "bundleName", "bundleName1");
    auto res = TimeSystemAbility::GetInstance()->GetEntry(obj, true);
    EXPECT_NE(res, nullptr);
    cJSON_Delete(obj);
}

/**
* @tc.name: Cjson008
* @tc.desc: Test CjsonIntoDatabase functionality for data migration
* @tc.precon: TimeSystemAbility and TimeDatabase are properly initialized
* @tc.step: 1. Create JSON array with both invalid and valid timer objects
*           2. Call CjsonIntoDatabase to migrate data to RDB
*           3. Verify no data is inserted due to validation checks
* @tc.expect: CjsonIntoDatabase properly validates JSON data and rejects invalid entries
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, Cjson008, TestSize.Level0)
{
    cJSON* resultSet = cJSON_CreateArray();
    cJSON* obj1 = cJSON_CreateObject();
    cJSON_AddItemToArray(resultSet, obj1);
    cJSON* obj2 = cJSON_CreateObject();
    cJSON_AddStringToObject(obj2, "name", "");
    cJSON_AddStringToObject(obj2, "timerId", std::to_string(TIMER_ID).c_str());
    cJSON_AddNumberToObject(obj2, "type", 1);
    cJSON_AddNumberToObject(obj2, "windowLength", 1);
    cJSON_AddNumberToObject(obj2, "interval", 1);
    cJSON_AddNumberToObject(obj2, "flag", 1);
    cJSON_AddStringToObject(obj2, "wantAgent", "");
    cJSON_AddNumberToObject(obj2, "uid", 1);
    cJSON_AddNumberToObject(obj2, "pid", 1);
    cJSON_AddStringToObject(obj2, "bundleName", "bundleName1");
    cJSON_AddItemToArray(resultSet, obj2);
    TimeSystemAbility::GetInstance()->CjsonIntoDatabase(resultSet, true, HOLD_ON_REBOOT);
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(HOLD_ON_REBOOT);
    rdbPredicatesDelete.EqualTo("timerId", static_cast<int64_t>(TIMER_ID));
    int count = 0;
    TimeDatabase::GetInstance().Query(rdbPredicatesDelete, {"timerId"})->GetRowCount(count);
    EXPECT_EQ(count, 0);
    cJSON_Delete(resultSet);
}

/**
* @tc.name: PidProxyTimer001
* @tc.desc: Test PID proxy timer enable and disable functionality
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Enable PID proxy timer with retrigger enabled
*           2. Disable PID proxy timer with retrigger enabled
*           3. Verify both operations succeed
* @tc.expect: PID proxy timer operations succeed for both enable and disable with retrigger
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, PidProxyTimer001, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, false, true);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: PidProxyTimer002
* @tc.desc: Test PID proxy timer reset functionality
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Enable PID proxy timer
*           2. Call ResetAllProxy to clear all proxy settings
*           3. Verify both operations succeed
* @tc.expect: PID proxy timer enable and reset operations succeed
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, PidProxyTimer002, TestSize.Level0)
{
    std::set<int> pidList;
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, true, true);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ResetAllProxy();
    EXPECT_TRUE(ret);
}

/**
* @tc.name: PidProxyTimer003
* @tc.desc: Test PID proxy timer disable without prior enable
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Disable PID proxy timer without prior enable
*           2. Verify operation returns false
* @tc.expect: Disabling non-existent PID proxy returns false
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, PidProxyTimer003, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, false, true);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: PidProxyTimer004
* @tc.desc: Test PID proxy timer without retrigger functionality
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Enable PID proxy timer with retrigger disabled
*           2. Disable PID proxy timer with retrigger disabled
*           3. Verify both operations succeed
* @tc.expect: PID proxy timer operations succeed with retrigger disabled
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, PidProxyTimer004, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, true, false);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, false, false);
    EXPECT_TRUE(ret);
}

/**
* @tc.name: AdjustTimer001
* @tc.desc: Test timer adjustment functionality via TimeServiceClient
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Test adjust timer with 0 interval (should fail)
*           2. Test adjust timer with valid interval (should succeed)
*           3. Test disable timer adjustment with 0 interval (should succeed)
*           4. Test disable timer adjustment with valid interval (should succeed)
* @tc.expect: Timer adjustment operations return appropriate error codes
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, AdjustTimer001, TestSize.Level0)
{
    auto errCode = TimeServiceClient::GetInstance()->AdjustTimer(true, 0, 0);
    EXPECT_EQ(errCode, TimeError::E_TIME_READ_PARCEL_ERROR);
    errCode = TimeServiceClient::GetInstance()->AdjustTimer(true, 1, 0);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->AdjustTimer(false, 0, 0);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->AdjustTimer(false, 1, 0);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: AdjustTimer002
* @tc.desc: Test timer adjustment functionality via TimeSystemAbility
* @tc.precon: TimeSystemAbility is properly initialized
* @tc.step: 1. Test adjust timer with 0 interval (should fail)
*           2. Test adjust timer with valid interval (should succeed)
*           3. Test disable timer adjustment with 0 interval (should succeed)
*           4. Test disable timer adjustment with valid interval (should succeed)
* @tc.expect: Timer adjustment operations return appropriate error codes
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, AdjustTimer002, TestSize.Level1)
{
    auto res = TimeSystemAbility::GetInstance()->AdjustTimer(true, 0, 0);
    EXPECT_EQ(res, TimeError::E_TIME_READ_PARCEL_ERROR);
    res = TimeSystemAbility::GetInstance()->AdjustTimer(true, 1, 0);
    EXPECT_EQ(res, TimeError::E_TIME_OK);
    res = TimeSystemAbility::GetInstance()->AdjustTimer(false, 0, 0);
    EXPECT_EQ(res, TimeError::E_TIME_OK);
    res = TimeSystemAbility::GetInstance()->AdjustTimer(false, 1, 0);
    EXPECT_EQ(res, TimeError::E_TIME_OK);
}

/**
* @tc.name: AdjustTimer003
* @tc.desc: Test timer exemption functionality
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Disable timer exemption for test timer names
*           2. Enable timer exemption for test timer names
*           3. Verify both operations succeed
* @tc.expect: Timer exemption operations succeed for both enable and disable
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, AdjustTimer003, TestSize.Level0)
{
    std::unordered_set<std::string> nameArr{"timer"};
    auto errCode = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
    errCode = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, true);
    EXPECT_EQ(errCode, TimeError::E_TIME_OK);
}

/**
* @tc.name: AdjustTimer004
* @tc.desc: Test timer exemption with oversized name array
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Create name array exceeding maximum exemption size limit
*           2. Call SetTimerExemption with oversized array
*           3. Verify operation returns parameter error
* @tc.expect: SetTimerExemption returns E_TIME_PARAMETERS_INVALID for oversized name arrays
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, AdjustTimer004, TestSize.Level1)
{
    std::unordered_set<std::string> nameArr{"timer"};
    for (int i = 0; i <= MAX_EXEMPTION_SIZE + 1; i++) {
        nameArr.insert("timer" + std::to_string(i));
    }
    auto res = TimeServiceClient::GetInstance()->SetTimerExemption(nameArr, false);
    EXPECT_EQ(res, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: ProxyTimer001
* @tc.desc: Test ProxyTimer parameter validation with oversized PID list
* @tc.precon: TimeSystemAbility is properly initialized
* @tc.step: 1. Create PID list exceeding maximum allowed size
*           2. Call ProxyTimer with oversized PID list
*           3. Verify operation returns parameter error
* @tc.expect: ProxyTimer returns E_TIME_PARAMETERS_INVALID when PID list exceeds MAX_PID_LIST_SIZE
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, ProxyTimer001, TestSize.Level1)
{
    std::vector<int> pidList{};
    for (int i = 0; i <= MAX_PID_LIST_SIZE + 1; i++) {
        pidList.push_back(0);
    }
    auto res = TimeSystemAbility::GetInstance()->ProxyTimer(0, pidList, false, false);
    EXPECT_EQ(res, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: IdleTimer001
* @tc.desc: Test idle timer creation functionality for applications
* @tc.precon: TimeServiceClient is properly initialized
* @tc.step: 1. Create timer info with IDLE type
*           2. Create timer using CreateTimerV9
*           3. Verify timer is created successfully
*           4. Destroy the created timer
* @tc.expect: Idle timer is successfully created and destroyed
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, IdleTimer001, TestSize.Level0)
{
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_IDLE);
    timerInfo->SetRepeat(false);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: IdleTimer002
* @tc.desc: Test timer behavior when device sleep duration exceeds timer callback time
* @tc.precon: TimeServiceClient is properly initialized, idle timer mechanism works
* @tc.step: 1. Create inexact reminder timer with callback
*           2. Start idle timer to simulate device sleep
*           3. Start timer with 500ms delay during device sleep
*           4. Verify timer doesn't trigger during sleep
*           5. Destroy idle timer to wake device
*           6. Wait for timer callback and verify trigger
* @tc.expect: Timer callback is delayed until device wakes from sleep when sleep duration exceeds callback time
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, IdleTimer002, TestSize.Level0)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_INEXACT_REMINDER);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    StartIdleTimer();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time) + FIVE_HUNDRED);
    usleep(FIVE_HUNDRED*MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 0);
    DestroyIdleTimer();
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: IdleTimer003
* @tc.desc: Test timer behavior when device sleep duration is less than timer callback time
* @tc.precon: TimeServiceClient is properly initialized, idle timer mechanism works
* @tc.step: 1. Create inexact reminder timer with callback
*           2. Start idle timer to simulate device sleep
*           3. Start timer with 500ms delay during device sleep
*           4. Verify timer doesn't trigger during sleep
*           5. Destroy idle timer to wake device
*           6. Wait for timer callback and verify trigger
* @tc.expect: Timer callback executes normally when device wakes before callback time
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, IdleTimer003, TestSize.Level0)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_INEXACT_REMINDER);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    StartIdleTimer();
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time) + FIVE_HUNDRED);
    EXPECT_EQ(g_data1, 0);
    DestroyIdleTimer();
    WaitForAlarm(&g_data1, FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: IdleTimer004
* @tc.desc: Test timer behavior when device enters sleep immediately after timer start
* @tc.precon: TimeServiceClient is properly initialized, idle timer mechanism works
* @tc.step: 1. Create inexact reminder timer with callback
*           2. Start timer with 500ms delay during normal operation
*           3. Immediately start idle timer to simulate device sleep
*           4. Wait for timer callback during sleep
*           5. Destroy idle timer to wake device
*           6. Verify timer callback executes after device wake
* @tc.expect: Timer callback executes after device wakes when sleep occurs immediately after timer start
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimerTest, IdleTimer004, TestSize.Level0)
{
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_INEXACT_REMINDER);
    timerInfo->SetRepeat(false);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    uint64_t timerId = 0;
    TimeServiceClient::GetInstance()->CreateTimerV9(timerInfo, timerId);
    EXPECT_NE(timerId, static_cast<uint64_t>(0));
    struct timeval currentTime {};
    gettimeofday(&currentTime, nullptr);
    int64_t time = currentTime.tv_sec * 1000 + currentTime.tv_usec / 1000;
    TimeServiceClient::GetInstance()->StartTimerV9(timerId, static_cast<uint64_t>(time + FIVE_HUNDRED));
    StartIdleTimer();
    usleep(FIVE_HUNDRED * MICRO_TO_MILLISECOND);
    DestroyIdleTimer();
    WaitForAlarm(&g_data1, ONE_HUNDRED * MICRO_TO_MILLISECOND);
    EXPECT_EQ(g_data1, 1);
    TimeServiceClient::GetInstance()->DestroyTimerV9(timerId);
}

/**
* @tc.name: CreateTimer001
* @tc.desc: Test timer operations with invalid timer ID (0)
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Attempt to start timer with ID 0
*           3. Attempt to stop timer with ID 0
*           4. Attempt to destroy timer with ID 0
*           5. Verify all operations fail
*           6. Remove permissions
* @tc.expect: All timer operations fail when using invalid timer ID (0)
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer001, TestSize.Level1)
{
    AddPermission();
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 5);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_FALSE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer002
* @tc.desc: Test complete timer lifecycle with realtime type timer
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create realtime type timer with callback
*           3. Start timer with 2000ms delay
*           4. Stop timer before trigger
*           5. Destroy timer
*           6. Verify all operations succeed
*           7. Remove permissions
* @tc.expect: Complete timer lifecycle operations succeed for realtime type timer
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer002, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    TIME_HILOGI(TIME_MODULE_CLIENT, "timerId now : %{public}" PRId64 "", timerId);
    EXPECT_GT(timerId, 0);
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer003
* @tc.desc: Test timer creation with WantAgent parameter
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create realtime type timer with WantAgent
*           3. Verify timer is created successfully
*           4. Remove permissions
* @tc.expect: Timer creation succeeds with WantAgent parameter
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer003, TestSize.Level1)
{
    AddPermission();
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    auto ability = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(ability);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    DeletePermission();
}

/**
* @tc.name: CreateTimer004
* @tc.desc: Test timer destruction before trigger time
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create realtime type timer with callback
*           3. Start timer with future boot time
*           4. Destroy timer immediately before trigger
*           5. Verify callback is not invoked
*           6. Attempt to stop destroyed timer
*           7. Remove permissions
* @tc.expect: Timer destruction succeeds before trigger, callback not invoked, stop operation fails on destroyed timer
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer004, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    auto BootTimeNano = system_clock::now().time_since_epoch().count();
    auto BootTimeMilli = BootTimeNano / NANO_TO_MILESECOND;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, BootTimeMilli + 2000);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer005
* @tc.desc: Test timer with absolute time trigger and immediate destruction
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create timer with type 0 (absolute time)
*           3. Start timer with calculated absolute time
*           4. Destroy timer immediately
*           5. Verify callback is not invoked
*           6. Attempt to stop destroyed timer
*           7. Remove permissions
* @tc.expect: Timer operations succeed, callback not invoked due to immediate destruction
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer005, TestSize.Level1)
{
    AddPermission();
    g_data1 = 1;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(0);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);

    struct timeval timeOfDay {
    };
    gettimeofday(&timeOfDay, NULL);
    int64_t currentTime = (timeOfDay.tv_sec + 100) * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);

    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, static_cast<uint64_t>(currentTime));
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 1);

    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer006
* @tc.desc: Test timer creation with null timer info
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Attempt to create timer with null timer info
*           3. Verify timer creation fails
*           4. Remove permissions
* @tc.expect: Timer creation returns 0 when timer info is null
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer006, TestSize.Level1)
{
    AddPermission();
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(nullptr);
    uint64_t ret = 0;
    EXPECT_EQ(timerId, ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer007
* @tc.desc: Test exact type timer with maximum trigger time value
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create exact type timer with callback
*           3. Start timer with maximum uint64_t value
*           4. Verify timer doesn't trigger immediately
*           5. Stop and destroy timer
*           6. Remove permissions
* @tc.expect: Exact timer with maximum trigger time doesn't trigger immediately, operations succeed
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer007, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, max);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer008
* @tc.desc: Test combined realtime and exact type timer with maximum trigger time
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create timer with realtime and exact type combination
*           3. Start timer with maximum uint64_t value
*           4. Verify timer doesn't trigger immediately
*           5. Stop and destroy timer
*           6. Remove permissions
* @tc.expect: Combined type timer with maximum trigger time doesn't trigger immediately, operations succeed
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer008, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME | timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, max);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer009
* @tc.desc: Test repeat timer behavior with system time adjustment
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Calculate time one day in future
*           3. Create exact type repeat timer with 1000ms interval
*           4. Start timer with future time
*           5. Set system time to future time to trigger timer
*           6. Wait for multiple timer triggers
*           7. Stop and destroy timer
*           8. Remove permissions
* @tc.expect: Repeat timer triggers multiple times after system time adjustment
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer009, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    struct timeval currentTime {
    };
    gettimeofday(&currentTime, NULL);
    // Set the time to one day later
    int64_t time = (currentTime.tv_sec + 86400) * 1000 + currentTime.tv_usec / 1000;
    TIME_HILOGI(TIME_MODULE_CLIENT, "Time now : %{public}" PRId64 "", time);
    ASSERT_GT(time, 0);

    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(true);
    timerInfo->SetInterval(1000);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, time);
    EXPECT_TRUE(ret);

    ret = TimeServiceClient::GetInstance()->SetTime(time);
    EXPECT_TRUE(ret);

    // wait for the second trigger success
    while (g_data1 < 2) {
        usleep(100000);
    }
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer010
* @tc.desc: Test asynchronous timer destruction with invalid timer ID
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Attempt to start timer with ID 0
*           3. Attempt to stop timer with ID 0
*           4. Attempt asynchronous destruction of timer with ID 0
*           5. Verify asynchronous destruction succeeds
*           6. Remove permissions
* @tc.expect: Asynchronous timer destruction succeeds even with invalid timer ID
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer010, TestSize.Level1)
{
    AddPermission();
    uint64_t timerId = 0;
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, 5);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_FALSE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimerAsync(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
* @tc.name: CreateTimer011
* @tc.desc: Test combined timer type with maximum trigger time and asynchronous destruction
* @tc.precon: TimeServiceClient is properly initialized, application has required permissions
* @tc.step: 1. Add required permissions
*           2. Create timer with realtime and exact type combination
*           3. Start timer with maximum uint64_t value
*           4. Verify timer doesn't trigger immediately
*           5. Stop timer
*           6. Destroy timer asynchronously
*           7. Remove permissions
* @tc.expect: Combined type timer operations succeed with maximum trigger time and asynchronous destruction
* @tc.type: FUNC
* @tc.require: issue#843
* @tc.level: level1
*/
HWTEST_F(TimeServiceTimerTest, CreateTimer011, TestSize.Level1)
{
    AddPermission();
    g_data1 = 0;
    auto timerInfo = std::make_shared<TimerInfoTest>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_REALTIME |
                       timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    timerInfo->SetInterval(0);
    timerInfo->SetWantAgent(nullptr);
    timerInfo->SetCallbackInfo(TimeOutCallback1);
    auto timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    EXPECT_GT(timerId, 0);
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto ret = TimeServiceClient::GetInstance()->StartTimer(timerId, max);
    EXPECT_TRUE(ret);
    EXPECT_EQ(g_data1, 0);
    ret = TimeServiceClient::GetInstance()->StopTimer(timerId);
    EXPECT_TRUE(ret);
    ret = TimeServiceClient::GetInstance()->DestroyTimerAsync(timerId);
    EXPECT_TRUE(ret);
    DeletePermission();
}

/**
 * @tc.name: TimerManager001
 * @tc.desc: Test ReCreateTimer function with valid timer entry
 * @tc.precon: TimerManager instance is available and timer entry map is accessible
 * @tc.step: 1. Create a TimerEntry with valid parameters
 *           2. Call ReCreateTimer to add timer to entry map
 *           3. Verify timer exists in timerEntryMap
 *           4. Clean up by removing timer from map
 * @tc.expect: Timer is successfully added to timerEntryMap and can be found
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager001, TestSize.Level0)
{
    auto timerId1 = TIMER_ID;
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", timerId1, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(timerId1, entry);
    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->entryMapMutex_);

    auto map = TimerManager::GetInstance()->timerEntryMap_;
    auto it = map.find(timerId1);
    EXPECT_NE(it, map.end());
    if (it != map.end()) {
        map.erase(it);
    }
}

/**
 * @tc.name: TimerManager002
 * @tc.desc: Test SetHandler with interval less than one second
 * @tc.precon: TimerManager instance is available and timer info can be created
 * @tc.step: 1. Create TimerInfo with interval = 10ms < 1s
 *           2. Call SetHandlerLocked to process the timer
 *           3. Verify timer is added to timerEntryMap
 *           4. Clean up timer entry
 * @tc.expect: Timer with small interval is successfully processed and added to entry map
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager002, TestSize.Level0)
{
    uint64_t max = std::numeric_limits<uint64_t>::max();
    auto alarm = TimerInfo::CreateTimerInfo("",
                                            TIMER_ID,
                                            0,
                                            max,
                                            10,
                                            0,
                                            1,
                                            false,
                                            nullptr,
                                            nullptr,
                                            0,
                                            0,
                                            "bundleName");
    std::lock_guard<std::mutex> lockGuard(TimerManager::GetInstance()->mutex_);
    TimerManager::GetInstance()->SetHandlerLocked(alarm);
    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->entryMapMutex_);
    auto map = TimerManager::GetInstance()->timerEntryMap_;
    auto it = map.find(TIMER_ID);
    EXPECT_NE(it, map.end());
    if (it != map.end()) {
        map.erase(it);
    }
}

/**
 * @tc.name: TimerManager003
 * @tc.desc: Test Set function with invalid alarm type (type > ALARM_TYPE_COUNT)
 * @tc.precon: TimerManager handler is properly initialized
 * @tc.step: 1. Prepare invalid alarm type (6) exceeding ALARM_TYPE_COUNT
 *           2. Call Set function with invalid type
 *           3. Verify function returns error code
 * @tc.expect: Set function returns -1 for invalid alarm type
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager003, TestSize.Level0)
{
    auto when = std::chrono::nanoseconds::zero();
    auto bootTime = std::chrono::steady_clock::now();
    auto res = TimerManager::GetInstance()->handler_->Set(6, when, bootTime);
    EXPECT_EQ(res, -1);
}

/**
 * @tc.name: TimerManager004
 * @tc.desc: Test StartTimer with UidProxy and PidProxy configurations
 * @tc.precon: TimerManager and TimerProxy instances are available
 * @tc.step: 1. Create timer entry with UID and PID
 *           2. Setup proxy timers for UID and PID combinations
 *           3. Call StartTimer and verify success for different proxy keys
 *           4. Clean up proxy timers and destroy timer
 * @tc.expect: StartTimer returns E_TIME_OK for both UID proxy and PID proxy configurations
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager004, TestSize.Level0)
{
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 0, 0, 0, 0, false, nullptr, nullptr, UID, PID, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    auto key1 = GetProxyKey(UID, 0);
    auto key2 = GetProxyKey(UID, PID);
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        std::vector<uint64_t> timerList;
        TimerProxy::GetInstance().proxyTimers_.insert(std::make_pair(key1, timerList));
    }
    auto res = TimerManager::GetInstance()->StartTimer(TIMER_ID, 0);
    EXPECT_EQ(res, E_TIME_OK);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        auto map = TimerProxy::GetInstance().proxyTimers_;
        auto it = map.find(key1);
        if (it != map.end()) {
            map.erase(it);
        }
    }
    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        auto map = TimerProxy::GetInstance().proxyTimers_;
        std::vector<uint64_t> timerList;
        TimerProxy::GetInstance().proxyTimers_.insert(std::make_pair(key2, timerList));
    }
    res = TimerManager::GetInstance()->StartTimer(TIMER_ID, 0);
    EXPECT_EQ(res, E_TIME_OK);

    {
        std::lock_guard<std::mutex> lock(TimerProxy::GetInstance().proxyMutex_);
        auto map = TimerProxy::GetInstance().proxyTimers_;
        auto it = map.find(key2);
        if (it != map.end()) {
            map.erase(it);
        }
    }

    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
}

/**
 * @tc.name: TimerManager005
 * @tc.desc: Test NotifyWantAgent function with different timer states
 * @tc.precon: TimerManager instance is available and database is accessible
 * @tc.step: 1. Create TimerInfo and call NotifyWantAgent
 *           2. Insert timer data to database (RDB or JSON based on configuration)
 *           3. Call NotifyWantAgent again with database entry
 *           4. Clean up database entries
 * @tc.expect: NotifyWantAgent returns false for both cases with valid cleanup
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager005, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, false, 0, 0, "");
    auto res = TimerManager::GetInstance()->NotifyWantAgent(timerInfo);
    EXPECT_FALSE(res);
    #ifdef RDB_ENABLE
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutLong("timerId", TIMER_ID);
    insertValues.PutInt("type", 0);
    insertValues.PutInt("flag", 0);
    insertValues.PutLong("windowLength", 0);
    insertValues.PutLong("interval", 0);
    insertValues.PutInt("uid", 0);
    insertValues.PutString("bundleName", "");
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    insertValues.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues.PutInt("state", 0);
    insertValues.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues);
    #else
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "bundleName"});
    CjsonHelper::GetInstance().Insert(HOLD_ON_REBOOT, entry);
    #endif
    res = TimerManager::GetInstance()->NotifyWantAgent(timerInfo);
    EXPECT_FALSE(res);
    #ifdef RDB_ENABLE
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(HOLD_ON_REBOOT);
    rdbPredicatesDelete.EqualTo("timerId", static_cast<int64_t>(TIMER_ID));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete);
    #else
    CjsonHelper::GetInstance().Delete(HOLD_ON_REBOOT, TIMER_ID);
    #endif
}

/**
 * @tc.name: TimerManager006
 * @tc.desc: Test AdjustTimer function with different adjustment parameters
 * @tc.precon: TimerManager instance is available and adjustment parameters can be modified
 * @tc.step: 1. Save current adjustment interval and policy
 *           2. Test AdjustTimer with same policy and interval
 *           3. Test AdjustTimer with different policy
 *           4. Test AdjustTimer with different interval
 *           5. Restore original adjustment settings
 * @tc.expect: AdjustTimer returns appropriate results based on parameter changes
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager006, TestSize.Level0)
{
    uint32_t interval;
    bool isAdjust;
    // Set 1000 as interval, because interval can not be 0;
    uint32_t intervalSet = 1000;
    {
        std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->mutex_);
        interval = TimerManager::GetInstance()->adjustInterval_;
        TimerManager::GetInstance()->adjustInterval_ = intervalSet;
        isAdjust = TimerManager::GetInstance()->adjustPolicy_;
    }

    auto res = TimerManager::GetInstance()->AdjustTimer(isAdjust, intervalSet, 0);
    EXPECT_FALSE(res);
    res = TimerManager::GetInstance()->AdjustTimer(!isAdjust, intervalSet, 0);
    EXPECT_TRUE(res);
    res = TimerManager::GetInstance()->AdjustTimer(isAdjust, intervalSet + 1, 0);
    EXPECT_TRUE(res);
    res = TimerManager::GetInstance()->AdjustTimer(isAdjust, intervalSet, 0);
    EXPECT_TRUE(res);

    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->mutex_);
    TimerManager::GetInstance()->adjustInterval_ = interval;
    TimerManager::GetInstance()->adjustPolicy_ = isAdjust;
}

/**
 * @tc.name: TimerManager007
 * @tc.desc: Test AdjustDeliveryTimeBasedOnDeviceIdle under different device states
 * @tc.precon: TimerManager instance is available and idle state can be simulated
 * @tc.step: 1. Set mPendingIdleUntil and test adjustment
 *           2. Clear mPendingIdleUntil and add delayed timer
 *           3. Test adjustment with different timer types and durations
 *           4. Restore original mPendingIdleUntil state
 * @tc.expect: AdjustDeliveryTimeBasedOnDeviceIdle returns correct results for various device idle scenarios
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager007, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, false, 0, 0, "");
    std::lock_guard<std::mutex> lock(TimerManager::GetInstance()->mutex_);
    auto alarm = TimerManager::GetInstance()->mPendingIdleUntil_;
    TimerManager::GetInstance()->mPendingIdleUntil_ = timerInfo1;
    auto res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo1);
    EXPECT_FALSE(res);

    TimerManager::GetInstance()->mPendingIdleUntil_ = nullptr;
    TimerManager::GetInstance()->delayedTimers_[TIMER_ID] = std::chrono::steady_clock::now();
    res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo1);
    EXPECT_TRUE(res);
    auto duration1 = std::chrono::duration_cast<std::chrono::milliseconds>(
            (timePoint + std::chrono::hours(1)).time_since_epoch());
    auto timerInfo2 = std::make_shared<TimerInfo>("", TIMER_ID, 1, duration1, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, false, 0, 0, "");
    res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo2);
    EXPECT_TRUE(res);
    auto timerInfo3 = std::make_shared<TimerInfo>("", TIMER_ID, 2, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, false, 0, 0, "");
    res = TimerManager::GetInstance()->AdjustDeliveryTimeBasedOnDeviceIdle(timerInfo3);
    EXPECT_TRUE(res);

    TimerManager::GetInstance()->mPendingIdleUntil_ = alarm;
}

#ifdef HIDUMPER_ENABLE
/**
 * @tc.name: TimerManager008
 * @tc.desc: Test ShowTimerEntryById when timer ID not exists in timerEntryMap
 * @tc.precon: TimerManager instance is available and timer is not created
 * @tc.step: 1. Ensure timer is destroyed and not in timerEntryMap
 *           2. Call ShowTimerEntryById with non-existent timer ID
 *           3. Verify function returns false
 * @tc.expect: ShowTimerEntryById returns false for non-existent timer ID
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager008, TestSize.Level0)
{
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);

    auto res = TimerManager::GetInstance()->ShowTimerEntryById(0, TIMER_ID);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: TimerManager009
 * @tc.desc: Test ShowTimerTriggerById when timer exists in alarmBatches
 * @tc.precon: TimerManager instance is available and timer can be created
 * @tc.step: 1. Create timer entry and add to timerEntryMap
 *           2. Start timer with maximum trigger time
 *           3. Call ShowTimerTriggerById and verify result
 *           4. Clean up by destroying timer
 * @tc.expect: ShowTimerTriggerById returns true for existing timer in alarmBatches
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager009, TestSize.Level0)
{
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    uint64_t triggerTime = std::numeric_limits<uint64_t>::max();
    TimerManager::GetInstance()->StartTimer(TIMER_ID, triggerTime);
    auto res = TimerManager::GetInstance()->ShowTimerTriggerById(0, TIMER_ID);
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    EXPECT_TRUE(res);
}
#endif

/**
 * @tc.name: TimerManager010
 * @tc.desc: Test HandleRSSDeath function for resource cleanup
 * @tc.precon: TimerManager instance is available and RSS death handler is functional
 * @tc.step: 1. Clear mPendingIdleUntil and call HandleRSSDeath
 *           2. Set mPendingIdleUntil and create timer entry
 *           3. Call HandleRSSDeath and verify timer cleanup
 *           4. Restore original mPendingIdleUntil state
 * @tc.expect: HandleRSSDeath properly cleans up resources and timers
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager010, TestSize.Level0)
{
    std::shared_ptr<TimerInfo> alarm;
    {
        std::lock_guard <std::mutex> lock(TimerManager::GetInstance()->mutex_);
        alarm = TimerManager::GetInstance()->mPendingIdleUntil_;
        TimerManager::GetInstance()->mPendingIdleUntil_ = nullptr;
    }
    TimerManager::GetInstance()->HandleRSSDeath();

    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                  nullptr, nullptr, 0, false, 0, 0, "");
    {
        std::lock_guard <std::mutex> lock(TimerManager::GetInstance()->mutex_);
        TimerManager::GetInstance()->mPendingIdleUntil_ = timerInfo;
    }
    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    TimerManager::GetInstance()->HandleRSSDeath();
    auto res = TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    EXPECT_EQ(res, E_TIME_NOT_FOUND);

    {
        std::lock_guard <std::mutex> lock(TimerManager::GetInstance()->mutex_);
        TimerManager::GetInstance()->mPendingIdleUntil_ = alarm;
    }
}

/**
 * @tc.name: TimerManager011
 * @tc.desc: Test OnPackageRemoved function for package-based timer cleanup
 * @tc.precon: TimerManager instance is available and timer entry map is accessible
 * @tc.step: 1. Clear timerEntryMap
 *           2. Create timer entry with specific UID
 *           3. Call OnPackageRemoved with the UID
 *           4. Verify timer is removed from timerEntryMap
 * @tc.expect: OnPackageRemoved successfully removes all timers associated with the specified UID
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager011, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    {
        std::lock_guard<std::mutex> lock(timerManager->entryMapMutex_);
        timerManager->timerEntryMap_.clear();
    }

    auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", TIMER_ID, 0, 0, 0, 0, false, nullptr, nullptr, UID, 0, "bundleName"});
    timerManager->ReCreateTimer(TIMER_ID, entry);
    timerManager->OnPackageRemoved(UID);

    {
        std::lock_guard<std::mutex> lock(timerManager->entryMapMutex_);
        auto map = timerManager->timerEntryMap_;
        auto it = map.find(TIMER_ID);
        EXPECT_EQ(it, map.end());
        if (it != map.end()) {
            map.erase(it);
        }
    }
}

/**
 * @tc.name: TimerManager012
 * @tc.desc: Test timer count recording and deletion functionality
 * @tc.precon: TimerManager instance is available and timerCount map is accessible
 * @tc.step: 1. Clear timerCount map
 *           2. Increase timer count for multiple UIDs
 *           3. Verify timer count values
 *           4. Decrease timer count and verify updated values
 * @tc.expect: Timer count is properly maintained for different UIDs with correct increment/decrement
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager012, TestSize.Level0)
{
    int uid1 = UID;
    int uid2 = UID + 1;
    TimerManager::GetInstance()->timerCount_.clear();
    for (int i = 0; i < 10; ++i) {
        TimerManager::GetInstance()->IncreaseTimerCount(uid1);
    }
    EXPECT_EQ(TimerManager::GetInstance()->timerCount_.size(), 1);
    auto it = std::find_if(TimerManager::GetInstance()->timerCount_.begin(),
        TimerManager::GetInstance()->timerCount_.end(),
        [uid1](const std::pair<int32_t, size_t>& pair) {
            return pair.first == uid1;
    });
    EXPECT_EQ(it->second, 10);
    for (int i = 0; i < 10; ++i) {
        TimerManager::GetInstance()->IncreaseTimerCount(uid2);
    }
    EXPECT_EQ(TimerManager::GetInstance()->timerCount_.size(), 2);
    for (int i = 0; i < 5; ++i) {
        TimerManager::GetInstance()->DecreaseTimerCount(uid2);
    }
    it = std::find_if(TimerManager::GetInstance()->timerCount_.begin(),
        TimerManager::GetInstance()->timerCount_.end(),
        [uid2](const std::pair<int32_t, size_t>& pair) {
            return pair.first == uid2;
    });
    EXPECT_EQ(it->second, 5);
}

/**
 * @tc.name: TimerManager013
 * @tc.desc: Test timer out-of-range counter when creating excessive timers
 * @tc.precon: TimerManager instance is available and alarm count threshold is defined
 * @tc.step: 1. Clear timer entry map and out-of-range counter
 *           2. Create timers exceeding TIMER_ALARM_COUNT limit
 *           3. Verify out-of-range counter increments appropriately
 *           4. Create more timers to trigger additional out-of-range events
 * @tc.expect: timerOutOfRangeTimes_ increments when timer count exceeds defined limits
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager013, TestSize.Level0)
{
    TimerManager::GetInstance()->timerEntryMap_.clear();
    TimerManager::GetInstance()->timerCount_.clear();
    TimerManager::GetInstance()->timerOutOfRangeTimes_ = 0;
    uint64_t i = 0;
    for (; i <= TIMER_ALARM_COUNT; ++i) {
        auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", i, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "bundleName"});
        TimerManager::GetInstance()->ReCreateTimer(i, entry);
    }
    EXPECT_EQ(TimerManager::GetInstance()->timerOutOfRangeTimes_, 1);
    for (; i <= TIMER_ALARM_COUNT * 2; ++i) {
        auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"", i, 0, 0, 0, 0, false, nullptr, nullptr, 0, 0, "bundleName"});
        TimerManager::GetInstance()->ReCreateTimer(i, entry);
    }
    EXPECT_EQ(TimerManager::GetInstance()->timerOutOfRangeTimes_, 2);
}

/**
 * @tc.name: TimerManager014
 * @tc.desc: Test timer creation with duplicate names for same UID
 * @tc.precon: TimerManager instance is available and timer name map is accessible
 * @tc.step: 1. Clear timerNameMap
 *           2. Create timer with specific name and UID
 *           3. Verify timer name mapping
 *           4. Create another timer with same name but different ID for same UID
 *           5. Verify name mapping is updated and original timer is not found
 * @tc.expect: Later timer with same name overwrites previous mapping for the same UID
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager014, TestSize.Level0)
{
    TIME_HILOGI(TIME_MODULE_CLIENT, "TimerManager014 start");
    TimerManager::GetInstance()->timerNameMap_.clear();
    auto entry = std::make_shared<TimerEntry>(
        TimerEntry{"name", TIMER_ID, 0, 0, 0, 0, false, nullptr, nullptr, UID, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    auto timerNameMap = TimerManager::GetInstance()->timerNameMap_;
    EXPECT_NE(timerNameMap.find(UID), timerNameMap.end());
    EXPECT_NE(timerNameMap[UID].find("name"), timerNameMap[UID].end());
    EXPECT_EQ(timerNameMap[UID]["name"], TIMER_ID);

    entry = std::make_shared<TimerEntry>(
        TimerEntry{"name", TIMER_ID + 1, 0, 0, 0, 0, false, nullptr, nullptr, UID, 0, "bundleName"});
    TimerManager::GetInstance()->ReCreateTimer(TIMER_ID + 1, entry);
    timerNameMap = TimerManager::GetInstance()->timerNameMap_;
    EXPECT_NE(timerNameMap.find(UID), timerNameMap.end());
    EXPECT_NE(timerNameMap[UID].find("name"), timerNameMap[UID].end());
    EXPECT_EQ(timerNameMap[UID]["name"], TIMER_ID + 1);
    auto ret = TimerManager::GetInstance()->DestroyTimer(TIMER_ID);
    EXPECT_EQ(ret, E_TIME_NOT_FOUND);
}

/**
 * @tc.name: TimerManager015
 * @tc.desc: Test timer count checking and out-of-range time updating
 * @tc.precon: TimerManager instance is available and timer count checking is enabled
 * @tc.step: 1. Clear timerNameMap and create multiple timers
 *           2. Set lastTimerOutOfRangeTime to past time
 *           3. Call CheckTimerCount function
 *           4. Verify lastTimerOutOfRangeTime is updated
 * @tc.expect: CheckTimerCount updates lastTimerOutOfRangeTime when appropriate conditions are met
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager015, TestSize.Level0)
{
    TimerManager::GetInstance()->timerNameMap_.clear();
    for (int i = 0; i < 101; i++)
    {
        auto entry = std::make_shared<TimerEntry>(
            TimerEntry{"name", TIMER_ID + i, 0, 0, 0, 0, false, nullptr, nullptr, UID, 0, "bundleName"});
        TimerManager::GetInstance()->ReCreateTimer(TIMER_ID, entry);
    }
    auto lastTimer = std::chrono::steady_clock::now() - std::chrono::minutes(61);
    TimerManager::GetInstance()->lastTimerOutOfRangeTime_ = lastTimer;
    TimerManager::GetInstance()->CheckTimerCount();
    EXPECT_NE(TimerManager::GetInstance()->lastTimerOutOfRangeTime_, lastTimer);
    TimerManager::GetInstance()->timerNameMap_.clear();
}

/**
 * @tc.name: TimerManager016
 * @tc.desc: Test database update and deletion operations
 * @tc.precon: TimeDatabase instance is available and accessible
 * @tc.step: 1. Insert timer data into HOLD_ON_REBOOT table
 *           2. Call UpdateOrDeleteDatabase with delete flag
 *           3. Query database to verify deletion
 * @tc.expect: Timer data is successfully deleted from database after UpdateOrDeleteDatabase call
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager016, TestSize.Level0)
{
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutLong("timerId", TIMER_ID);
    insertValues.PutInt("type", 0);
    insertValues.PutInt("flag", 0);
    insertValues.PutLong("windowLength", 0);
    insertValues.PutLong("interval", 0);
    insertValues.PutInt("uid", 0);
    insertValues.PutString("bundleName", "");
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent = nullptr;
    insertValues.PutString("wantAgent", OHOS::AbilityRuntime::WantAgent::WantAgentHelper::ToString(wantAgent));
    insertValues.PutInt("state", 0);
    insertValues.PutLong("triggerTime", static_cast<int64_t>(std::numeric_limits<int64_t>::max()));
    TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues);
    TimerManager::GetInstance()->UpdateOrDeleteDatabase(true, TIMER_ID, true);
    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete(HOLD_ON_REBOOT);
    rdbPredicatesDelete.EqualTo("timerId", static_cast<int64_t>(TIMER_ID));
    int count = 0;
    TimeDatabase::GetInstance().Query(rdbPredicatesDelete, {"timerId"})->GetRowCount(count);
    EXPECT_EQ(count, 0);
}

/**
 * @tc.name: TimerManager017
 * @tc.desc: Test database operations when store pointer is null
 * @tc.precon: TimeDatabase instance is available but store can be set to null
 * @tc.step: 1. Clear database and set store pointer to null
 *           2. Attempt various database operations (insert, update, query, delete)
 *           3. Verify operations handle null store gracefully
 *           4. Restore original store pointer
 * @tc.expect: All database operations return appropriate error results when store is null
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerManager017, TestSize.Level0)
{
    auto DataBase = TimeDatabase::GetInstance();
    DataBase.ClearDropOnReboot();
    DataBase.ClearInvaildDataInHoldOnReboot();
    auto storeptr = DataBase.store_;
    DataBase.store_ = nullptr;
    OHOS::NativeRdb::ValuesBucket Values;
    OHOS::NativeRdb::RdbPredicates rdbPredicates(HOLD_ON_REBOOT);
    DataBase.ClearDropOnReboot();
    DataBase.ClearInvaildDataInHoldOnReboot();
    auto res = DataBase.Insert(HOLD_ON_REBOOT, Values);
    EXPECT_FALSE(res);
    res = DataBase.Update(Values, rdbPredicates);
    EXPECT_FALSE(res);
    auto queryres = DataBase.Query(rdbPredicates, {"something"});
    EXPECT_EQ(queryres, nullptr);
    res = DataBase.Delete(rdbPredicates);
    EXPECT_FALSE(res);
    DataBase.store_ = storeptr;
}

/**
 * @tc.name: TimerInfo001
 * @tc.desc: Test UpdateWhenElapsedFromNow function with zero duration
 * @tc.precon: TimerInfo instance can be created and time points are available
 * @tc.step: 1. Create TimerInfo with zero duration parameters
 *           2. Call UpdateWhenElapsedFromNow with current time and zero duration
 *           3. Verify function returns false
 * @tc.expect: UpdateWhenElapsedFromNow returns false for zero duration update
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo001, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = TimerInfo("", 0, 0, duration, timePoint, duration, timePoint, duration, nullptr,
                                          nullptr, 0, false, 0, 0, "");
    auto res = timerInfo.UpdateWhenElapsedFromNow(timePoint, duration);
    EXPECT_FALSE(res);
}

/**
 * @tc.name: TimerInfo002
 * @tc.desc: Test AdjustTimer function with valid adjustment parameters
 * @tc.precon: TimerInfo instance can be created and adjustment parameters are valid
 * @tc.step: 1. Create TimerInfo with zero duration parameters
 *           2. Call AdjustTimer with current time and adjustment parameters
 *           3. Verify function returns true
 * @tc.expect: AdjustTimer returns true for valid adjustment operation
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo002, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds(0);
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = TimerInfo("", 0, 0, duration, timePoint, duration, timePoint, duration, nullptr,
                                          nullptr, 0, false, 0, 0, "");
    auto res = timerInfo.AdjustTimer(timePoint, 1, 0, 0);
    EXPECT_TRUE(res);
    res = timerInfo.AdjustTimer(timePoint, 0, 0, 1);
    EXPECT_FALSE(res);
    res = timerInfo.AdjustTimer(timePoint, 1, 0, 2);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: TimerInfo003
 * @tc.desc: Test CreateTimerInfo static function with RTC timer type
 * @tc.precon: System time functions are available and TimerInfo creation is supported
 * @tc.step: 1. Get current time using gettimeofday
 *           2. Create TimerInfo with RTC type and future trigger time
 *           3. Verify all TimerInfo attributes are correctly initialized
 * @tc.expect: TimerInfo is created with correct attributes including converted elapsed times
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo003, TestSize.Level0)
{
    struct timeval timeOfDay {};
    gettimeofday(&timeOfDay, nullptr);
    int64_t currentTime = (timeOfDay.tv_sec + 100) * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }
    auto timerInfo = TimerInfo::CreateTimerInfo("",
                                                0,
                                                ITimerManager::RTC,
                                                currentTime,
                                                0,
                                                10000,
                                                0,
                                                false,
                                                nullptr,
                                                nullptr,
                                                0,
                                                false,
                                                "");
    auto triggerTime = milliseconds(currentTime);
    auto triggerElapsed = TimerInfo::ConvertToElapsed(triggerTime, ITimerManager::RTC);
    EXPECT_EQ(timerInfo->name, "");
    EXPECT_EQ(timerInfo->id, 0);
    EXPECT_EQ(timerInfo->type, ITimerManager::RTC);
    EXPECT_EQ(timerInfo->when, triggerTime);
    EXPECT_EQ(timerInfo->origWhen, triggerTime);
    EXPECT_EQ(timerInfo->wakeup, false);
    EXPECT_EQ(timerInfo->whenElapsed.time_since_epoch().count() / NANO_TO_SECOND,
              triggerElapsed.time_since_epoch().count() / NANO_TO_SECOND);
    EXPECT_EQ(timerInfo->maxWhenElapsed.time_since_epoch().count() / NANO_TO_SECOND,
              triggerElapsed.time_since_epoch().count() / NANO_TO_SECOND);
    EXPECT_EQ(timerInfo->windowLength, milliseconds(0));
    EXPECT_EQ(timerInfo->repeatInterval, milliseconds(10000));
    EXPECT_EQ(timerInfo->bundleName, "");
    EXPECT_EQ(timerInfo->callback, nullptr);
    EXPECT_EQ(timerInfo->wantAgent, nullptr);
    EXPECT_EQ(timerInfo->autoRestore, false);
}

/**
 * @tc.name: TimerInfo004
 * @tc.desc: Test MaxTriggerTime static function with different time windows
 * @tc.precon: TimeUtils functions are available and time calculations are supported
 * @tc.step: 1. Get current boot time as reference
 *           2. Calculate max trigger time for different whenElapsed and windowLength combinations
 *           3. Verify max trigger time calculations are correct
 * @tc.expect: MaxTriggerTime returns correct values based on window length and elapsed time rules
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo004, TestSize.Level0)
{
    auto currentBootTime = TimeUtils::GetBootTimeNs();
    auto maxTriggerTime = TimerInfo::MaxTriggerTime(currentBootTime,
                                                    currentBootTime + milliseconds(9999),
                                                    milliseconds::zero());
    EXPECT_EQ(maxTriggerTime, currentBootTime + milliseconds(9999));

    auto maxTriggerTime2 = TimerInfo::MaxTriggerTime(currentBootTime,
                                                currentBootTime + milliseconds(10000),
                                                     milliseconds::zero());
    EXPECT_EQ(maxTriggerTime2, currentBootTime + milliseconds(10000 + 7500));

    auto maxTriggerTime3 = TimerInfo::MaxTriggerTime(currentBootTime,
                                                 currentBootTime + milliseconds(9999),
                                                 milliseconds(20000));
    EXPECT_EQ(maxTriggerTime3, currentBootTime + milliseconds(9999 + 15000));

    auto maxTriggerTime4 = TimerInfo::MaxTriggerTime(currentBootTime,
                                                 currentBootTime + milliseconds(10000),
                                                 milliseconds(20000));
    EXPECT_EQ(maxTriggerTime4, currentBootTime + milliseconds(10000 + 15000));
}

/**
 * @tc.name: TimerInfo005
 * @tc.desc: Test ConvertToElapsed static function for RTC and ELAPSED_REALTIME types
 * @tc.precon: System time functions are available and time conversion is supported
 * @tc.step: 1. Get current system time and boot time
 *           2. Test RTC type conversion with duration offset
 *           3. Test ELAPSED_REALTIME type conversion with duration offset
 *           4. Verify converted elapsed times are within expected ranges
 * @tc.expect: ConvertToElapsed returns correct elapsed time for both timer types
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo005, TestSize.Level0)
{
    struct timeval timeOfDay {};
    gettimeofday(&timeOfDay, nullptr);
    int64_t currentTime = timeOfDay.tv_sec * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }

    auto currentBootTime = TimeUtils::GetBootTimeNs();
    auto range = milliseconds(1000);
    auto duration = milliseconds(5000);

    auto elapsed1 = TimerInfo::ConvertToElapsed(milliseconds(currentTime) + duration,
                                                ITimerManager::RTC);
    EXPECT_GT(elapsed1, currentBootTime + duration - range);
    EXPECT_GT(currentBootTime + duration + range, elapsed1);

    int64_t currentBootTime2 = 0;
    TimeUtils::GetBootTimeMs(currentBootTime2);
    std::chrono::steady_clock::time_point bootTime2 ((std::chrono::milliseconds(currentBootTime2)));

    auto elapsed2 = TimerInfo::ConvertToElapsed(milliseconds(currentBootTime2) + duration,
                                                ITimerManager::ELAPSED_REALTIME);
    EXPECT_EQ(elapsed2, bootTime2 + duration);
}

/**
 * @tc.name: TimerInfo006
 * @tc.desc: Test CalculateWhenElapsed function for RTC timer type
 * @tc.precon: TimerInfo instance can be created and time calculation functions are available
 * @tc.step: 1. Create TimerInfo with RTC type and current time
 *           2. Call CalculateWhenElapsed with epoch time point
 *           3. Verify whenElapsed and maxWhenElapsed are correctly calculated
 * @tc.expect: CalculateWhenElapsed sets correct elapsed times within expected range
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo006, TestSize.Level0)
{
    struct timeval timeOfDay {};
    gettimeofday(&timeOfDay, nullptr);
    int64_t currentTime = timeOfDay.tv_sec * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }

    auto currentBootTime = TimeUtils::GetBootTimeNs();
    auto range = milliseconds(1000);
    auto zero = milliseconds(0);

    std::chrono::steady_clock::time_point empty (zero);
    std::chrono::steady_clock::time_point tp_epoch ((std::chrono::milliseconds(currentTime)));

    auto timerInfo = TimerInfo("", 0, ITimerManager::RTC, std::chrono::milliseconds(currentTime), empty, zero,
                               empty, zero, nullptr, nullptr, 0, false, 0, 0, "");
    timerInfo.CalculateWhenElapsed(tp_epoch);
    EXPECT_GT(timerInfo.whenElapsed, currentBootTime - range);
    EXPECT_GT(currentBootTime + range, timerInfo.whenElapsed);
    EXPECT_EQ(timerInfo.whenElapsed, timerInfo.maxWhenElapsed);
}

/**
 * @tc.name: TimerInfo007
 * @tc.desc: Test CalculateOriWhenElapsed function for RTC timer type
 * @tc.precon: TimerInfo instance can be created and original time calculation is supported
 * @tc.step: 1. Create TimerInfo with RTC type and current time
 *           2. Call CalculateOriWhenElapsed function
 *           3. Verify originWhenElapsed and originMaxWhenElapsed are correctly calculated
 * @tc.expect: CalculateOriWhenElapsed sets correct original elapsed times within expected range
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo007, TestSize.Level0)
{
    struct timeval timeOfDay {};
    gettimeofday(&timeOfDay, nullptr);
    int64_t currentTime = timeOfDay.tv_sec * 1000 + timeOfDay.tv_usec / 1000;
    if (currentTime < 0) {
        currentTime = 0;
    }

    auto currentBootTime = TimeUtils::GetBootTimeNs();
    auto range = milliseconds(1000);
    auto zero = milliseconds(0);

    std::chrono::steady_clock::time_point empty (zero);

    auto timerInfo = TimerInfo("", 0, ITimerManager::RTC, std::chrono::milliseconds(currentTime), empty, zero,
                               empty, zero, nullptr, nullptr, 0, false, 0, 0, "");
    timerInfo.CalculateOriWhenElapsed();
    EXPECT_GT(timerInfo.originWhenElapsed, currentBootTime - range);
    EXPECT_GT(currentBootTime + range, timerInfo.originWhenElapsed);
    EXPECT_EQ(timerInfo.originWhenElapsed, timerInfo.originMaxWhenElapsed);
}

/**
 * @tc.name: TimerInfo008
 * @tc.desc: Test ProxyTimer function for ELAPSED_REALTIME timer type
 * @tc.precon: TimerInfo instance can be created and proxy functionality is available
 * @tc.step: 1. Create TimerInfo with ELAPSED_REALTIME type
 *           2. Call ProxyTimer with 3000ms delay
 *           3. Verify timer state and time attributes are updated correctly
 * @tc.expect: ProxyTimer updates state to PROXY and adjusts time attributes appropriately
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo008, TestSize.Level0)
{
    auto zero = milliseconds(0);
    std::chrono::steady_clock::time_point empty (zero);
    auto timerInfo = TimerInfo("", 0, ITimerManager::ELAPSED_REALTIME, zero, empty, zero, empty, zero, nullptr,
                               nullptr, 0, false, 0, 0, "");
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::INIT);
    EXPECT_TRUE(timerInfo.ProxyTimer(empty, milliseconds(3000)));
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::PROXY);
    EXPECT_EQ(timerInfo.whenElapsed, empty + milliseconds(3000));
    EXPECT_EQ(timerInfo.maxWhenElapsed, empty + milliseconds(3000));
    EXPECT_EQ(timerInfo.when, milliseconds(3000));
}

/**
 * @tc.name: TimerInfo009
 * @tc.desc: Test RestoreProxyTimer function for different timer states
 * @tc.precon: TimerInfo instance can be created and proxy restoration is supported
 * @tc.step: 1. Create TimerInfo and test restore from INIT state
 *           2. Test restore from ADJUST state
 *           3. Set timer to PROXY state and test restore
 *           4. Verify state and time attributes are restored correctly
 * @tc.expect: RestoreProxyTimer correctly restores timer attributes only from PROXY state
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo009, TestSize.Level0)
{
    auto zero = milliseconds(0);
    std::chrono::steady_clock::time_point empty (zero);
    auto timerInfo = TimerInfo("", 0, ITimerManager::ELAPSED_REALTIME, zero, empty, zero, empty, zero, nullptr,
                               nullptr, 0, false, 0, 0, "");
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::INIT);
    EXPECT_FALSE(timerInfo.RestoreProxyTimer());
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::INIT);

    timerInfo.state = TimerInfo::TimerState::ADJUST;
    EXPECT_FALSE(timerInfo.RestoreProxyTimer());
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::INIT);

    timerInfo.ProxyTimer(empty, milliseconds(3000));
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::PROXY);
    EXPECT_EQ(timerInfo.whenElapsed, empty + milliseconds(3000));
    EXPECT_EQ(timerInfo.maxWhenElapsed, empty + milliseconds(3000));
    EXPECT_EQ(timerInfo.when, milliseconds(3000));

    EXPECT_TRUE(timerInfo.RestoreProxyTimer());
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::INIT);
    EXPECT_EQ(timerInfo.whenElapsed, empty);
    EXPECT_EQ(timerInfo.maxWhenElapsed, empty);
    EXPECT_EQ(timerInfo.when, milliseconds(0));
}

/**
 * @tc.name: TimerInfo010
 * @tc.desc: test ChangeStatusToAdjust.
 * @tc.precon: TimerInfo instance can be created and adjust restoration is supported
 * @tc.step: 1. Create TimerInfo and test restore from INIT state
 *           2. Test adjust from INIT state
 *           3. Test adjust from ADJUST state
 *           4. Test adjust from PROXY state
 * @tc.expect: RestoreProxyTimer correctly restores timer attributes only from PROXY state
 * @tc.type: FUNC
 * @tc.require: issue#853
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo010, TestSize.Level0)
{
    auto zero = milliseconds(0);
    std::chrono::steady_clock::time_point empty (zero);
    auto timerInfo = TimerInfo("", 0, ITimerManager::ELAPSED_REALTIME, zero, empty, zero, empty, zero, nullptr,
                               nullptr, 0, false, 0, 0, "");
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::INIT);
    auto timePoint = std::chrono::steady_clock::now();
    timerInfo.AdjustTimer(timePoint, 1, 0, 0);
    EXPECT_TRUE(timerInfo.ChangeStatusToAdjust());
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::ADJUST);

    timerInfo.ProxyTimer(empty, milliseconds(3000));
    EXPECT_EQ(timerInfo.state, TimerInfo::TimerState::PROXY);
    EXPECT_FALSE(timerInfo.ChangeStatusToAdjust());
}

/**
 * @tc.name: TimerInfo011
 * @tc.desc: Test repeat timer with triggertime before currenttime
 * @tc.precon: the calculate of timer must be correct
 * @tc.step: 1. Create repeat timer with ealier tirggertime
 *           2. Timer triggered and system handler repeat timer, create a new timer
 *           3. The New timer has the same gap time between when and whenelapsed as the old timer's gap
 * @tc.expect: RestoreProxyTimer correctly restores timer attributes only from PROXY state
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, TimerInfo011, TestSize.Level0)
{
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    auto triggerTime = currentTime - 5000000;
    auto callback = [this](uint64_t id) -> int32_t {
        return 0;
    };
    auto timerInfo = TimerInfo::CreateTimerInfo("", TIMER_ID, 0, triggerTime, 0, 1800000, 1, false, callback,
        nullptr, UID, PID, "");
    auto bootTime = TimeUtils::GetBootTimeNs();

    auto origWhen = timerInfo->origWhen;
    auto origWhenElapsed = timerInfo->whenElapsed;
    auto origGap = (origWhen- origWhenElapsed.time_since_epoch()).count();
    TimerManager::GetInstance()->HandleRepeatTimer(timerInfo, bootTime);

    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    auto it1 = uidTimersMap.find(UID);
    EXPECT_NE(it1, uidTimersMap.end());
    auto it2 = it1->second.find(TIMER_ID);
    EXPECT_NE(it2, it1->second.end());
    auto newGap = (it2->second->when - it2->second->maxWhenElapsed.time_since_epoch()).count();
    EXPECT_LE(std::abs(origGap - newGap), NANO_TO_MILLISECOND);
    TimerManager::GetInstance()->RemoveLocked(TIMER_ID, false);
}

#ifdef SET_AUTO_REBOOT_ENABLE
/**
 * @tc.name: IsPowerOnTimer001
 * @tc.desc: Test IsPowerOnTimer function with different timer name and bundle name combinations
 * @tc.precon: TimerManager instance is available and powerOnApps list is configured
 * @tc.step: 1. Configure powerOnApps with test bundle and timer names
 *           2. Test timers with only timer name matching
 *           3. Test timers with only bundle name matching
 *           4. Test timers with autoRestore flag and name matching
 *           5. Test timers with autoRestore flag and bundle name matching
 * @tc.expect: IsPowerOnTimer returns true only for autoRestore timers with matching names
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, IsPowerOnTimer001, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    timerManager->powerOnApps_ = {"testBundleName", "testTimerName"};
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();

    auto timerInfo1 = std::make_shared<TimerInfo>("testTimerName", TIMER_ID, 0, duration, timePoint, duration,
        timePoint, duration, nullptr, nullptr, 0, false, 0, 0, "");
    bool ret = true;
    ret = timerManager->IsPowerOnTimer(timerInfo1);
    EXPECT_EQ(ret, false);

    auto timerInfo2 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
        nullptr, nullptr, 0, false, 0, 0, "testBundleName");
    ret = true;
    ret = timerManager->IsPowerOnTimer(timerInfo2);
    EXPECT_EQ(ret, false);

    auto timerInfo3 = std::make_shared<TimerInfo>("testTimerName", TIMER_ID, 0, duration, timePoint, duration,
        timePoint, duration, nullptr, nullptr, 0, true, 0, 0, "");
    ret = false;
    ret = timerManager->IsPowerOnTimer(timerInfo3);
    EXPECT_EQ(ret, true);

    auto timerInfo4 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
        nullptr, nullptr, 0, true, 0, 0, "testBundleName");
    ret = false;
    ret = timerManager->IsPowerOnTimer(timerInfo4);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: AddPowerOnTimer001
 * @tc.desc: Test SetHandlerLocked function to prevent duplicate timers in powerOnTriggerTimerList
 * @tc.precon: TimerManager instance is available and powerOnApps list is configured
 * @tc.step: 1. Clear powerOnTriggerTimerList and configure powerOnApps
 *           2. Create power-on timer with autoRestore flag
 *           3. Call SetHandlerLocked multiple times with same timer
 *           4. Verify timer is only added once to the list
 *           5. Remove timer and verify list is cleared
 * @tc.expect: Same timer is not duplicated in powerOnTriggerTimerList and can be properly removed
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, AddPowerOnTimer001, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    timerManager->powerOnTriggerTimerList_.clear();
    timerManager->powerOnApps_ = {"testBundleName", "testTimerName"};
    int64_t currentTime = 0;
    auto ret = TimeUtils::GetWallTimeMs(currentTime);
    EXPECT_EQ(ret, ERR_OK);
    auto duration = std::chrono::milliseconds(currentTime + 10000);
    auto timePoint = std::chrono::steady_clock::now() + std::chrono::milliseconds(10000);

    auto timerInfo1 = std::make_shared<TimerInfo>("testTimerName", TIMER_ID, 0, duration, timePoint, duration,
        timePoint, duration, nullptr, nullptr, 0, true, 0, 0, "");
    timerManager->SetHandlerLocked(timerInfo1, false, false);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 1);
    timerManager->SetHandlerLocked(timerInfo1, false, false);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 1);
    timerManager->SetHandlerLocked(timerInfo1, false, false);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 1);
    timerManager->SetHandlerLocked(timerInfo1, false, false);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 1);
    timerManager->RemoveLocked(TIMER_ID, true);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 0);
}

/**
 * @tc.name: DeleteTimerFromPowerOnTimerListById001
 * @tc.desc: Test DeleteTimerFromPowerOnTimerListById function for timer removal
 * @tc.precon: TimerManager instance is available and powerOnTriggerTimerList can be modified
 * @tc.step: 1. Add timer to powerOnTriggerTimerList
 *           2. Verify timer is added successfully
 *           3. Call DeleteTimerFromPowerOnTimerListById with timer ID
 *           4. Verify timer is removed from the list
 * @tc.expect: Timer is successfully removed from powerOnTriggerTimerList by ID
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, DeleteTimerFromPowerOnTimerListById001, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    auto duration = std::chrono::milliseconds(1000);
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
        nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 1);
    timerManager->DeleteTimerFromPowerOnTimerListById(TIMER_ID);
    EXPECT_EQ(timerManager->powerOnTriggerTimerList_.size(), 0);
}

/**
 * @tc.name: ReschedulePowerOnTimerLocked001
 * @tc.desc: Test ReschedulePowerOnTimerLocked function with multiple timer scenarios
 * @tc.precon: TimerManager instance is available and lastSetTime can be modified
 * @tc.step: 1. Reset lastSetTime and add timer with 1000ms trigger
 *           2. Add timer with 2000ms trigger and verify scheduling
 *           3. Add timer with 500ms trigger (earliest) and verify rescheduling
 *           4. Remove timers in sequence and verify lastSetTime updates
 *           5. Clear all timers and verify default scheduling
 * @tc.expect: ReschedulePowerOnTimerLocked always schedules the earliest trigger time
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ReschedulePowerOnTimerLocked001, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    timerManager->lastSetTime_[POWER_ON_ALARM] = 0;
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    auto triggerTime1 = currentTime + 1000;
    auto duration1 = std::chrono::milliseconds(triggerTime1);
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration1, timePoint, duration1, timePoint,
        duration1, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo1);
    timerManager->ReschedulePowerOnTimerLocked(false);
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime1);

    auto triggerTime2 = currentTime + 2000 + TWO_MINUTES_TO_MILLI;
    auto duration2 = std::chrono::milliseconds(triggerTime2);
    auto timerId2 = TIMER_ID + 1;
    auto timerInfo2 = std::make_shared<TimerInfo>("", timerId2, 0, duration2, timePoint, duration2, timePoint,
        duration2, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo2);
    timerManager->ReschedulePowerOnTimerLocked(false);
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime1);

    auto triggerTime3 = currentTime + 500;
    auto duration3 = std::chrono::milliseconds(triggerTime3);
    auto timerId3 = timerId2 + 1;
    auto timerInfo3 = std::make_shared<TimerInfo>("", timerId3, 0, duration3, timePoint, duration3, timePoint,
        duration3, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo3);
    timerManager->ReschedulePowerOnTimerLocked(false);
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime3);

    timerManager->DeleteTimerFromPowerOnTimerListById(timerId3);
    timerManager->ReschedulePowerOnTimerLocked(false);
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime1);

    timerManager->DeleteTimerFromPowerOnTimerListById(TIMER_ID);
    timerManager->ReschedulePowerOnTimerLocked(false);
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime2);

    timerManager->powerOnTriggerTimerList_.clear();
    timerManager->ReschedulePowerOnTimerLocked(false);
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM] >= currentTime + TEN_YEARS_TO_SECOND * SECOND_TO_MILLISECOND,
        true);
}

/**
 * @tc.name: ReschedulePowerOnTimerLocked002
 * @tc.desc: Test ReschedulePowerOnTimerLocked function with multiple timer scenarios with isShutdown false
 * @tc.precon: TimerManager instance is available and lastSetTime can be modified
 * @tc.step: 1. Reset lastSetTime and add timer with 1000ms trigger
 *           2. Add timer with 2000ms trigger and verify scheduling
 *           3. Add timer with 500ms trigger (earliest) and verify rescheduling
 *           4. Remove timers in sequence and verify lastSetTime updates
 *           5. Clear all timers and verify default scheduling
 * @tc.expect: ReschedulePowerOnTimerLocked always schedules the earliest trigger time
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ReschedulePowerOnTimerLocked002, TestSize.Level0)
{
    auto timerManager = TimerManager::GetInstance();
    timerManager->lastSetTime_[POWER_ON_ALARM] = 0;
    int64_t currentTime = 0;
    TimeUtils::GetWallTimeMs(currentTime);
    auto triggerTime1 = currentTime - 1000 + TWO_MINUTES_TO_MILLI;
    auto duration1 = std::chrono::milliseconds(triggerTime1);
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo1 = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration1, timePoint, duration1, timePoint,
        duration1, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo1);
    timerManager->ShutDownReschedulePowerOnTimer();
    EXPECT_GE(timerManager->lastSetTime_[POWER_ON_ALARM], currentTime + TWO_MINUTES_TO_MILLI);
    timerManager->powerOnTriggerTimerList_.clear();

    auto triggerTime2 = currentTime + 1000 + TWO_MINUTES_TO_MILLI;
    auto duration2 = std::chrono::milliseconds(triggerTime2);
    auto timerId2 = TIMER_ID + 1;
    auto timerInfo2 = std::make_shared<TimerInfo>("", timerId2, 0, duration2, timePoint, duration2, timePoint,
        duration2, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo2);
    timerManager->ShutDownReschedulePowerOnTimer();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime2);
    timerManager->powerOnTriggerTimerList_.clear();

    auto triggerTime3 = currentTime + TWO_MINUTES_TO_MILLI;
    auto duration3 = std::chrono::milliseconds(triggerTime3);
    auto timerId3 = timerId2 + 1;
    auto timerInfo3 = std::make_shared<TimerInfo>("", timerId3, 0, duration3, timePoint, duration3, timePoint,
        duration3, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo3);
    timerManager->ShutDownReschedulePowerOnTimer();
    EXPECT_GE(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime3);
}
#endif

/**
 * @tc.name: ResetAllProxy001
 * @tc.desc: Test ResetAllProxy function without required permissions
 * @tc.precon: TimeSystemAbility instance is available and permissions can be removed
 * @tc.step: 1. Remove required permissions using DeletePermission
 *           2. Call ResetAllProxy function
 *           3. Verify function returns permission error
 * @tc.expect: ResetAllProxy returns E_TIME_NO_PERMISSION when permissions are missing
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ResetAllProxy001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
 * @tc.name: ExactRepeatTimer001
 * @tc.desc: Test exact repeat timer handling in HandleRepeatTimer function
 * @tc.precon: TimerManager and TimerProxy instances are available
 * @tc.step: 1. Create repeat timer with 20-second interval
 *           2. Call HandleRepeatTimer with current boot time
 *           3. Verify timer is added to uidTimersMap with correct attributes
 * @tc.expect: Repeat timer is properly registered with equal whenElapsed and maxWhenElapsed times
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ExactRepeatTimer001, TestSize.Level0)
{
    auto windowLength = std::chrono::milliseconds::zero();
    auto interval = std::chrono::milliseconds(20000);
    auto timePoint = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>((timePoint).time_since_epoch());
    auto callback = [this](uint64_t id) -> int32_t {
        return 0;
    };
    auto timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, windowLength, timePoint,
        interval, callback, nullptr, 0, false, UID, PID, "");
    auto bootTime = TimeUtils::GetBootTimeNs();
    TimerManager::GetInstance()->HandleRepeatTimer(timerInfo, bootTime);
    auto uidTimersMap = TimerProxy::GetInstance().uidTimersMap_;
    auto it1 = uidTimersMap.find(UID);
    EXPECT_NE(it1, uidTimersMap.end());
    auto it2 = it1->second.find(TIMER_ID);
    EXPECT_NE(it2, it1->second.end());
    EXPECT_EQ(it2->second->whenElapsed, it2->second->maxWhenElapsed);
}

#ifdef MULTI_ACCOUNT_ENABLE
/**
 * @tc.name: CheckUserIdForNotify001
 * @tc.desc: Test CheckUserIdForNotify function with different user ID values
 * @tc.precon: TimerManager instance is available and multi-account feature is enabled
 * @tc.step: 1. Create timer with invalid user ID (-1)
 *           2. Verify CheckUserIdForNotify returns account error
 *           3. Create timer with valid user ID (0)
 *           4. Verify CheckUserIdForNotify returns success
 * @tc.expect: CheckUserIdForNotify validates user IDs correctly and returns appropriate error codes
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, CheckUserIdForNotify001, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds::zero();
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, false, -1, 0, "");
    auto res = TimerManager::GetInstance()->CheckUserIdForNotify(timerInfo);
    EXPECT_EQ(res, E_TIME_ACCOUNT_ERROR);
    timerInfo = std::make_shared<TimerInfo>("", TIMER_ID, 0, duration, timePoint, duration, timePoint, duration,
                                                 nullptr, nullptr, 0, false, 0, 0, "");
    res = TimerManager::GetInstance()->CheckUserIdForNotify(timerInfo);
    EXPECT_EQ(res, E_TIME_OK);
}
#endif

/**
 * @tc.name: AdjustTimerWithNoPermission001
 * @tc.desc: Test AdjustTimer function without required permissions
 * @tc.precon: TimeSystemAbility instance is available and permissions can be removed
 * @tc.step: 1. Remove required permissions using DeletePermission
 *           2. Call AdjustTimer with adjustment parameters
 *           3. Verify function returns permission error
 * @tc.expect: AdjustTimer returns E_TIME_NO_PERMISSION when permissions are missing
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, AdjustTimerWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->AdjustTimer(false, 0, 0);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
 * @tc.name: ProxyTimerWithNoPermission001
 * @tc.desc: Test ProxyTimer function without required permissions
 * @tc.precon: TimeSystemAbility instance is available and permissions can be removed
 * @tc.step: 1. Remove required permissions using DeletePermission
 *           2. Call ProxyTimer with PID list and parameters
 *           3. Verify function returns permission error
 * @tc.expect: ProxyTimer returns E_TIME_NO_PERMISSION when permissions are missing
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ProxyTimerWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    std::vector<int> pidList{1};
    auto res = TimeSystemAbility::GetInstance()->ProxyTimer(1, pidList, false, false);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
 * @tc.name: SetTimerExemptionWithNoPermission001
 * @tc.desc: Test SetTimerExemption function without required permissions
 * @tc.precon: TimeSystemAbility instance is available and permissions can be removed
 * @tc.step: 1. Remove required permissions using DeletePermission
 *           2. Call SetTimerExemption with timer name array
 *           3. Verify function returns permission error
 * @tc.expect: SetTimerExemption returns E_TIME_NO_PERMISSION when permissions are missing
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, SetTimerExemptionWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    std::vector<std::string> nameArr{"timer"};
    auto res = TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, false);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
 * @tc.name: ResetAllProxyWithNoPermission001
 * @tc.desc: Test ResetAllProxy function without required permissions
 * @tc.precon: TimeSystemAbility instance is available and permissions can be removed
 * @tc.step: 1. Remove required permissions using DeletePermission
 *           2. Call ResetAllProxy function
 *           3. Verify function returns permission error
 * @tc.expect: ResetAllProxy returns E_TIME_NO_PERMISSION when permissions are missing
 * @tc.type: FUNC
 * @tc.require: issue#843
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ResetAllProxyWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}


/**
 * @tc.name: ConvertAdjustPolicy001
 * @tc.desc: Test ConvertAdjustPolicy function without required permissions
 * @tc.precon: TimeSystemAbility instance is available and permissions can be removed
 * @tc.step: 1. Convert adjustment strategy
 * @tc.expect: ConvertAdjustPolicy returns chrono count when the adjustment takes effect
 * @tc.type: FUNC
 * @tc.require: issue#851
 * @tc.level: level0
 */
HWTEST_F(TimeServiceTimerTest, ConvertAdjustPolicy001, TestSize.Level0)
{
    auto zero = milliseconds(0);
    std::chrono::steady_clock::time_point empty (zero);
    auto timerInfo = TimerInfo("", 0, ITimerManager::ELAPSED_REALTIME, zero, empty, zero, empty, zero, nullptr,
                               nullptr, 0, false, 0, 0, "");
    std::chrono::seconds ret = timerInfo.ConvertAdjustPolicy(300, 0);
    EXPECT_TRUE(ret.count() > 0);
    ret = timerInfo.ConvertAdjustPolicy(300, 1);
    EXPECT_FALSE(ret.count() > 0);
    ret = timerInfo.ConvertAdjustPolicy(300, 2);
    EXPECT_TRUE(ret.count() > 0);
    ret = timerInfo.ConvertAdjustPolicy(300, 3);
    EXPECT_TRUE(ret.count() > 0);
}
} // namespace