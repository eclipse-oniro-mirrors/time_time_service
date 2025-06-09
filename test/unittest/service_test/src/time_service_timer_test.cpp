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
#ifdef SET_AUTO_REBOOT_ENABLE
static const int POWER_ON_ALARM = 6;
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
* @tc.desc: Verify the value of newly Batch as expected.
* @tc.type: FUNC
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
* @tc.desc: test OnStop.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility001, TestSize.Level0)
{
    TimeSystemAbility::GetInstance()->OnStop();
    EXPECT_EQ(TimeSystemAbility::GetInstance()->state_, ServiceRunningState::STATE_NOT_START);
}

#ifdef RDB_ENABLE
/**
* @tc.name: SystemAbility002
* @tc.desc: test RecoverTimer.
* @tc.type: FUNC
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

#ifdef SET_AUTO_REBOOT_ENABLE
/**
* @tc.name: SystemAbility003
* @tc.desc: test SetAutoReboot when triggerTime is smaller than currenttime plus 2min.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility003, TestSize.Level0)
{
    uint64_t timerId1 = TIMER_ID;

    TimeSystemAbility::GetInstance()->SetAutoReboot();

    OHOS::NativeRdb::ValuesBucket insertValues1;
    insertValues1.PutLong("timerId", timerId1);
    insertValues1.PutInt("type", 0);
    insertValues1.PutInt("flag", 0);
    insertValues1.PutLong("windowLength", 0);
    insertValues1.PutLong("interval", 0);
    insertValues1.PutInt("uid", 0);
    insertValues1.PutString("bundleName", "anything");
    insertValues1.PutString("wantAgent", "");
    insertValues1.PutInt("state", 1);
    insertValues1.PutLong("triggerTime", static_cast<int64_t>(0));
    auto res = TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues1);
    EXPECT_EQ(res, true);

    TimeSystemAbility::GetInstance()->SetAutoReboot();

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete1(HOLD_ON_REBOOT);
    rdbPredicatesDelete1.EqualTo("timerId", static_cast<int64_t>(timerId1));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete1);
}

/**
* @tc.name: SystemAbility004
* @tc.desc: test SetAutoReboot when triggerTime is larger than currenttime plus 2min.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility004, TestSize.Level0)
{
    uint64_t timerId1 = TIMER_ID;

    TimeSystemAbility::GetInstance()->SetAutoReboot();

    OHOS::NativeRdb::ValuesBucket insertValues1;
    insertValues1.PutLong("timerId", timerId1);
    insertValues1.PutInt("type", 0);
    insertValues1.PutInt("flag", 0);
    insertValues1.PutLong("windowLength", 0);
    insertValues1.PutLong("interval", 0);
    insertValues1.PutInt("uid", 0);
    insertValues1.PutString("bundleName", "anything");
    insertValues1.PutString("wantAgent", "");
    insertValues1.PutInt("state", 1);
    insertValues1.PutLong("triggerTime", std::numeric_limits<int64_t>::max());
    insertValues1.PutString("name", "");
    auto res = TimeDatabase::GetInstance().Insert(HOLD_ON_REBOOT, insertValues1);
    EXPECT_EQ(res, true);

    TimeSystemAbility::GetInstance()->SetAutoReboot();

    OHOS::NativeRdb::RdbPredicates rdbPredicatesDelete1(HOLD_ON_REBOOT);
    rdbPredicatesDelete1.EqualTo("timerId", static_cast<int64_t>(timerId1));
    TimeDatabase::GetInstance().Delete(rdbPredicatesDelete1);
}
#endif

/**
* @tc.name: SystemAbility005
* @tc.desc: Verify set negative value by SetRealTime will return false.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, SystemAbility005, TestSize.Level0)
{
    auto res = TimeSystemAbility::GetInstance()->SetRealTime(-1);
    EXPECT_FALSE(res);
}

#ifdef RDB_ENABLE
/**
* @tc.name: TimeDatabase001
* @tc.desc: test TimeDatabase Insert.
* @tc.type: FUNC
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
* @tc.desc: test TimeDatabase Update.
* @tc.type: FUNC
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
* @tc.desc: test TimeDatabase Delete.
* @tc.type: FUNC
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
* @tc.desc: Test Delete of CjsonHelper.
* @tc.type: FUNC
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
* @tc.desc: Test clear of CjsonHelper.
* @tc.type: FUNC
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
* @tc.desc: Test QueryTable of cjson.
* @tc.type: FUNC
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
* @tc.desc: Test QueryWant of cjson.
* @tc.type: FUNC
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
* @tc.desc: Test QueryAutoReboot of cjson.
* @tc.type: FUNC
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
* @tc.desc: Test GetEntry will return nullptr when cjson is incomplete and invalid.
* @tc.type: FUNC
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
* @tc.desc: Test GetEntry will return nullptr when cjson is complete and valid.
* @tc.type: FUNC
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
* @tc.desc: Test CjsonIntoDatabase.
* @tc.type: FUNC
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
* @tc.desc: proxy timer.
* @tc.type: FUNC
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
* @tc.desc: proxy timer.
* @tc.type: FUNC
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
* @tc.desc: proxy timer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, PidProxyTimer003, TestSize.Level0)
{
    auto ret = TimeServiceClient::GetInstance()->ProxyTimer(RESERVED_UID, RESERVED_PIDLIST, false, true);
    EXPECT_FALSE(ret);
}

/**
* @tc.name: PidProxyTimer004
* @tc.desc: proxy timer.
* @tc.type: FUNC
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
* @tc.desc: adjust timer.
* @tc.type: FUNC
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
* @tc.desc: Check AdjustTimer.
* @tc.type: FUNC
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
* @tc.desc: exemption timer.
* @tc.type: FUNC
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
* @tc.desc: Verify SetTimerExemption will return PARAMETERS_INVALID when nameArr is larger than MAX_EXEMPTION_SIZE.
* @tc.type: FUNC
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
* @tc.desc: Verify ProxyTimer will return PARAMETERS_INVALID when pidList is larger than MAX_PID_LIST_SIZE.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, ProxyTimer001, TestSize.Level1)
{
    std::vector<int> pidList{};
    auto res = TimeSystemAbility::GetInstance()->ProxyTimer(0, pidList, false, false);
    EXPECT_EQ(res, E_TIME_PARAMETERS_INVALID);
    for (int i = 0; i <= MAX_PID_LIST_SIZE + 1; i++) {
        pidList.push_back(0);
    }
    res = TimeSystemAbility::GetInstance()->ProxyTimer(0, pidList, false, false);
    EXPECT_EQ(res, E_TIME_PARAMETERS_INVALID);
}

/**
* @tc.name: IdleTimer001
* @tc.desc: test create idle timer for app.
* @tc.type: FUNC
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
* @tc.desc: test public app start timer when device is sleeping and device sleep quit greater than timer callback.
* @tc.type: FUNC
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
* @tc.desc: test public app start timer when device is sleeping and device sleep quit less than timer callback.
* @tc.type: FUNC
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
* @tc.desc: test public app start timer when device is working, device sleep immediately
*           and timer callback greater than idle quit.
* @tc.type: FUNC
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
* @tc.desc: Create system timer.
* @tc.type: FUNC
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
* @tc.desc: Create system timer.
* @tc.type: FUNC
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
* @tc.desc: Create system timer.
* @tc.type: FUNC
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
* @tc.desc: Create system timer.
* @tc.type: FUNC
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
* @tc.desc: Create system timer.
* @tc.type: FUNC
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
* @tc.desc: Create system timer.
* @tc.type: FUNC
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
* @tc.desc: Create system timer with TIMER_TYPE_EXACT, then start timer with uint64_t::max.
* @tc.type: FUNC
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
* @tc.desc: Create system timer with TIMER_TYPE_REALTIME and TIMER_TYPE_EXACT, then start timer with uint64_t::max.
* @tc.type: FUNC
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
* @tc.desc: Create system timer start with one day later, then setTime to one day later.
* @tc.type: FUNC
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
 * @tc.desc: Create system timer.
 * @tc.type: FUNC
 */
HWTEST_F(TimeServiceTimerTest, CreateTimer010, TestSize.Level1) {
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
 * @tc.desc: Create system timer.
 * @tc.type: FUNC
 */
HWTEST_F(TimeServiceTimerTest, CreateTimer011, TestSize.Level1) {
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
* @tc.desc: test ReCreateTimer.
* @tc.type: FUNC
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
* @tc.desc: test SetHandler with interval = milliseconds(10) < second(1).
* @tc.type: FUNC
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
* @tc.desc: test Set() with type > ALARM_TYPE_COUNT.
* @tc.type: FUNC
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
* @tc.desc: test StartTimer with UidProxy and PidProxy.
* @tc.type: FUNC
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
* @tc.desc: test NotifyWantAgent.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, TimerManager005, TestSize.Level0)
{
    TimerManager::GetInstance()->NotifyWantAgentRetry(nullptr);

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
* @tc.desc: test AdjustTimer.
* @tc.type: FUNC
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
* @tc.desc: test AdjustDeliveryTimeBasedOnDeviceIdle.
* @tc.type: FUNC
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
* @tc.desc: test ShowTimerEntryById TIMER_ID not in timerEntryMap_.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, TimerManager008, TestSize.Level0)
{
    TimerManager::GetInstance()->DestroyTimer(TIMER_ID);

    auto res = TimerManager::GetInstance()->ShowTimerEntryById(0, TIMER_ID);
    EXPECT_FALSE(res);
}

/**
* @tc.name: TimerManager009.
* @tc.desc: test ShowTimerTriggerById TIMER_ID in alarmBatches_.
* @tc.type: FUNC
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
* @tc.desc: test HandleRSSDeath.
* @tc.type: FUNC
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
* @tc.desc: test OnPackageRemoved.
* @tc.type: FUNC
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
* @tc.desc: test record and delete of timerCount_.
* @tc.type: FUNC
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
* @tc.desc: test when create and delete timer, the change of timerOutOfRangeTimes_.
* @tc.type: FUNC
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
* @tc.desc: test create two timer with same name.
* @tc.type: FUNC
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
* @tc.desc: test check timer.
* @tc.type: FUNC
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
* @tc.desc: test update or delete database.
* @tc.type: FUNC
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
* @tc.desc: test timer database when store is nullptr.
* @tc.type: FUNC
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
* @tc.desc: test UpdateWhenElapsedFromNow.
* @tc.type: FUNC
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
* @tc.desc: test AdjustTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, TimerInfo002, TestSize.Level0)
{
    auto duration = std::chrono::milliseconds(0);
    auto timePoint = std::chrono::steady_clock::now();
    auto timerInfo = TimerInfo("", 0, 0, duration, timePoint, duration, timePoint, duration, nullptr,
                                          nullptr, 0, false, 0, 0, "");
    auto res = timerInfo.AdjustTimer(timePoint, 1, 0);
    EXPECT_TRUE(res);
}

/**
* @tc.name: TimerInfo003
* @tc.desc: test CreateTimerInfo.
* @tc.type: FUNC
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
* @tc.desc: test MaxTriggerTime.
* @tc.type: FUNC
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
* @tc.desc: test ConvertToElapsed.
* @tc.type: FUNC
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
* @tc.desc: test CalculateWhenElapsed.
* @tc.type: FUNC
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
* @tc.desc: test CalculateOriWhenElapsed.
* @tc.type: FUNC
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
* @tc.desc: test ProxyTimer.
* @tc.type: FUNC
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
* @tc.desc: test RestoreProxyTimer.
* @tc.type: FUNC
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

#ifdef SET_AUTO_REBOOT_ENABLE
/**
* @tc.name: IsPowerOnTimer001.
* @tc.desc: Test function IsPowerOnTimer, use four timer to check the return of function.
* @tc.type: FUNC
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
* @tc.name: DeleteTimerFromPowerOnTimerListById001.
* @tc.desc: Test function ReschedulePowerOnTimer, check delete a timer in powerOnTriggerTimerList_ by timer id.
* @tc.type: FUNC
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
* @tc.name: ReschedulePowerOnTimerLocked001.
* @tc.desc: Test function ReschedulePowerOnTimer, use three timer to test the schedule.
* @tc.type: FUNC
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
    timerManager->ReschedulePowerOnTimerLocked();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime1);

    auto triggerTime2 = currentTime + 2000;
    auto duration2 = std::chrono::milliseconds(triggerTime2);
    auto timerId2 = TIMER_ID + 1;
    auto timerInfo2 = std::make_shared<TimerInfo>("", timerId2, 0, duration2, timePoint, duration2, timePoint,
        duration2, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo2);
    timerManager->ReschedulePowerOnTimerLocked();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime1);

    auto triggerTime3 = currentTime + 500;
    auto duration3 = std::chrono::milliseconds(triggerTime3);
    auto timerId3 = timerId2 + 1;
    auto timerInfo3 = std::make_shared<TimerInfo>("", timerId3, 0, duration3, timePoint, duration3, timePoint,
        duration3, nullptr, nullptr, 0, false, 0, 0, "");
    timerManager->powerOnTriggerTimerList_.push_back(timerInfo3);
    timerManager->ReschedulePowerOnTimerLocked();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime3);

    timerManager->DeleteTimerFromPowerOnTimerListById(timerId3);
    timerManager->ReschedulePowerOnTimerLocked();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime1);

    timerManager->DeleteTimerFromPowerOnTimerListById(TIMER_ID);
    timerManager->ReschedulePowerOnTimerLocked();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], triggerTime2);

    timerManager->powerOnTriggerTimerList_.clear();
    timerManager->ReschedulePowerOnTimerLocked();
    EXPECT_EQ(timerManager->lastSetTime_[POWER_ON_ALARM], 0);
}
#endif

/**
* @tc.name: ResetAllProxy001.
* @tc.desc: test RefreshNetworkTimeByTimer.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, ResetAllProxy001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: ExactRepeatTimer001.
* @tc.desc: test exact & repeat tiemr.
* @tc.type: FUNC
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
* @tc.desc: test CheckUserIdForNotify.
* @tc.type: FUNC
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
* @tc.desc: Verify AdjustTimer with no permission.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, AdjustTimerWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->AdjustTimer(false, 0, 0);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name:ProxyTimerWithNoPermission001
* @tc.desc: Verify ProxyTimer with no permission.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, ProxyTimerWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    std::vector<int> pidList{1};
    auto res = TimeSystemAbility::GetInstance()->ProxyTimer(1, pidList, false, false);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: SetTimerExemptionyWithNoPermission001
* @tc.desc: Verify SetTimerExemption with no permission.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, SetTimerExemptionWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    std::vector<std::string> nameArr{"timer"};
    auto res = TimeSystemAbility::GetInstance()->SetTimerExemption(nameArr, false);
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}

/**
* @tc.name: ResetAllProxyWithNoPermission004.
* @tc.desc: Verify ResetAllProxy with no permission.
* @tc.type: FUNC
*/
HWTEST_F(TimeServiceTimerTest, ResetAllProxyWithNoPermission001, TestSize.Level0)
{
    DeletePermission();
    auto res = TimeSystemAbility::GetInstance()->ResetAllProxy();
    EXPECT_EQ(res, E_TIME_NO_PERMISSION);
}
} // namespace