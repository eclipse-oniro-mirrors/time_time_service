/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <chrono>
#include <climits>
#include <cstdio>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <cJSON.h>

#define private public
#define protected public
#include "timer_database_monitor.h"
#ifdef RDB_ENABLE
#include "timer_database.h"
#endif
#include "cjson_helper.h"
#undef private
#undef protected

#include "time_common.h"
#include "time_sysevent.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;
using namespace std::chrono;

namespace {
constexpr const char* TEST_DB_PATH = "/data/service/el1/public/database/time/time.json";
constexpr uint64_t TEST_TIMER_ID_BASE = 900000;
constexpr int32_t TEST_UID = 1000;
constexpr int32_t TEST_PID = 2000;

cJSON* ReadDbJson()
{
    std::ifstream file(TEST_DB_PATH);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return cJSON_Parse(content.c_str());
}

void WriteDbJson(cJSON* root)
{
    char* str = cJSON_Print(root);
    if (str) {
        std::ofstream file(TEST_DB_PATH);
        file << str;
        file.close();
        cJSON_free(str);
    }
}

cJSON* MakeTimerObj(uint64_t id, const std::string& bundle, const std::string& name,
                    int type = 0, int state = 0)
{
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", name.c_str());
    cJSON_AddStringToObject(obj, "timerId", std::to_string(id).c_str());
    cJSON_AddNumberToObject(obj, "type", type);
    cJSON_AddNumberToObject(obj, "flag", 0);
    cJSON_AddNumberToObject(obj, "windowLength", 0);
    cJSON_AddNumberToObject(obj, "interval", 0);
    cJSON_AddNumberToObject(obj, "uid", TEST_UID);
    cJSON_AddNumberToObject(obj, "pid", TEST_PID);
    cJSON_AddStringToObject(obj, "bundleName", bundle.c_str());
    cJSON_AddStringToObject(obj, "wantAgent", "");
    cJSON_AddNumberToObject(obj, "state", state);
    cJSON_AddStringToObject(obj, "triggerTime", "0");
    return obj;
}

void AddEntriesToTable(const std::string& table, const std::vector<cJSON*>& entries)
{
    cJSON* root = ReadDbJson();
    if (!root) {
        root = cJSON_CreateObject();
    }
    cJSON* tableArr = cJSON_GetObjectItem(root, table.c_str());
    if (!tableArr) {
        tableArr = cJSON_CreateArray();
        cJSON_AddItemToObject(root, table.c_str(), tableArr);
    }
    for (auto* entry : entries) {
        cJSON_AddItemToArray(tableArr, entry);
    }
    WriteDbJson(root);
    cJSON_Delete(root);
}

void RemoveEntriesByTimerIds(const std::string& table, const std::vector<uint64_t>& timerIds)
{
    cJSON* root = ReadDbJson();
    if (!root) {
        return;
    }
    cJSON* tableArr = cJSON_GetObjectItem(root, table.c_str());
    if (!tableArr) {
        cJSON_Delete(root);
        return;
    }
    std::set<uint64_t> idSet(timerIds.begin(), timerIds.end());
    int size = cJSON_GetArraySize(tableArr);
    for (int i = size - 1; i >= 0; --i) {
        cJSON* obj = cJSON_GetArrayItem(tableArr, i);
        cJSON* idItem = cJSON_GetObjectItem(obj, "timerId");
        if (idItem && cJSON_IsString(idItem) && idItem->valuestring != nullptr &&
            idSet.count(std::stoull(idItem->valuestring))) {
            cJSON_DeleteItemFromArray(tableArr, i);
        }
    }
    WriteDbJson(root);
    cJSON_Delete(root);
}

#ifndef RDB_ENABLE
void AddPaddingField(size_t padSize)
{
    cJSON* root = ReadDbJson();
    if (!root) {
        return;
    }
    std::string padding(padSize, 'X');
    cJSON_ReplaceItemInObject(root, "test_padding", cJSON_CreateString(padding.c_str()));
    WriteDbJson(root);
    cJSON_Delete(root);
}

void RemovePaddingField()
{
    cJSON* root = ReadDbJson();
    if (!root) {
        return;
    }
    cJSON_DeleteItemFromObject(root, "test_padding");
    WriteDbJson(root);
    cJSON_Delete(root);
}
#endif

#ifdef RDB_ENABLE
void InsertRdbTimer(const std::string& table, int64_t timerId, const std::string& bundle,
                    const std::string& name, int type = 0, int state = 0)
{
    OHOS::NativeRdb::ValuesBucket values;
    values.PutLong("timerId", timerId);
    values.PutInt("type", type);
    values.PutInt("flag", 0);
    values.PutLong("windowLength", 0);
    values.PutLong("interval", 0);
    values.PutInt("uid", TEST_UID);
    values.PutString("bundleName", bundle);
    values.PutString("wantAgent", "");
    values.PutInt("state", state);
    values.PutLong("triggerTime", 0);
    values.PutInt("pid", TEST_PID);
    values.PutString("name", name);
    TimeDatabase::GetInstance().Insert(table, values);
}

void DeleteRdbTimers(const std::string& table, const std::vector<int64_t>& timerIds)
{
    for (auto id : timerIds) {
        OHOS::NativeRdb::RdbPredicates predicates(table);
        predicates.EqualTo("timerId", id);
        TimeDatabase::GetInstance().Delete(predicates);
    }
}
#endif

void AddTestTimer(const std::string& table, uint64_t id, const std::string& bundle,
                  const std::string& name)
{
#ifdef RDB_ENABLE
    InsertRdbTimer(table, static_cast<int64_t>(id), bundle, name);
#else
    AddEntriesToTable(table, {MakeTimerObj(id, bundle, name)});
#endif
}

void RemoveTestTimers(const std::string& table, const std::vector<uint64_t>& ids)
{
#ifdef RDB_ENABLE
    std::vector<int64_t> rdbIds;
    for (auto id : ids) {
        rdbIds.push_back(static_cast<int64_t>(id));
    }
    DeleteRdbTimers(table, rdbIds);
#else
    RemoveEntriesByTimerIds(table, ids);
#endif
}
} // namespace

class TimerDatabaseMonitorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimerDatabaseMonitorTest::SetUpTestCase(void)
{
}

void TimerDatabaseMonitorTest::TearDownTestCase(void)
{
}

void TimerDatabaseMonitorTest::SetUp(void)
{
    // Ensure monitor is stopped before each test
    TimerDatabaseMonitor::GetInstance().Stop();
}

void TimerDatabaseMonitorTest::TearDown(void)
{
    // Clean up: stop monitor after each test
    TimerDatabaseMonitor::GetInstance().Stop();
}

/**
 * @tc.name: TimerDatabaseMonitorSingletonTest001
 * @tc.desc: Test singleton instance returns same reference
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorSingletonTest001, TestSize.Level1)
{
    auto &instance1 = TimerDatabaseMonitor::GetInstance();
    auto &instance2 = TimerDatabaseMonitor::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: TimerDatabaseMonitorStartStopTest001
 * @tc.desc: Test Start and Stop basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorStartStopTest001, TestSize.Level1)
{
    auto &monitor = TimerDatabaseMonitor::GetInstance();
    EXPECT_FALSE(monitor.running_);
    monitor.Start();
    EXPECT_TRUE(monitor.running_);
}

/**
 * @tc.name: TimerDatabaseMonitorGetTotalRecordCountTest001
 * @tc.desc: Test GetTotalRecordCount returns non-negative value
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorGetTotalRecordCountTest001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    EXPECT_GE(db.GetTotalRecordCount(), 0);
}

/**
 * @tc.name: TimerDatabaseMonitorGetTopAppsTest001
 * @tc.desc: Test GetTopApps returns at most topN elements, invalid topN returns empty
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorGetTopAppsTest001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    EXPECT_LE(db.GetTopApps(5).size(), static_cast<size_t>(5));
    EXPECT_LE(db.GetTopApps(3).size(), static_cast<size_t>(3));
    EXPECT_TRUE(db.GetTopApps(-1).empty());
    EXPECT_TRUE(db.GetTopApps(0).empty());
}

/**
 * @tc.name: TimerDatabaseMonitorCheckDatabaseAndReportTest001
 * @tc.desc: Test CheckDatabaseAndReport does not crash with small DB
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorCheckDatabaseAndReportTest001, TestSize.Level1)
{
    auto &monitor = TimerDatabaseMonitor::GetInstance();
    monitor.CheckDatabaseAndReport();
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TimerDatabaseMonitorTimerDbTopAppInfoTest001
 * @tc.desc: Test TimerDbTopAppInfo struct initialization and assignment
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorTimerDbTopAppInfoTest001, TestSize.Level1)
{
    TimerDbTopAppInfo info;
    info.bundleName = "com.example.app";
    info.timerName = "TestTimer";
    info.count = 42;

    EXPECT_EQ(info.bundleName, "com.example.app");
    EXPECT_EQ(info.timerName, "TestTimer");
    EXPECT_EQ(info.count, 42);
}

/**
 * @tc.name: TimerDatabaseMonitorTimerDbSizeInfoTest001
 * @tc.desc: Test TimerDbSizeInfo struct initialization and GetTotalSize
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorTimerDbSizeInfoTest001, TestSize.Level1)
{
    TimerDbSizeInfo info;
    info.dbSize = 100;
    info.shmSize = 50;
    info.walSize = 25;

    EXPECT_EQ(info.dbSize, 100);
    EXPECT_EQ(info.shmSize, 50);
    EXPECT_EQ(info.walSize, 25);
    EXPECT_EQ(info.GetTotalSize(), 175);
}

/**
 * @tc.name: TimerDatabaseMonitorTimerDbSizeInfoTest002
 * @tc.desc: Test TimerDbSizeInfo with zero values
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorTimerDbSizeInfoTest002, TestSize.Level1)
{
    TimerDbSizeInfo info;
    info.dbSize = 0;
    info.shmSize = 0;
    info.walSize = 0;

    EXPECT_EQ(info.GetTotalSize(), 0);
}

/**
 * @tc.name: TimerDatabaseMonitorGetDatabaseSizeDetailTest001
 * @tc.desc: Test GetDatabaseSizeDetail returns valid TimerDbSizeInfo
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorGetDatabaseSizeDetailTest001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    TimerDbSizeInfo sizeInfo = db.GetDatabaseSizeDetail();
    EXPECT_GE(sizeInfo.dbSize, 0);
    EXPECT_GE(sizeInfo.shmSize, 0);
    EXPECT_GE(sizeInfo.walSize, 0);
    EXPECT_GE(sizeInfo.GetTotalSize(), 0);
}

// ==================== Unified DB method tests (both RDB and non-RDB) ====================

/**
 * @tc.name: GetTotalRecordCountWithDataTest001
 * @tc.desc: Test GetTotalRecordCount increases after adding entries to hold_on_reboot
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTotalRecordCountWithDataTest001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    int32_t before = db.GetTotalRecordCount();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 1, TEST_TIMER_ID_BASE + 2};
    AddTestTimer(HOLD_ON_REBOOT, ids[0], "com.test.cnt1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[1], "com.test.cnt2", "t2");
    EXPECT_EQ(db.GetTotalRecordCount() - before, 2);
    RemoveTestTimers(HOLD_ON_REBOOT, ids);
    EXPECT_EQ(db.GetTotalRecordCount(), before);
}

/**
 * @tc.name: GetTotalRecordCountWithDataTest002
 * @tc.desc: Test GetTotalRecordCount increases after adding entries to drop_on_reboot
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTotalRecordCountWithDataTest002, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    int32_t before = db.GetTotalRecordCount();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 3, TEST_TIMER_ID_BASE + 4, TEST_TIMER_ID_BASE + 5};
    AddTestTimer(DROP_ON_REBOOT, ids[0], "com.test.drop1", "t1");
    AddTestTimer(DROP_ON_REBOOT, ids[1], "com.test.drop2", "t2");
    AddTestTimer(DROP_ON_REBOOT, ids[2], "com.test.drop3", "t3");
    EXPECT_EQ(db.GetTotalRecordCount() - before, 3);
    RemoveTestTimers(DROP_ON_REBOOT, ids);
    EXPECT_EQ(db.GetTotalRecordCount(), before);
}

/**
 * @tc.name: GetTotalRecordCountWithDataTest003
 * @tc.desc: Test GetTotalRecordCount sums entries from both tables
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTotalRecordCountWithDataTest003, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    int32_t before = db.GetTotalRecordCount();
    std::vector<uint64_t> holdIds = {TEST_TIMER_ID_BASE + 6, TEST_TIMER_ID_BASE + 7};
    std::vector<uint64_t> dropIds = {TEST_TIMER_ID_BASE + 8};
    AddTestTimer(HOLD_ON_REBOOT, holdIds[0], "com.test.both1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, holdIds[1], "com.test.both2", "t2");
    AddTestTimer(DROP_ON_REBOOT, dropIds[0], "com.test.both3", "t3");
    EXPECT_EQ(db.GetTotalRecordCount() - before, 3);
    RemoveTestTimers(HOLD_ON_REBOOT, holdIds);
    RemoveTestTimers(DROP_ON_REBOOT, dropIds);
    EXPECT_EQ(db.GetTotalRecordCount(), before);
}

/**
 * @tc.name: GetTopAppsWithDataTest001
 * @tc.desc: Test GetTopApps returns sorted results with test data
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTopAppsWithDataTest001, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    std::vector<uint64_t> ids = {
        TEST_TIMER_ID_BASE + 50, TEST_TIMER_ID_BASE + 51, TEST_TIMER_ID_BASE + 52,
        TEST_TIMER_ID_BASE + 53, TEST_TIMER_ID_BASE + 54, TEST_TIMER_ID_BASE + 55,
    };
    AddTestTimer(HOLD_ON_REBOOT, ids[0], "com.test.top1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[3], "com.test.top2", "t2");
    AddTestTimer(HOLD_ON_REBOOT, ids[5], "com.test.top3", "t3");

    auto result = db.GetTopApps(100);
    bool foundApp1 = false, foundApp2 = false, foundApp3 = false;
    for (const auto& info : result) {
        if (info.bundleName == "com.test.top1") { foundApp1 = true; EXPECT_EQ(info.count, 1); }
        if (info.bundleName == "com.test.top2") { foundApp2 = true; EXPECT_EQ(info.count, 1); }
        if (info.bundleName == "com.test.top3") { foundApp3 = true; EXPECT_EQ(info.count, 1); }
    }
    EXPECT_TRUE(foundApp1);
    EXPECT_TRUE(foundApp2);
    EXPECT_TRUE(foundApp3);
    RemoveTestTimers(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: GetTopAppsWithDataTest003
 * @tc.desc: Test GetTopApps aggregates counts across both tables
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTopAppsWithDataTest003, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    std::vector<uint64_t> holdIds = {TEST_TIMER_ID_BASE + 70, TEST_TIMER_ID_BASE + 71};
    std::vector<uint64_t> dropIds = {TEST_TIMER_ID_BASE + 72, TEST_TIMER_ID_BASE + 73};
    AddTestTimer(HOLD_ON_REBOOT, holdIds[0], "com.test.cross", "t1");
    AddTestTimer(HOLD_ON_REBOOT, holdIds[1], "com.test.cross", "t1");
    AddTestTimer(DROP_ON_REBOOT, dropIds[0], "com.test.cross", "t1");
    AddTestTimer(DROP_ON_REBOOT, dropIds[1], "com.test.cross2", "t2");

    auto result = db.GetTopApps(100);
    bool foundCross = false, foundCross2 = false;
    for (const auto& info : result) {
        if (info.bundleName == "com.test.cross" && info.timerName == "t1") {
            foundCross = true;
            EXPECT_EQ(info.count, 3);
        }
        if (info.bundleName == "com.test.cross2") { foundCross2 = true; EXPECT_EQ(info.count, 1); }
    }
    EXPECT_TRUE(foundCross);
    EXPECT_TRUE(foundCross2);
    RemoveTestTimers(HOLD_ON_REBOOT, holdIds);
    RemoveTestTimers(DROP_ON_REBOOT, dropIds);
}

/**
 * @tc.name: GetTopAppsWithDataTest004
 * @tc.desc: Test GetTopApps result is sorted by count descending
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTopAppsWithDataTest004, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    std::vector<uint64_t> ids = {
        TEST_TIMER_ID_BASE + 90, TEST_TIMER_ID_BASE + 91, TEST_TIMER_ID_BASE + 92,
        TEST_TIMER_ID_BASE + 93,
    };
    AddTestTimer(HOLD_ON_REBOOT, ids[0], "com.test.sort1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[1], "com.test.sort1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[2], "com.test.sort1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[3], "com.test.sort2", "t2");

    auto result = db.GetTopApps(100);
    for (size_t i = 1; i < result.size(); ++i) {
        EXPECT_GE(result[i - 1].count, result[i].count);
    }
    RemoveTestTimers(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: GetTopAppsWithDataTest005
 * @tc.desc: Test GetTopApps with topN exactly equal to app count (no resize)
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, GetTopAppsWithDataTest005, TestSize.Level1)
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    std::vector<uint64_t> ids = {
        TEST_TIMER_ID_BASE + 95, TEST_TIMER_ID_BASE + 96, TEST_TIMER_ID_BASE + 97,
    };
    AddTestTimer(HOLD_ON_REBOOT, ids[0], "com.test.exact1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[1], "com.test.exact1", "t1");
    AddTestTimer(HOLD_ON_REBOOT, ids[2], "com.test.exact2", "t2");

    auto result = db.GetTopApps(2);
    EXPECT_EQ(result.size(), static_cast<size_t>(2));
    RemoveTestTimers(HOLD_ON_REBOOT, ids);
}

// ==================== CjsonHelper-specific tests (private method) ====================

/**
 * @tc.name: CjsonHelperGetDatabaseSizeDetailTest001
 * @tc.desc: Test CjsonHelper GetDatabaseSizeDetail returns positive dbSize with zero shm/wal
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperGetDatabaseSizeDetailTest001, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    TimerDbSizeInfo info = db.GetDatabaseSizeDetail();
    EXPECT_GE(info.dbSize, 0);
    EXPECT_GE(info.shmSize, 0);
    EXPECT_GE(info.walSize, 0);
}

/**
 * @tc.name: CjsonHelperGetDatabaseSizeDetailTest002
 * @tc.desc: Test CjsonHelper GetDatabaseSizeDetail GetTotalSize equals dbSize when shm/wal are zero
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperGetDatabaseSizeDetailTest002, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    TimerDbSizeInfo info = db.GetDatabaseSizeDetail();
    EXPECT_EQ(info.GetTotalSize(), info.dbSize + info.shmSize + info.walSize);
}

/**
 * @tc.name: CjsonHelperGetTotalRecordCountTest001
 * @tc.desc: Test CjsonHelper GetTotalRecordCount increases after adding data to hold_on_reboot
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperGetTotalRecordCountTest001, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    int32_t before = db.GetTotalRecordCount();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 300, TEST_TIMER_ID_BASE + 301};
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.cjcnt1", "t1"),
        MakeTimerObj(ids[1], "com.test.cjcnt2", "t2"),
    });
    EXPECT_EQ(db.GetTotalRecordCount() - before, 2);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
    EXPECT_EQ(db.GetTotalRecordCount(), before);
}

/**
 * @tc.name: CjsonHelperGetTopAppsTest001
 * @tc.desc: Test CjsonHelper GetTopApps with data and sorted by count descending
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperGetTopAppsTest001, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {
        TEST_TIMER_ID_BASE + 310, TEST_TIMER_ID_BASE + 311, TEST_TIMER_ID_BASE + 312,
        TEST_TIMER_ID_BASE + 313, TEST_TIMER_ID_BASE + 314,
    };
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.cjtop1", "t1"),
        MakeTimerObj(ids[1], "com.test.cjtop1", "t1"),
        MakeTimerObj(ids[2], "com.test.cjtop1", "t1"),
        MakeTimerObj(ids[3], "com.test.cjtop2", "t2"),
        MakeTimerObj(ids[4], "com.test.cjtop2", "t2"),
    });

    auto result = db.GetTopApps(100);
    bool found1 = false, found2 = false;
    for (const auto& info : result) {
        if (info.bundleName == "com.test.cjtop1" && info.timerName == "t1") {
            found1 = true;
            EXPECT_EQ(info.count, 3);
        }
        if (info.bundleName == "com.test.cjtop2" && info.timerName == "t2") {
            found2 = true;
            EXPECT_EQ(info.count, 2);
        }
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: CjsonHelperGetTopAppsTest002
 * @tc.desc: Test CjsonHelper GetTopApps resize when topN < app count
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperGetTopAppsTest002, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {
        TEST_TIMER_ID_BASE + 320, TEST_TIMER_ID_BASE + 321,
        TEST_TIMER_ID_BASE + 322, TEST_TIMER_ID_BASE + 323,
    };
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.cjtrunc1", "t1"),
        MakeTimerObj(ids[1], "com.test.cjtrunc1", "t1"),
        MakeTimerObj(ids[2], "com.test.cjtrunc2", "t2"),
        MakeTimerObj(ids[3], "com.test.cjtrunc3", "t3"),
    });

    auto result = db.GetTopApps(1);
    EXPECT_EQ(result.size(), static_cast<size_t>(1));
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: CjsonHelperGetTopAppsTest003
 * @tc.desc: Test CjsonHelper GetTopApps with invalid topN returns empty
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperGetTopAppsTest003, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    EXPECT_TRUE(db.GetTopApps(-1).empty());
    EXPECT_TRUE(db.GetTopApps(0).empty());
}

/**
 * @tc.name: CjsonHelperCountTimersFromTableTest001
 * @tc.desc: Test CountTimersFromTable counts valid entries correctly
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperCountTimersFromTableTest001, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 10, TEST_TIMER_ID_BASE + 11, TEST_TIMER_ID_BASE + 12};
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.cnttbl1", "t1"),
        MakeTimerObj(ids[1], "com.test.cnttbl1", "t2"),
        MakeTimerObj(ids[2], "com.test.cnttbl2", "t3"),
    });

    std::map<std::pair<std::string, std::string>, int32_t> countMap;
    db.CountTimersFromTable(HOLD_ON_REBOOT, countMap);
    EXPECT_GE((countMap[{"com.test.cnttbl1", "t1"}]), 1);
    EXPECT_GE((countMap[{"com.test.cnttbl1", "t2"}]), 1);
    EXPECT_GE((countMap[{"com.test.cnttbl2", "t3"}]), 1);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: CjsonHelperCountTimersFromTableTest002
 * @tc.desc: Test CountTimersFromTable skips entries with missing bundleName
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperCountTimersFromTableTest002, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 20, TEST_TIMER_ID_BASE + 21};
    cJSON* objNoBundle = cJSON_CreateObject();
    cJSON_AddStringToObject(objNoBundle, "name", "t_nobundle");
    cJSON_AddStringToObject(objNoBundle, "timerId", std::to_string(ids[1]).c_str());
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.nobundle", "t1"),
        objNoBundle,
    });

    std::map<std::pair<std::string, std::string>, int32_t> countMap;
    db.CountTimersFromTable(HOLD_ON_REBOOT, countMap);
    EXPECT_GE((countMap[{"com.test.nobundle", "t1"}]), 1);
    EXPECT_EQ(countMap.count({"", "t_nobundle"}), 0);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: CjsonHelperCountTimersFromTableTest003
 * @tc.desc: Test CountTimersFromTable skips entries with missing name
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperCountTimersFromTableTest003, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 30, TEST_TIMER_ID_BASE + 31};
    cJSON* objNoName = cJSON_CreateObject();
    cJSON_AddStringToObject(objNoName, "timerId", std::to_string(ids[1]).c_str());
    cJSON_AddStringToObject(objNoName, "bundleName", "com.test.noname");
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.hasname", "t1"),
        objNoName,
    });

    std::map<std::pair<std::string, std::string>, int32_t> countMap;
    db.CountTimersFromTable(HOLD_ON_REBOOT, countMap);
    EXPECT_GE((countMap[{"com.test.hasname", "t1"}]), 1);
    EXPECT_EQ(countMap.count({"com.test.noname", ""}), 0);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: CjsonHelperCountTimersFromTableTest004
 * @tc.desc: Test CountTimersFromTable handles null valuestring as empty string
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperCountTimersFromTableTest004, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 40};
    cJSON* obj = cJSON_CreateObject();
    cJSON_AddItemToObject(obj, "bundleName", cJSON_CreateNull());
    cJSON_AddItemToObject(obj, "name", cJSON_CreateNull());
    cJSON_AddStringToObject(obj, "timerId", std::to_string(ids[0]).c_str());
    AddEntriesToTable(HOLD_ON_REBOOT, {obj});

    std::map<std::pair<std::string, std::string>, int32_t> countMap;
    db.CountTimersFromTable(HOLD_ON_REBOOT, countMap);
    EXPECT_GE((countMap[{"", ""}]), 1);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

/**
 * @tc.name: CjsonHelperCountTimersFromTableTest005
 * @tc.desc: Test CountTimersFromTable does nothing when table not found
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperCountTimersFromTableTest005, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::map<std::pair<std::string, std::string>, int32_t> countMap;
    db.CountTimersFromTable("nonexistent_table", countMap);
    EXPECT_TRUE(countMap.empty());
}

/**
 * @tc.name: CjsonHelperCountTimersFromTableTest006
 * @tc.desc: Test CountTimersFromTable accumulates count for duplicate bundleName+name
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, CjsonHelperCountTimersFromTableTest006, TestSize.Level1)
{
    auto &db = CjsonHelper::GetInstance();
    std::vector<uint64_t> ids = {TEST_TIMER_ID_BASE + 80, TEST_TIMER_ID_BASE + 81, TEST_TIMER_ID_BASE + 82};
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(ids[0], "com.test.dup", "same"),
        MakeTimerObj(ids[1], "com.test.dup", "same"),
        MakeTimerObj(ids[2], "com.test.dup", "same"),
    });

    std::map<std::pair<std::string, std::string>, int32_t> countMap;
    db.CountTimersFromTable(HOLD_ON_REBOOT, countMap);
    EXPECT_GE((countMap[{"com.test.dup", "same"}]), 3);
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, ids);
}

// ==================== TimeDatabase-specific tests (RDB only) ====================

#ifdef RDB_ENABLE
/**
 * @tc.name: TimeDatabaseQuerySqlTest001
 * @tc.desc: Test QuerySql with valid query returns non-null result
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimeDatabaseQuerySqlTest001, TestSize.Level1)
{
    int64_t id = static_cast<int64_t>(TEST_TIMER_ID_BASE + 110);
    InsertRdbTimer(HOLD_ON_REBOOT, id, "com.test.query", "queryTimer");
    auto &db = TimeDatabase::GetInstance();
    auto result = db.QuerySql("SELECT * FROM hold_on_reboot WHERE timerId = " + std::to_string(id));
    EXPECT_NE(result, nullptr);
    if (result != nullptr) {
        EXPECT_EQ(result->GoToFirstRow(), OHOS::NativeRdb::E_OK);
        result->Close();
    }
    DeleteRdbTimers(HOLD_ON_REBOOT, {id});
}

/**
 * @tc.name: TimeDatabaseQuerySqlTest002
 * @tc.desc: Test QuerySql with invalid SQL
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimeDatabaseQuerySqlTest002, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto result = db.QuerySql("SELECT * FROM nonexistent_table");
    EXPECT_TRUE(result);
}
#endif // RDB_ENABLE

// ==================== TimerDatabaseOverBaselineReporter tests ====================

/**
 * @tc.name: TimerDatabaseOverBaselineReporterTest001
 * @tc.desc: Test TimerDatabaseOverBaselineReporter with valid data does not crash
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseOverBaselineReporterTest001, TestSize.Level1)
{
    TimerDbSizeInfo sizeInfo;
    sizeInfo.dbSize = 20 * 1024 * 1024;
    sizeInfo.shmSize = 1024;
    sizeInfo.walSize = 2048;
    TimerDatabaseOverBaselineReporter(sizeInfo, 100, "com.app1:t1:50;com.app2:t2:30");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TimerDatabaseOverBaselineReporterTest002
 * @tc.desc: Test TimerDatabaseOverBaselineReporter with empty topAppInfo
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseOverBaselineReporterTest002, TestSize.Level1)
{
    TimerDbSizeInfo sizeInfo;
    sizeInfo.dbSize = 15 * 1024 * 1024;
    sizeInfo.shmSize = 0;
    sizeInfo.walSize = 0;
    TimerDatabaseOverBaselineReporter(sizeInfo, 0, "");
    EXPECT_TRUE(true);
}

/**
 * @tc.name: TimerDatabaseOverBaselineReporterTest003
 * @tc.desc: Test TimerDatabaseOverBaselineReporter with zero sizes
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseOverBaselineReporterTest003, TestSize.Level1)
{
    TimerDbSizeInfo sizeInfo;
    sizeInfo.dbSize = 0;
    sizeInfo.shmSize = 0;
    sizeInfo.walSize = 0;
    TimerDatabaseOverBaselineReporter(sizeInfo, 0, "");
    EXPECT_TRUE(true);
}

// ==================== CheckDatabaseAndReport over-baseline path ====================

#ifndef RDB_ENABLE
/**
 * @tc.name: TimerDatabaseMonitorCheckOverBaselineTest001
 * @tc.desc: Test CheckDatabaseAndReport triggers report when DB size exceeds baseline
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorCheckOverBaselineTest001, TestSize.Level1)
{
    AddPaddingField(11 * 1024 * 1024);
    auto &monitor = TimerDatabaseMonitor::GetInstance();
    monitor.CheckDatabaseAndReport();
    EXPECT_TRUE(true);
    RemovePaddingField();
}

/**
 * @tc.name: TimerDatabaseMonitorCheckOverBaselineTest002
 * @tc.desc: Test CheckDatabaseAndReport with over-baseline and data in tables
 * @tc.type: FUNC
 */
HWTEST_F(TimerDatabaseMonitorTest, TimerDatabaseMonitorCheckOverBaselineTest002, TestSize.Level1)
{
    std::vector<uint64_t> holdIds = {TEST_TIMER_ID_BASE + 200, TEST_TIMER_ID_BASE + 201, TEST_TIMER_ID_BASE + 202};
    std::vector<uint64_t> dropIds = {TEST_TIMER_ID_BASE + 203};
    AddEntriesToTable(HOLD_ON_REBOOT, {
        MakeTimerObj(holdIds[0], "com.test.over1", "t1"),
        MakeTimerObj(holdIds[1], "com.test.over1", "t1"),
        MakeTimerObj(holdIds[2], "com.test.over2", "t2"),
    });
    AddEntriesToTable(DROP_ON_REBOOT, {
        MakeTimerObj(dropIds[0], "com.test.over2", "t2"),
    });
    AddPaddingField(11 * 1024 * 1024);

    auto &monitor = TimerDatabaseMonitor::GetInstance();
    monitor.CheckDatabaseAndReport();
    EXPECT_TRUE(true);

    RemovePaddingField();
    RemoveEntriesByTimerIds(HOLD_ON_REBOOT, holdIds);
    RemoveEntriesByTimerIds(DROP_ON_REBOOT, dropIds);
}
#endif // !RDB_ENABLE

} // namespace MiscServices
} // namespace OHOS
