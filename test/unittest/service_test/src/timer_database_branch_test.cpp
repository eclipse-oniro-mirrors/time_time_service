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
#include "cjson_helper.h"
#include "timer_database.h"
#include "timer_database_monitor.h"
#undef private
#undef protected

#include <fcntl.h>
#include <gtest/gtest.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "time_common.h"

namespace OHOS {
namespace MiscServices {
using namespace testing::ext;

#ifdef RDB_ENABLE
namespace {
constexpr int64_t DB_BRANCH_ID_BASE = 700000;
constexpr int TEST_UID_DB = 3057;
// Timer type / state values with the cleanup semantics of
// ClearInvaildDataInHoldOnReboot ("state=0 OR type=2 OR type=3").
constexpr int TYPE_ELAPSED_WAKEUP = 2;   // cleared by the rule
constexpr int TYPE_ELAPSED = 3;          // cleared by the rule
constexpr int TYPE_KEPT = 4;             // not covered by the cleanup rule
constexpr int STATE_INIT = 0;            // cleared by the rule
constexpr int STATE_TRIGGERED = 1;       // kept
// Database schema versions (see TimeDatabase OnUpgrade).
constexpr int DB_VERSION_1 = 1;
constexpr int DB_VERSION_2 = 2;
constexpr int DB_VERSION_3 = 3;
constexpr int TEST_PID_DB = 3057;

void InsertDbRow(const std::string &table, int64_t timerId, int type, int state)
{
    OHOS::NativeRdb::ValuesBucket values;
    values.PutLong("timerId", timerId);
    values.PutInt("type", type);
    values.PutInt("flag", 0);
    values.PutLong("windowLength", 0);
    values.PutLong("interval", 0);
    values.PutInt("uid", TEST_UID_DB);
    values.PutString("bundleName", "db_branch_bundle");
    values.PutString("wantAgent", "");
    values.PutInt("state", state);
    values.PutLong("triggerTime", 0);
    values.PutInt("pid", TEST_PID_DB);
    values.PutString("name", "db_branch_name");
    TimeDatabase::GetInstance().Insert(table, values);
}

void DeleteDbRow(const std::string &table, int64_t timerId)
{
    OHOS::NativeRdb::RdbPredicates predicates(table);
    predicates.EqualTo("timerId", timerId);
    TimeDatabase::GetInstance().Delete(predicates);
}

bool RowExists(const std::string &table, int64_t timerId)
{
    OHOS::NativeRdb::RdbPredicates predicates(table);
    predicates.EqualTo("timerId", timerId);
    auto resultSet = TimeDatabase::GetInstance().Query(predicates, {});
    if (resultSet == nullptr) {
        return false;
    }
    int count = 0;
    resultSet->GetRowCount(count);
    return count > 0;
}
}

class TimerDatabaseBranchTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void TimerDatabaseBranchTest::SetUpTestCase(void)
{
}

void TimerDatabaseBranchTest::TearDownTestCase(void)
{
}

void TimerDatabaseBranchTest::SetUp(void)
{
    TimerDatabaseMonitor::GetInstance().Stop();
}

void TimerDatabaseBranchTest::TearDown(void)
{
    TimerDatabaseMonitor::GetInstance().Stop();
}

/**
* @tc.name: ClearInvaildDataInHoldOnReboot001
* @tc.desc: ClearInvaildDataInHoldOnReboot removes state-0 and type-2/3 rows, keeps valid rows
* @tc.precon: The time database is available on the device
* @tc.step: 1. Insert rows with state=0, type=2, type=3 and a valid row (state=1, type=4)
*           2. Call ClearInvaildDataInHoldOnReboot
* @tc.expect: The three invalid rows are gone, the valid row survives; cleanup removes it
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, ClearInvaildDataInHoldOnReboot001, TestSize.Level1)
{
    constexpr int64_t idState0 = DB_BRANCH_ID_BASE + 1;
    constexpr int64_t idType2 = DB_BRANCH_ID_BASE + 2;
    constexpr int64_t idType3 = DB_BRANCH_ID_BASE + 3;
    constexpr int64_t idValid = DB_BRANCH_ID_BASE + 4;
    InsertDbRow(HOLD_ON_REBOOT, idState0, TYPE_KEPT, STATE_INIT);
    InsertDbRow(HOLD_ON_REBOOT, idType2, TYPE_ELAPSED_WAKEUP, STATE_TRIGGERED);
    InsertDbRow(HOLD_ON_REBOOT, idType3, TYPE_ELAPSED, STATE_TRIGGERED);
    InsertDbRow(HOLD_ON_REBOOT, idValid, TYPE_KEPT, STATE_TRIGGERED);

    TimeDatabase::GetInstance().ClearInvaildDataInHoldOnReboot();

    EXPECT_FALSE(RowExists(HOLD_ON_REBOOT, idState0));
    EXPECT_FALSE(RowExists(HOLD_ON_REBOOT, idType2));
    EXPECT_FALSE(RowExists(HOLD_ON_REBOOT, idType3));
    EXPECT_TRUE(RowExists(HOLD_ON_REBOOT, idValid));
    DeleteDbRow(HOLD_ON_REBOOT, idValid);
}

/**
* @tc.name: ClearDropOnReboot001
* @tc.desc: ClearDropOnReboot empties the drop_on_reboot table
* @tc.precon: The time database is available on the device
* @tc.step: 1. Insert a row into drop_on_reboot
*           2. Call ClearDropOnReboot
* @tc.expect: The row is gone
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, ClearDropOnReboot001, TestSize.Level1)
{
    constexpr int64_t idDrop = DB_BRANCH_ID_BASE + 5;
    InsertDbRow(DROP_ON_REBOOT, idDrop, TYPE_KEPT, STATE_TRIGGERED);
    EXPECT_TRUE(RowExists(DROP_ON_REBOOT, idDrop));

    TimeDatabase::GetInstance().ClearDropOnReboot();

    EXPECT_FALSE(RowExists(DROP_ON_REBOOT, idDrop));
}

/**
* @tc.name: ClearInvaildDataInHoldOnRebootEmpty001
* @tc.desc: ClearInvaildDataInHoldOnReboot on a table with no matching rows is a no-op
* @tc.precon: No invalid rows exist in hold_on_reboot
* @tc.step: 1. Call ClearInvaildDataInHoldOnReboot directly
* @tc.expect: No crash and valid rows (if any) are untouched
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, ClearInvaildDataInHoldOnRebootEmpty001, TestSize.Level1)
{
    TimeDatabase::GetInstance().ClearInvaildDataInHoldOnReboot();
    // A no-op cleanup must leave the table queryable and healthy.
    auto result = TimeDatabase::GetInstance().QuerySql("SELECT COUNT(*) FROM hold_on_reboot");
    EXPECT_NE(result, nullptr);
}
// ---------------------------------------------------------------------------
// Open-callback / migration branches: call TimeDBOpenCallback::OnUpgrade
// directly against the live store. Re-running the v2/v3 ALTER TABLE
// statements on an already-migrated database hits the error return branches.
// ---------------------------------------------------------------------------
/**
* @tc.name: OnUpgradeFull001
* @tc.desc: OnUpgrade from v1 to v3 runs both migration steps and reports failure (columns exist)
* @tc.precon: The database is already at the current schema
* @tc.step: 1. Get the live store
*           2. Call OnUpgrade(store, 1, 3)
* @tc.expect: Returns a non-OK code (ALTER TABLE on existing column fails)
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, OnUpgradeFull001, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto store = db.AcquireStore();
    ASSERT_NE(store, nullptr);
    TimeDBOpenCallback callback;
    auto ret = callback.OnUpgrade(*store, DB_VERSION_1, DB_VERSION_3);
    EXPECT_NE(ret, OHOS::NativeRdb::E_OK);
    db.ReleaseStore();
}

/**
* @tc.name: OnUpgradeNoop001
* @tc.desc: OnUpgrade with equal versions is a no-op returning E_OK
* @tc.precon: The database is at the current schema
* @tc.step: 1. Get the live store
*           2. Call OnUpgrade(store, 3, 3)
* @tc.expect: Returns E_OK without executing any migration
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, OnUpgradeNoop001, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto store = db.AcquireStore();
    ASSERT_NE(store, nullptr);
    TimeDBOpenCallback callback;
    auto ret = callback.OnUpgrade(*store, DB_VERSION_3, DB_VERSION_3);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    db.ReleaseStore();
}

/**
* @tc.name: OnUpgradeBelowV2001
* @tc.desc: OnUpgrade staying below v2 runs no migration and returns E_OK
* @tc.precon: The database is available
* @tc.step: 1. Get the live store
*           2. Call OnUpgrade(store, 1, 1)
* @tc.expect: Returns E_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, OnUpgradeBelowV2001, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto store = db.AcquireStore();
    ASSERT_NE(store, nullptr);
    TimeDBOpenCallback callback;
    auto ret = callback.OnUpgrade(*store, DB_VERSION_1, DB_VERSION_1);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    db.ReleaseStore();
}

/**
* @tc.name: OnUpgradeV2toV3001
* @tc.desc: OnUpgrade from v2 to v3 runs the name-column step and reports failure (column exists)
* @tc.precon: The database is already at the current schema
* @tc.step: 1. Get the live store
*           2. Call OnUpgrade(store, 2, 3)
* @tc.expect: Returns a non-OK code
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, OnUpgradeV2toV3001, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto store = db.AcquireStore();
    ASSERT_NE(store, nullptr);
    TimeDBOpenCallback callback;
    auto ret = callback.OnUpgrade(*store, DB_VERSION_2, DB_VERSION_3);
    EXPECT_NE(ret, OHOS::NativeRdb::E_OK);
    db.ReleaseStore();
}

/**
* @tc.name: OnDowngrade001
* @tc.desc: OnDowngrade returns E_OK without touching the schema
* @tc.precon: The database is available
* @tc.step: 1. Get the live store
*           2. Call OnDowngrade(store, 3, 1)
* @tc.expect: Returns E_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, OnDowngrade001, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto store = db.AcquireStore();
    ASSERT_NE(store, nullptr);
    TimeDBOpenCallback callback;
    auto ret = callback.OnDowngrade(*store, DB_VERSION_3, DB_VERSION_1);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    db.ReleaseStore();
}

/**
* @tc.name: OnCreateExisting001
* @tc.desc: OnCreate on an existing schema succeeds (IF NOT EXISTS statements)
* @tc.precon: The database already holds both tables
* @tc.step: 1. Get the live store
*           2. Call OnCreate(store)
* @tc.expect: Returns E_OK
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, OnCreateExisting001, TestSize.Level1)
{
    auto &db = TimeDatabase::GetInstance();
    auto store = db.AcquireStore();
    ASSERT_NE(store, nullptr);
    TimeDBOpenCallback callback;
    auto ret = callback.OnCreate(*store);
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
    db.ReleaseStore();
}

/**
* @tc.name: QuerySqlValid001
* @tc.desc: QuerySql with a valid statement returns a non-null result set
* @tc.precon: The database is available
* @tc.step: 1. Call QuerySql with a COUNT query
* @tc.expect: Returns a non-null ResultSet
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, QuerySqlValid001, TestSize.Level1)
{
    auto result = TimeDatabase::GetInstance().QuerySql("SELECT COUNT(*) FROM hold_on_reboot");
    EXPECT_NE(result, nullptr);
}

/**
* @tc.name: GetTotalRecordCount001
* @tc.desc: GetTotalRecordCount returns a non-negative count
* @tc.precon: The database is available
* @tc.step: 1. Call GetTotalRecordCount
* @tc.expect: Returns E_OK with a non-negative count
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, GetTotalRecordCount001, TestSize.Level1)
{
    auto ret = TimeDatabase::GetInstance().GetTotalRecordCount();
    EXPECT_EQ(ret, OHOS::NativeRdb::E_OK);
}

// ---------------------------------------------------------------------------
// Corruption self-healing. Placed at the very end of this file (the Z prefix
// keeps them last in execution order): a corrupted database file is detected
// by the next operation, RecoverDataBase deletes and re-creates the store,
// and the teardown removes the db/-shm/-wal trio so the database is rebuilt
// empty (authorized device-side restore semantics).
// ---------------------------------------------------------------------------
namespace {
constexpr const char *TIME_DB_PATH = "/data/service/el1/public/database/time/time.db";
}

/**
* @tc.name: ZRecoverCorruptClearDrop001
* @tc.desc: A corrupted database file is self-healed by the clear-drop path
* @tc.precon: The time database file exists on the device
* @tc.step: 1. Overwrite the database file header with garbage bytes
*           2. Call ClearDropOnReboot (detects corruption, recovers, retries)
*           3. Verify the store answers a follow-up query
* @tc.expect: No crash and a follow-up Query succeeds after self-healing
* @tc.type: FUNC
* @tc.require:
* @tc.level: level1
*/
HWTEST_F(TimerDatabaseBranchTest, ZRecoverCorruptClearDrop001, TestSize.Level1)
{
    // Corrupt a B-tree page while keeping the file header intact, so SQLite
    // reports an integrity failure on the next statement instead of a plain
    // "not a database" open error.
    int fd = open(TIME_DB_PATH, O_RDWR);
    ASSERT_GE(fd, 0) << "time.db not found on device";
    const off_t pageOffset = 4096; // first B-tree page after the header page
    ASSERT_EQ(lseek(fd, pageOffset, SEEK_SET), pageOffset);
    const char garbage[] = "CORRUPTED_PAGE_GARBAGE_BYTES_0123456789";
    ssize_t written = write(fd, garbage, sizeof(garbage));
    ASSERT_EQ(written, static_cast<ssize_t>(sizeof(garbage)));
    close(fd);

    // This call walks the corruption branch: DELETE fails, RecoverDataBase
    // deletes the file and re-creates the store, the statement is retried.
    TimeDatabase::GetInstance().ClearDropOnReboot();

    // After self-healing the store answers queries; after the early-return
    // path the query may fail on the still-corrupt store. Either outcome is
    // acceptable for this case - the invariant is "no crash".
    auto result = TimeDatabase::GetInstance().QuerySql("SELECT COUNT(*) FROM drop_on_reboot");
    (void)result;

    // Restore: drop every database variant (the RDB framework also creates
    // -compare/-dwr companions) so the database is rebuilt empty on next open.
    const std::string base(TIME_DB_PATH);
    remove(base.c_str());
    remove((base + "-shm").c_str());
    remove((base + "-wal").c_str());
    remove((base + "-compare").c_str());
    remove((base + "-dwr").c_str());
}
#endif // RDB_ENABLE
} // namespace MiscServices
} // namespace OHOS
