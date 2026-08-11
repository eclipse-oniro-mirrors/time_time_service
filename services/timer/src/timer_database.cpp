/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "timer_database.h"
#include "time_common.h"

#include <sys/stat.h>

namespace OHOS {
namespace MiscServices {
constexpr const char *CREATE_TIME_TIMER_HOLD_ON_REBOOT = "CREATE TABLE IF NOT EXISTS hold_on_reboot "
                                                         "(timerId INTEGER PRIMARY KEY, "
                                                         "type INTEGER, "
                                                         "flag INTEGER, "
                                                         "windowLength INTEGER, "
                                                         "interval INTEGER, "
                                                         "uid INTEGER, "
                                                         "bundleName TEXT, "
                                                         "wantAgent TEXT, "
                                                         "state INTEGER, "
                                                         "triggerTime INTEGER, "
                                                         "pid INTEGER, "
                                                         "name TEXT)";

constexpr const char *CREATE_TIME_TIMER_DROP_ON_REBOOT = "CREATE TABLE IF NOT EXISTS drop_on_reboot "
                                                         "(timerId INTEGER PRIMARY KEY, "
                                                         "type INTEGER, "
                                                         "flag INTEGER, "
                                                         "windowLength INTEGER, "
                                                         "interval INTEGER, "
                                                         "uid INTEGER, "
                                                         "bundleName TEXT, "
                                                         "wantAgent TEXT, "
                                                         "state INTEGER, "
                                                         "triggerTime INTEGER, "
                                                         "pid INTEGER, "
                                                         "name TEXT)";

constexpr const char *HOLD_ON_REBOOT_ADD_PID_COLUMN = "ALTER TABLE hold_on_reboot ADD COLUMN pid INTEGER";
constexpr const char *HOLD_ON_REBOOT_ADD_NAME_COLUMN = "ALTER TABLE hold_on_reboot ADD COLUMN name TEXT";
constexpr const char *DROP_ON_REBOOT_ADD_PID_COLUMN = "ALTER TABLE drop_on_reboot ADD COLUMN pid INTEGER";
constexpr const char *DROP_ON_REBOOT_ADD_NAME_COLUMN = "ALTER TABLE drop_on_reboot ADD COLUMN name TEXT";
constexpr const char *DB_NAME = "/data/service/el1/public/database/time/time.db";
constexpr int DATABASE_OPEN_VERSION_2 = 2;
constexpr int DATABASE_OPEN_VERSION_3 = 3;
constexpr int TOP_COLUMN_INDEX_BUNDLE_NAME = 0;
constexpr int TOP_COLUMN_INDEX_TIMER_NAME = 1;
constexpr int TOP_COLUMN_INDEX_COUNT = 2;

TimeDatabase::TimeDatabase()
{
    int errCode = OHOS::NativeRdb::E_OK;
    OHOS::NativeRdb::RdbStoreConfig config(DB_NAME);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetEncryptStatus(false);
    config.SetReadConSize(1);
    TimeDBOpenCallback timeDBOpenCallback;
    store_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_OPEN_VERSION_3, timeDBOpenCallback, errCode);
    if (errCode) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Get database, ret:%{public}d", errCode);
    }
    if (errCode == OHOS::NativeRdb::E_SQLITE_CORRUPT) {
        auto ret = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(config);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "delete corrupt database failed, ret:%{public}d", ret);
            return;
        }
        store_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_OPEN_VERSION_3, timeDBOpenCallback, errCode);
    }
}

TimeDatabase &TimeDatabase::GetInstance()
{
    static TimeDatabase timeDatabase;
    return timeDatabase;
}

// RAII bracket for an in-flight store operation. AcquireStore bumps inFlight_
// under storeMutex_; ~StoreGuard calls ReleaseStore. Assigning nullptr to the
// guard releases early (used before RecoverDataBase, which drains inFlight_).
// Nested in TimeDatabase (declared in the header) so it can reach the private
// AcquireStore/ReleaseStore without a friend declaration.
class TimeDatabase::StoreGuard {
public:
    explicit StoreGuard(TimeDatabase &db) : store_(db.AcquireStore()), db_(&db) {}
    ~StoreGuard()
    {
        if (store_ != nullptr && db_ != nullptr) {
            db_->ReleaseStore();
        }
    }
    StoreGuard(const StoreGuard &) = delete;
    StoreGuard &operator=(const StoreGuard &) = delete;
    StoreGuard(StoreGuard &&other) noexcept : store_(std::move(other.store_)), db_(other.db_) { other.db_ = nullptr; }
    StoreGuard &operator=(StoreGuard &&other) noexcept
    {
        if (this != &other) {
            if (store_ != nullptr && db_ != nullptr) {
                db_->ReleaseStore();
            }
            store_ = std::move(other.store_);
            db_ = other.db_;
            other.db_ = nullptr;
        }
        return *this;
    }
    // nullptr assignment releases the in-flight ref immediately.
    StoreGuard &operator=(std::nullptr_t)
    {
        if (store_ != nullptr && db_ != nullptr) {
            db_->ReleaseStore();
        }
        store_ = nullptr;
        return *this;
    }
    // Hand off the in-flight ref to an external owner (e.g. WrapResult's deleter)
    // without decrementing it. The receiver becomes responsible for ReleaseStore.
    void Detach()
    {
        store_ = nullptr;
        db_ = nullptr;
    }
    const std::shared_ptr<OHOS::NativeRdb::RdbStore> &Get() const { return store_; }
    explicit operator bool() const { return store_ != nullptr; }

private:
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store_;
    TimeDatabase *db_;
};

bool TimeDatabase::RecoverDataBase()
{
    std::unique_lock<std::mutex> lock(storeMutex_);
    // Drain all in-flight operations before destroying the store. A thread may
    // be holding a copy of store_ (Insert/Update/Delete) or iterating a
    // ResultSet whose connection belongs to this store's pool; DeleteRdbStore
    // tears down the pool and closes the underlying sqlite3 handles, so we must
    // wait until none are in flight. New operations block on storeMutex_ until
    // the swap completes, then observe the new store_.
    inFlightCv_.wait(lock, [this] { return inFlight_ == 0; });
    OHOS::NativeRdb::RdbStoreConfig config(DB_NAME);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetEncryptStatus(false);
    config.SetReadConSize(1);
    auto ret = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(config);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "delete corrupt database failed, ret %{public}d", ret);
        return false;
    }
    TimeDBOpenCallback timeDbOpenCallback;
    int errCode = OHOS::NativeRdb::E_OK;
    store_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_OPEN_VERSION_3, timeDbOpenCallback, errCode);
    if (store_ == nullptr) {
        return false;
    }
    return true;
}

std::shared_ptr<OHOS::NativeRdb::RdbStore> TimeDatabase::AcquireStore()
{
    std::lock_guard<std::mutex> lock(storeMutex_);
    if (store_ == nullptr) {
        return nullptr;
    }
    ++inFlight_;
    return store_;
}

void TimeDatabase::ReleaseStore()
{
    std::lock_guard<std::mutex> lock(storeMutex_);
    if (inFlight_ > 0) {
        --inFlight_;
    }
    inFlightCv_.notify_one();
}

// Transfers the in-flight ref (already bumped by AcquireStore) to the ResultSet's
// lifetime. The deleter closes the result (idempotent) and releases the ref when
// the caller drops the shared_ptr, so RecoverDataBase drains even while a
// ResultSet is being iterated outside TimeDatabase.
std::shared_ptr<OHOS::NativeRdb::ResultSet> TimeDatabase::WrapResult(
    std::shared_ptr<OHOS::NativeRdb::ResultSet> result)
{
    TimeDatabase *db = this;
    return std::shared_ptr<OHOS::NativeRdb::ResultSet>(
        result.get(),
        [result, db](OHOS::NativeRdb::ResultSet *) {
            if (result != nullptr) {
                result->Close();
            }
            db->ReleaseStore();
        });
}

int GetInt(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    int value = 0;
    int ret = resultSet->GetInt(line, value);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "GetInt failed, line:%{public}d, ret:%{public}d", line, ret);
    }
    return value;
}

int64_t GetLong(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    int64_t value = 0;
    int ret = resultSet->GetLong(line, value);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "GetLong failed, line:%{public}d, ret:%{public}d", line, ret);
    }
    return value;
}

std::string GetString(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    std::string value = "";
    int ret = resultSet->GetString(line, value);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "GetString failed, line:%{public}d, ret:%{public}d", line, ret);
    }
    return value;
}

bool TimeDatabase::Insert(const std::string &table, const OHOS::NativeRdb::ValuesBucket &insertValues)
{
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return false;
    }

    int64_t outRowId = 0;
    auto ret = store.Get()->Insert(outRowId, table, insertValues);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "insert values failed, ret:%{public}d", ret);
        if (ret != OHOS::NativeRdb::E_SQLITE_CORRUPT) {
            return false;
        }
        // Release the in-flight ref before RecoverDataBase, which drains inFlight_.
        store = nullptr;
        if (!RecoverDataBase()) {
            return false;
        }
        store = StoreGuard(*this);
        if (!store) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
            return false;
        }
        ret = store.Get()->Insert(outRowId, table, insertValues);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Insert values after RecoverDataBase failed, ret:%{public}d", ret);
            return false;
        }
    }
    return true;
}

bool TimeDatabase::Update(
    const OHOS::NativeRdb::ValuesBucket values, const OHOS::NativeRdb::AbsRdbPredicates &predicates)
{
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return false;
    }

    int changedRows = 0;
    auto ret = store.Get()->Update(changedRows, values, predicates);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "update values failed, ret:%{public}d", ret);
        if (ret != OHOS::NativeRdb::E_SQLITE_CORRUPT) {
            return false;
        }
        store = nullptr;
        if (!RecoverDataBase()) {
            return false;
        }
        store = StoreGuard(*this);
        if (!store) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
            return false;
        }
        ret = store.Get()->Update(changedRows, values, predicates);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Update values after RecoverDataBase failed, ret:%{public}d", ret);
            return false;
        }
    }
    return true;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> TimeDatabase::Query(
    const OHOS::NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return nullptr;
    }
    auto result = store.Get()->Query(predicates, columns);
    if (result == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "result is nullptr");
        return nullptr;
    }
    int32_t count = 0;
    if (result->GetRowCount(count) == OHOS::NativeRdb::E_SQLITE_CORRUPT) {
        // Close result BEFORE RecoverDataBase: RecoverDataBase deletes the db and closes the
        // underlying sqlite3 connection, so closing result afterwards would touch freed resources
        // (use-after-free).
        result->Close();
        store = nullptr;
        RecoverDataBase();
        return nullptr;
    }
    // The in-flight ref (bumped by AcquireStore) is transferred to the ResultSet's
    // lifetime: Detach keeps inFlight_ elevated and makes WrapResult's deleter
    // responsible for the eventual ReleaseStore, so RecoverDataBase drains even
    // while the caller iterates this ResultSet outside TimeDatabase.
    store.Detach();
    return WrapResult(result);
}

bool TimeDatabase::Delete(const OHOS::NativeRdb::AbsRdbPredicates &predicates)
{
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return false;
    }

    int deletedRows = 0;
    auto ret = store.Get()->Delete(deletedRows, predicates);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "delete values failed, ret:%{public}d", ret);
        if (ret != OHOS::NativeRdb::E_SQLITE_CORRUPT) {
            return false;
        }
        store = nullptr;
        if (!RecoverDataBase()) {
            return false;
        }
        store = StoreGuard(*this);
        if (!store) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
            return false;
        }
        ret = store.Get()->Delete(deletedRows, predicates);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Delete values after RecoverDataBase failed, ret:%{public}d", ret);
            return false;
        }
    }
    return true;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> TimeDatabase::QuerySql(const std::string &sql)
{
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return nullptr;
    }
    auto result = store.Get()->QuerySql(sql, std::vector<OHOS::NativeRdb::ValueObject>());
    if (result == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "result is nullptr");
        return nullptr;
    }
    int32_t count = 0;
    if (result->GetRowCount(count) == OHOS::NativeRdb::E_SQLITE_CORRUPT) {
        // Close result BEFORE RecoverDataBase: RecoverDataBase deletes the db and closes the
        // underlying sqlite3 connection, so closing result afterwards would touch freed resources
        // (use-after-free).
        result->Close();
        store = nullptr;
        RecoverDataBase();
        return nullptr;
    }
    store.Detach();
    return WrapResult(result);
}

void TimeDatabase::ClearDropOnReboot()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Clears drop_on_reboot table");
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return;
    }
    auto ret = store.Get()->ExecuteSql("DELETE FROM drop_on_reboot");
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Clears drop_on_reboot table failed");
        if (ret != OHOS::NativeRdb::E_SQLITE_CORRUPT) {
            return;
        }
        store = nullptr;
        if (!RecoverDataBase()) {
            return;
        }
        store = StoreGuard(*this);
        if (!store) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
            return;
        }
        ret = store.Get()->ExecuteSql("DELETE FROM drop_on_reboot");
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Clears after RecoverDataBase failed, ret:%{public}d", ret);
        }
    }
}

void TimeDatabase::ClearInvaildDataInHoldOnReboot()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Clears hold_on_reboot table");
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return;
    }
    auto ret = store.Get()->ExecuteSql("DELETE FROM hold_on_reboot WHERE state = 0 OR type = 2 OR type = 3");
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Clears hold_on_reboot table failed");
        if (ret != OHOS::NativeRdb::E_SQLITE_CORRUPT) {
            return;
        }
        store = nullptr;
        if (!RecoverDataBase()) {
            return;
        }
        store = StoreGuard(*this);
        if (!store) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
            return;
        }
        ret = store.Get()->ExecuteSql("DELETE FROM hold_on_reboot WHERE state = 0 OR type = 2 OR type = 3");
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Clears after RecoverDataBase failed, ret:%{public}d", ret);
        }
    }
}

void TimeDatabase::CheckpointWal()
{
    // TRUNCATE merges the WAL into the main DB and physically truncates -wal to 0 bytes;
    // degrades to a plain checkpoint (no truncation) if a reader is in flight.
    auto store = StoreGuard(*this);
    if (!store) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return;
    }
    auto ret = store.Get()->ExecuteSql("PRAGMA wal_checkpoint(TRUNCATE)");
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "checkpoint WAL failed, ret:%{public}d", ret);
    }
}

TimerDbSizeInfo TimeDatabase::GetDatabaseSizeDetail()
{
    TimerDbSizeInfo sizeInfo{};
    struct stat st;
    if (stat(DB_NAME, &st) == 0) {
        sizeInfo.dbSize = st.st_size;
    }
    if (stat((std::string(DB_NAME) + "-shm").c_str(), &st) == 0) {
        sizeInfo.shmSize = st.st_size;
    }
    if (stat((std::string(DB_NAME) + "-wal").c_str(), &st) == 0) {
        sizeInfo.walSize = st.st_size;
    }
    return sizeInfo;
}

int32_t TimeDatabase::GetTotalRecordCount()
{
    int32_t totalCount = 0;
    auto result = QuerySql(
        "SELECT SUM(cnt) FROM ("
        "  SELECT COUNT(*) AS cnt FROM hold_on_reboot"
        "  UNION ALL"
        "  SELECT COUNT(*) AS cnt FROM drop_on_reboot"
        ")");
    if (result != nullptr) {
        if (result->GoToFirstRow() == OHOS::NativeRdb::E_OK) {
            int32_t ret = result->GetInt(0, totalCount);
            if (ret != OHOS::NativeRdb::E_OK) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "GetTotalRecordCount failed, ret:%{public}d", ret);
                totalCount = 0;
            }
        }
        result->Close();
    }
    return totalCount;
}

std::vector<TimerDbTopAppInfo> TimeDatabase::GetTopApps(int topN)
{
    std::vector<TimerDbTopAppInfo> result;
    if (topN <= 0) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "GetTopApps invalid topN:%{public}d", topN);
        return result;
    }
    std::string sql =
        "SELECT bundleName, name, SUM(cnt) as total FROM ("
        "  SELECT bundleName, name, COUNT(*) as cnt FROM hold_on_reboot GROUP BY bundleName, name"
        "  UNION ALL"
        "  SELECT bundleName, name, COUNT(*) as cnt FROM drop_on_reboot GROUP BY bundleName, name"
        ") GROUP BY bundleName, name ORDER BY total DESC LIMIT " + std::to_string(topN);
    auto queryResult = QuerySql(sql);
    if (queryResult != nullptr) {
        if (queryResult->GoToFirstRow() == OHOS::NativeRdb::E_OK) {
            do {
                TimerDbTopAppInfo info;
                info.bundleName = GetString(queryResult, TOP_COLUMN_INDEX_BUNDLE_NAME);
                info.timerName = GetString(queryResult, TOP_COLUMN_INDEX_TIMER_NAME);
                info.count = GetInt(queryResult, TOP_COLUMN_INDEX_COUNT);
                result.push_back(info);
            } while (queryResult->GoToNextRow() == OHOS::NativeRdb::E_OK);
        }
        queryResult->Close();
    }
    return result;
}

int TimeDBCreateTables(OHOS::NativeRdb::RdbStore &store)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Creates hold_on_reboot table");
    // Creates hold_on_reboot table.
    int ret = store.ExecuteSql(CREATE_TIME_TIMER_HOLD_ON_REBOOT);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Creates hold_on_reboot table failed, ret:%{public}d", ret);
        return ret;
    }

    TIME_HILOGI(TIME_MODULE_SERVICE, "Creates drop_on_reboot table");
    // Creates drop_on_reboot table.
    ret = store.ExecuteSql(CREATE_TIME_TIMER_DROP_ON_REBOOT);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Creates drop_on_reboot table failed, ret:%{public}d", ret);
        return ret;
    }
    return ret;
}

int TimeDBOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &store)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnCreate");
    auto initRet = TimeDBCreateTables(store);
    if (initRet != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init database failed:%{public}d", initRet);
        return initRet;
    }
    return OHOS::NativeRdb::E_OK;
}

int TimeDBOpenCallback::OnOpen(OHOS::NativeRdb::RdbStore &store)
{
    return OHOS::NativeRdb::E_OK;
}

int TimeDBOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    if (oldVersion < DATABASE_OPEN_VERSION_2 && newVersion >= DATABASE_OPEN_VERSION_2) {
        int ret = store.ExecuteSql(HOLD_ON_REBOOT_ADD_PID_COLUMN);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "hold_on_reboot add column failed, ret:%{public}d", ret);
            return ret;
        }
        ret = store.ExecuteSql(DROP_ON_REBOOT_ADD_PID_COLUMN);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "drop_on_reboot add column failed, ret:%{public}d", ret);
            return ret;
        }
    }
    if (oldVersion < DATABASE_OPEN_VERSION_3 && newVersion >= DATABASE_OPEN_VERSION_3) {
        int ret = store.ExecuteSql(HOLD_ON_REBOOT_ADD_NAME_COLUMN);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "hold_on_reboot add column failed, ret:%{public}d", ret);
            return ret;
        }
        ret = store.ExecuteSql(DROP_ON_REBOOT_ADD_NAME_COLUMN);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "drop_on_reboot add column failed, ret:%{public}d", ret);
            return ret;
        }
    }
    return OHOS::NativeRdb::E_OK;
}

int TimeDBOpenCallback::OnDowngrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}
}
}
