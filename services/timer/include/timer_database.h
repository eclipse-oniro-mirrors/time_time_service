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

#ifndef TIMER_DATABASE_H
#define TIMER_DATABASE_H

#include <condition_variable>
#include <mutex>
#include <vector>
#include <string>
#include "timer_db_info.h"
#include "rdb_helper.h"
#include "rdb_predicates.h"

namespace OHOS {
namespace MiscServices {

// Column indices in the timer table (see CREATE_TIME_TIMER_* in timer_database.cpp).
// Keep in sync with the schema.
constexpr int COLUMN_INDEX_TIMER_ID = 0;
constexpr int COLUMN_INDEX_TYPE = 1;
constexpr int COLUMN_INDEX_FLAG = 2;
constexpr int COLUMN_INDEX_WINDOW_LENGTH = 3;
constexpr int COLUMN_INDEX_INTERVAL = 4;
constexpr int COLUMN_INDEX_UID = 5;
constexpr int COLUMN_INDEX_BUNDLE_NAME = 6;
constexpr int COLUMN_INDEX_WANT_AGENT = 7;
constexpr int COLUMN_INDEX_STATE = 8;
constexpr int COLUMN_INDEX_TRIGGER_TIME = 9;
constexpr int COLUMN_INDEX_PID = 10;
constexpr int COLUMN_INDEX_NAME = 11;

int GetInt(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line);
int64_t GetLong(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line);
std::string GetString(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line);

class TimeDatabase {
public:
    TimeDatabase();
    static TimeDatabase &GetInstance();
    bool Insert(const std::string &table, const OHOS::NativeRdb::ValuesBucket &insertValues);
    bool Update(const OHOS::NativeRdb::ValuesBucket values, const OHOS::NativeRdb::AbsRdbPredicates &predicates);
    std::shared_ptr<OHOS::NativeRdb::ResultSet> Query(
        const OHOS::NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> &columns);
    bool Delete(const OHOS::NativeRdb::AbsRdbPredicates &predicates);
    std::shared_ptr<OHOS::NativeRdb::ResultSet> QuerySql(const std::string &sql);
    void ClearDropOnReboot();
    void ClearInvaildDataInHoldOnReboot();
    void CheckpointWal();

    TimerDbSizeInfo GetDatabaseSizeDetail();
    int32_t GetTotalRecordCount();
    std::vector<TimerDbTopAppInfo> GetTopApps(int topN);

private:
    // RAII bracket for an in-flight store operation. Defined in the .cpp; nested
    // so it can reach AcquireStore/ReleaseStore without a friend declaration.
    class StoreGuard;
    // Brackets an in-flight operation: AcquireStore increments inFlight_ under
    // storeMutex_ before handing out store_; ReleaseStore decrements and
    // notifies. RecoverDataBase waits on inFlightCv_ until inFlight_ == 0
    // before DeleteRdbStore, so no thread is left using a destroyed connection.
    std::shared_ptr<OHOS::NativeRdb::RdbStore> AcquireStore();
    void ReleaseStore();
    std::shared_ptr<OHOS::NativeRdb::ResultSet> WrapResult(
        std::shared_ptr<OHOS::NativeRdb::ResultSet> result);
    std::mutex storeMutex_;
    size_t inFlight_ = 0;
    std::condition_variable inFlightCv_;
    bool RecoverDataBase();
    std::shared_ptr<OHOS::NativeRdb::RdbStore> store_;
};

class TimeDBOpenCallback : public OHOS::NativeRdb::RdbOpenCallback {
public:
    int OnCreate(OHOS::NativeRdb::RdbStore &rdbStore) override;
    int OnOpen(OHOS::NativeRdb::RdbStore &rdbStore) override;
    int OnUpgrade(OHOS::NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override;
    int OnDowngrade(OHOS::NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
};
} // namespace MiscServices
} // namespace OHOS
#endif // TIMER_DATABASE_H
