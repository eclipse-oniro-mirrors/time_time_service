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

#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "itimer_info.h"
#include "timer_manager.h"

#include <memory>

namespace OHOS {
namespace MiscServices {
constexpr const char *DB_NAME = "/data/service/el1/public/database/time/time.db";
constexpr const char *TIMER_DATABASE_VERSION = "API12_5.0-release";
constexpr int DATABASE_OPEN_VERSION = 1;
constexpr int CHECK_VERSION_FAILED = -1;
constexpr int WITHOUT_VERSION_TABLE = 0;
constexpr int API12_5_0_RELEASE = 50;
constexpr int INVALID_VERSION = -50;
constexpr int64_t MILLISECOND_TO_NANO = 1000000;
constexpr int CLOCK_POWEROFF_ALARM = 12;
constexpr const char *TIME_VERSION = "time_version";
constexpr const char *HOLD_ON_REBOOT = "hold_on_reboot";
constexpr const char *DROP_ON_REBOOT = "drop_on_reboot";

constexpr const char *CHECK_TIME_VERSION = "SELECT name FROM sqlite_master WHERE type='table' AND "
                                           "name='time_version'";

constexpr const char *CREATE_TIME_VERSION_TABLE = "CREATE TABLE IF NOT EXISTS time_version "
                                                  "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                                  "version TEXT)";

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
                                                         "triggerTime INTEGER)";

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
                                                         "triggerTime INTEGER)";

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
    void ClearDropOnReboot();

private:
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