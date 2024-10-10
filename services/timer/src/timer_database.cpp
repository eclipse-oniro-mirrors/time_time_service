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
#include "time_hilog.h"
#include "time_common.h"

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
                                                         "pid INTEGER)";

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
                                                         "pid INTEGER)";

constexpr const char *HOLD_ON_REBOOT_ADD_COLUMN = "ALTER TABLE hold_on_reboot ADD COLUMN pid INTEGER";

constexpr const char *DROP_ON_REBOOT_ADD_COLUMN = "ALTER TABLE drop_on_reboot ADD COLUMN pid INTEGER";

TimeDatabase::TimeDatabase()
{
    int errCode = OHOS::NativeRdb::E_OK;
    OHOS::NativeRdb::RdbStoreConfig config(DB_NAME);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetEncryptStatus(false);
    config.SetReadConSize(1);
    TimeDBOpenCallback timeDBOpenCallback;
    store_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_OPEN_VERSION_2, timeDBOpenCallback, errCode);
    TIME_HILOGI(TIME_MODULE_SERVICE, "Gets time database, ret: %{public}d", errCode);
}

TimeDatabase &TimeDatabase::GetInstance()
{
    static TimeDatabase timeDatabase;
    return timeDatabase;
}

int GetInt(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    int value = 0;
    resultSet->GetInt(line, value);
    return value;
}

int64_t GetLong(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    int64_t value = 0;
    resultSet->GetLong(line, value);
    return value;
}

std::string GetString(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    std::string value = "";
    resultSet->GetString(line, value);
    return value;
}

bool TimeDatabase::Insert(const std::string &table, const OHOS::NativeRdb::ValuesBucket &insertValues)
{
    if (store_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return false;
    }

    int64_t outRowId = 0;
    int ret = store_->Insert(outRowId, table, insertValues);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "insert values failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

bool TimeDatabase::Update(
    const OHOS::NativeRdb::ValuesBucket values, const OHOS::NativeRdb::AbsRdbPredicates &predicates)
{
    if (store_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return false;
    }

    int changedRows = 0;
    int ret = store_->Update(changedRows, values, predicates);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "update values failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

std::shared_ptr<OHOS::NativeRdb::ResultSet> TimeDatabase::Query(
    const OHOS::NativeRdb::AbsRdbPredicates &predicates, const std::vector<std::string> &columns)
{
    if (store_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return nullptr;
    }
    return store_->Query(predicates, columns);
}

bool TimeDatabase::Delete(const OHOS::NativeRdb::AbsRdbPredicates &predicates)
{
    if (store_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return false;
    }

    int deletedRows = 0;
    int ret = store_->Delete(deletedRows, predicates);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "delete values failed, ret: %{public}d", ret);
        return false;
    }
    return true;
}

void TimeDatabase::ClearDropOnReboot()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Clears drop_on_reboot table");
    if (store_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return;
    }
    int ret = store_->ExecuteSql("DELETE FROM drop_on_reboot");
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Clears drop_on_reboot table failed");
    }
}

int TimeDBCreateTables(OHOS::NativeRdb::RdbStore &store)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Creates hold_on_reboot table");
    // Creates hold_on_reboot table.
    int ret = store.ExecuteSql(CREATE_TIME_TIMER_HOLD_ON_REBOOT);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Creates hold_on_reboot table failed, ret: %{public}d", ret);
        return ret;
    }

    TIME_HILOGI(TIME_MODULE_SERVICE, "Creates drop_on_reboot table");
    // Creates drop_on_reboot table.
    ret = store.ExecuteSql(CREATE_TIME_TIMER_DROP_ON_REBOOT);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Creates drop_on_reboot table failed, ret: %{public}d", ret);
        return ret;
    }
    return ret;
}

int TimeDBOpenCallback::OnCreate(OHOS::NativeRdb::RdbStore &store)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnCreate");
    auto initRet = TimeDBCreateTables(store);
    if (initRet != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init database failed: %{public}d", initRet);
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
    if (oldVersion == DATABASE_OPEN_VERSION && newVersion == DATABASE_OPEN_VERSION_2) {
        int ret = store.ExecuteSql(HOLD_ON_REBOOT_ADD_COLUMN);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "hold_on_reboot add column failed, ret: %{public}d", ret);
            return ret;
        }
        ret = store.ExecuteSql(DROP_ON_REBOOT_ADD_COLUMN);
        if (ret != OHOS::NativeRdb::E_OK) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "drop_on_reboot add column failed, ret: %{public}d", ret);
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