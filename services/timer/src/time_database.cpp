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

#include <sys/timerfd.h>

#include "time_database.h"
#include "time_hilog.h"
#include "time_common.h"
#include "time_system_ability.h"

namespace OHOS {
namespace MiscServices {
TimeDatabase::TimeDatabase()
{
    int errCode = OHOS::NativeRdb::E_OK;
    OHOS::NativeRdb::RdbStoreConfig config(DB_NAME);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    config.SetEncryptStatus(false);
    TimeDBOpenCallback timeDBOpenCallback;
    store_ = OHOS::NativeRdb::RdbHelper::GetRdbStore(config, DATABASE_OPEN_VERSION, timeDBOpenCallback, errCode);
    TIME_HILOGI(TIME_MODULE_SERVICE, "Gets time database, ret: %{public}d", errCode);
}

TimeDatabase &TimeDatabase::GetInstance()
{
    static TimeDatabase timeDatabase;
    return timeDatabase;
}

int TimeDatabase::GetInt(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    int value = 0;
    resultSet->GetInt(line, value);
    return value;
}

int64_t TimeDatabase::GetLong(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    int64_t value = 0;
    resultSet->GetLong(line, value);
    return value;
}

std::string TimeDatabase::GetString(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet, int line)
{
    std::string value = "";
    resultSet->GetString(line, value);
    return value;
}

void TimeDatabase::InnerRecover(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet,
                                std::shared_ptr<TimerManager> timerManagerHandler)
{
    do {
        auto timerId = static_cast<uint64_t>(GetLong(resultSet, 0));
        auto timerInfo = std::make_shared<TimerEntry>(TimerEntry {
            // Line 0 is 'timerId'
            timerId,
            // Line 1 is 'type'
            GetInt(resultSet, 1),
            // Line 3 is 'windowLength'
            static_cast<uint64_t>(GetLong(resultSet, 3)),
            // Line 4 is 'interval'
            static_cast<uint64_t>(GetLong(resultSet, 4)),
            // Line 2 is 'flag'
            GetInt(resultSet, 2),
            // Callback can't recover.
            nullptr,
            // Line 7 is 'wantAgent'
            OHOS::AbilityRuntime::WantAgent::WantAgentHelper::FromString(GetString(resultSet, 7)),
            // Line 5 is 'uid'
            GetInt(resultSet, 5),
            // Line 6 is 'bundleName'
            GetString(resultSet, 6)
        });
        timerManagerHandler->ReCreateTimer(timerId, timerInfo);
        // Line 8 is 'state'
        auto state = static_cast<uint8_t>(GetInt(resultSet, 8));
        if (state == 1) {
            // Line 9 is 'triggerTime'
            auto triggerTime = static_cast<uint64_t>(GetLong(resultSet, 9));
            timerManagerHandler->StartTimer(timerId, triggerTime);
        }
    } while (resultSet->GoToNextRow() == OHOS::NativeRdb::E_OK);
    resultSet->Close();
}

bool TimeDatabase::Recover(std::shared_ptr<TimerManager> timerManagerHandler)
{
    OHOS::NativeRdb::RdbPredicates holdRdbPredicates("hold_on_reboot");
    auto holdResultSet = Query(
        holdRdbPredicates, { "timerId", "type" , "flag", "windowLength", "interval", "uid", \
        "bundleName", "wantAgent", "state", "triggerTime"});
    if (holdResultSet == nullptr || holdResultSet->GoToFirstRow() != OHOS::NativeRdb::E_OK) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "hold result set is nullptr or go to first row failed");
    } else {
        InnerRecover(holdResultSet, timerManagerHandler);
    }

    OHOS::NativeRdb::RdbPredicates dropRdbPredicates("drop_on_reboot");
    auto dropResultSet = Query(
        dropRdbPredicates, { "timerId", "type" , "flag", "windowLength", "interval", "uid", \
        "bundleName", "wantAgent", "state", "triggerTime"});
    if (dropResultSet == nullptr || dropResultSet->GoToFirstRow() != OHOS::NativeRdb::E_OK) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "drop result set is nullptr or go to first row failed");
    } else {
        InnerRecover(dropResultSet, timerManagerHandler);
    }
    return true;
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
    // Clears `drop_on_reboot` table.
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

void TimeDatabase::SetAutoBoot()
{
    // Find the most recent trigger time to boot on.
    TIME_HILOGI(TIME_MODULE_SERVICE, "Find the most recent trigger time");
    if (store_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "store_ is nullptr");
        return;
    }
    OHOS::NativeRdb::RdbPredicates holdRdbPredicates("hold_on_reboot");
    holdRdbPredicates.EqualTo("state", 1)->OrderByDesc("triggerTime");
    auto resultSet = Query(holdRdbPredicates, { "timerId", "type" , "flag", "windowLength", "interval", "uid", \
        "bundleName", "wantAgent", "state", "triggerTime"});
    if (resultSet == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Find the most recent trigger time failed");
        return;
    }
    do {
        auto bundleName = GetString(resultSet, 6);
        auto triggerTime = static_cast<uint64_t>(GetLong(resultSet, 9));
        int64_t currentTime = 0;
        TimeSystemAbility::GetInstance()->GetWallTimeMs(currentTime);
        if (triggerTime < static_cast<uint64_t>(currentTime)) {
            continue;
        }
        if (bundleName == NEED_RECOVER_ON_REBOOT) {
            int tmfd = timerfd_create(CLOCK_POWEROFF_ALARM, TFD_NONBLOCK);
            if (tmfd < 0) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "timerfd_create error");
            }

            struct itimerspec new_value;
            std::chrono::nanoseconds nsec(triggerTime * MILLISECOND_TO_NANO);
            auto second = std::chrono::duration_cast<std::chrono::seconds>(nsec);
            new_value.it_value.tv_sec = second.count();
            new_value.it_value.tv_nsec = (nsec - second).count();
            new_value.it_interval.tv_sec = 0;
            int ret = timerfd_settime(tmfd, TFD_TIMER_ABSTIME, &new_value, nullptr);
            if (ret < 0) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "timerfd_settime error");
                close(tmfd);
            }
            resultSet->Close();
            return;
        }
    } while (resultSet->GoToNextRow() == OHOS::NativeRdb::E_OK);
    resultSet->Close();
}

int TimeDBCreateTables(OHOS::NativeRdb::RdbStore &store)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Creates time_version table");
    // Creates time_version table.
    int ret = store.ExecuteSql(CREATE_TIME_VERSION_TABLE);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Creates time_version table failed, ret: %{public}d", ret);
        return ret;
    }

    TIME_HILOGI(TIME_MODULE_SERVICE, "Creates hold_on_reboot table");
    // Creates hold_on_reboot table.
    ret = store.ExecuteSql(CREATE_TIME_TIMER_HOLD_ON_REBOOT);
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
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init database failed");
        return initRet;
    }
    return initRet;
}

int TimeDBInitVersionTable(OHOS::NativeRdb::RdbStore &store)
{
    // Clears `time_version` table.
    int ret = store.ExecuteSql("DELETE FROM time_version");
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Clears time_version table failed");
        return ret;
    }

    int64_t outRowId = 0;
    OHOS::NativeRdb::ValuesBucket insertValues;
    insertValues.PutString("version", std::string(TIME_DATABASE_VERSION));
    ret = store.Insert(outRowId, std::string("time_version"), insertValues);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Inits time_version table failed");
        return ret;
    }
    return ret;
}

int TimeDBOpenCallback::OnOpen(OHOS::NativeRdb::RdbStore &store)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnOpen");
    auto ret = TimeDBInitVersionTable(store);
    if (ret != OHOS::NativeRdb::E_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init time_version table failed");
        return ret;
    }
    return ret;
}

int TimeDBOpenCallback::OnUpgrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}

int TimeDBOpenCallback::OnDowngrade(OHOS::NativeRdb::RdbStore &store, int oldVersion, int newVersion)
{
    return OHOS::NativeRdb::E_OK;
}
}
}