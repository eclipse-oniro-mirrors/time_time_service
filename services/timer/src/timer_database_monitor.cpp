/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "timer_database_monitor.h"

#include <chrono>

#ifdef RDB_ENABLE
#include "timer_database.h"
#endif
#include "cjson_helper.h"
#include "time_common.h"
#include "time_sysevent.h"

namespace OHOS {
namespace MiscServices {

using namespace std::chrono;

namespace {
constexpr int64_t DB_SIZE_BASELINE = 10 * 1024 * 1024; // 10MB
constexpr int CHECK_INTERVAL_SECONDS = 43200; // 12 hours
constexpr int TOP_N = 10;
}

TimerDatabaseMonitor::TimerDatabaseMonitor() : running_(false) {}

TimerDatabaseMonitor::~TimerDatabaseMonitor()
{
    Stop();
}

TimerDatabaseMonitor &TimerDatabaseMonitor::GetInstance()
{
    static TimerDatabaseMonitor instance;
    return instance;
}

void TimerDatabaseMonitor::Start()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (running_) {
            return;
        }
        running_ = true;
    }
    monitorThread_.reset(new std::thread([this] { this->MonitorLoop(); }));
    TIME_HILOGI(TIME_MODULE_SERVICE, "TimerDatabaseMonitor started");
}

void TimerDatabaseMonitor::Stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
    }
    cv_.notify_one();
    if (monitorThread_ && monitorThread_->joinable()) {
        monitorThread_->join();
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "TimerDatabaseMonitor stopped");
}

void TimerDatabaseMonitor::MonitorLoop()
{
    pthread_setname_np(pthread_self(), "timer_db_monitor");
    std::unique_lock<std::mutex> lock(mutex_);
    while (running_) {
        cv_.wait_for(lock, std::chrono::seconds(CHECK_INTERVAL_SECONDS),
                     [this] { return !running_; });
        if (!running_) {
            break;
        }
        lock.unlock();
        CheckDatabaseAndReport();
        lock.lock();
    }
}

void TimerDatabaseMonitor::CheckDatabaseAndReport()
{
#ifdef RDB_ENABLE
    auto &db = TimeDatabase::GetInstance();
#else
    auto &db = CjsonHelper::GetInstance();
#endif
    TimerDbSizeInfo sizeInfo = db.GetDatabaseSizeDetail();
    int64_t dbSize = sizeInfo.GetTotalSize();

    TIME_HILOGI(TIME_MODULE_SERVICE,
        "TimerDB check: size=%{public}lld bytes", static_cast<long long>(dbSize));

    if (dbSize <= DB_SIZE_BASELINE) {
        return;
    }
    int32_t recordCount = db.GetTotalRecordCount();
    auto topApps = db.GetTopApps(TOP_N);
    std::string topAppInfo = "";
    for (const auto &info : topApps) {
        if (!topAppInfo.empty()) {
            topAppInfo += ";";
        }
        topAppInfo += info.bundleName + ":" + info.timerName + ":" + std::to_string(info.count);
    }
    TimerDatabaseOverBaselineReporter(sizeInfo, recordCount, topAppInfo);
    TIME_HILOGW(TIME_MODULE_SERVICE,
        "TimerDB over baseline! size=%{public}lld, count=%{public}d, topApps=%{public}s",
        static_cast<long long>(dbSize), recordCount, topAppInfo.c_str());
}

} // namespace MiscServices
} // namespace OHOS
