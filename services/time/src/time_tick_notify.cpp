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
#include "time_tick_notify.h"

#include <chrono>
#include <cinttypes>
#include <ctime>
#include <thread>

#include "common_timer_errors.h"
#include "matching_skills.h"
#include "time_common.h"
#include "time_service_notify.h"
#include "time_system_ability.h"
#include "timer_manager_interface.h"

using namespace std::chrono;

namespace OHOS {
namespace MiscServices {
namespace {
constexpr uint64_t MINUTE_TO_MILLISECOND = 60000;
constexpr uint64_t MICRO_TO_MILLISECOND = 1000;
constexpr uint64_t MILLISECOND_TO_SECOND = 1000;
} // namespace

TimeTickNotify &TimeTickNotify::GetInstance()
{
    static TimeTickNotify instance;
    return instance;
}

TimeTickNotify::TimeTickNotify() : timer_("TickTimer"){};
TimeTickNotify::~TimeTickNotify() = default;

void TimeTickNotify::Init()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Tick notify start.");
    uint32_t ret = timer_.Setup();
    if (ret != Utils::TIMER_ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer Setup failed: %{public}d", ret);
        return;
    }
    auto callback = [this]() { this->Callback(); };
    uint64_t nextTriggerTime = RefreshNextTriggerTime();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Tick notify triggertime: %{public}" PRId64 "", nextTriggerTime);
    timerId_ = timer_.Register(callback, nextTriggerTime);
    TIME_HILOGD(TIME_MODULE_SERVICE, "Tick timer ID: %{public}d", timerId_);
}

void TimeTickNotify::Callback()
{
    timer_.Unregister(timerId_);
    uint64_t nextTriggerTime = RefreshNextTriggerTime();
    auto callback = [this]() { this->Callback(); };
    timerId_ = timer_.Register(callback, nextTriggerTime);
    if (nextTriggerTime > (MINUTE_TO_MILLISECOND - MILLISECOND_TO_SECOND)) {
        auto currentTime = steady_clock::now().time_since_epoch().count();
        TimeServiceNotify::GetInstance().PublishTimeTickEvents(currentTime);
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "id: %{public}d triggertime: %{public}" PRId64 "", timerId_, nextTriggerTime);
}

void TimeTickNotify::PowerCallback()
{
    timer_.Unregister(timerId_);
    uint64_t nextTriggerTime = RefreshNextTriggerTime();
    auto callback = [this]() { this->Callback(); };
    timerId_ = timer_.Register(callback, nextTriggerTime);
    TIME_HILOGI(TIME_MODULE_SERVICE, "id: %{public}d triggertime: %{public}" PRId64 "", timerId_, nextTriggerTime);
}

uint64_t TimeTickNotify::RefreshNextTriggerTime()
{
    auto UTCTimeMicro = static_cast<uint64_t>(duration_cast<microseconds>(system_clock::now()
        .time_since_epoch()).count());
    TIME_HILOGI(TIME_MODULE_SERVICE, "Time micro: %{public}" PRIu64 "", UTCTimeMicro);
    uint64_t timeMilliseconds = (UTCTimeMicro / MICRO_TO_MILLISECOND) % MINUTE_TO_MILLISECOND;
    uint64_t nextTriggerTime = MINUTE_TO_MILLISECOND - timeMilliseconds;
    return nextTriggerTime;
}

void TimeTickNotify::Stop()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    timer_.Shutdown();
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
}
} // namespace MiscServices
} // namespace OHOS