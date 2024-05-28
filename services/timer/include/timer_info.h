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

#ifndef TIMER_INFO_H
#define TIMER_INFO_H

#include <cstdint>
#include <string>

#include "timer_manager_interface.h"

namespace OHOS {
namespace MiscServices {
static const uint32_t HALF_SECEND = 2;

class TimerInfo {
public:
    const uint64_t id;
    const int type;
    const std::chrono::milliseconds origWhen;
    const bool wakeup;
    const std::function<void (const uint64_t)> callback;
    const std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent;
    const uint32_t flags;
    const int uid;
    const int pid;

    uint64_t count {};
    std::chrono::milliseconds when;
    std::chrono::milliseconds windowLength;
    std::chrono::steady_clock::time_point originWhenElapsed;
    std::chrono::steady_clock::time_point originMaxWhenElapsed;
    std::chrono::steady_clock::time_point whenElapsed;
    std::chrono::steady_clock::time_point maxWhenElapsed;
    std::chrono::steady_clock::time_point expectedWhenElapsed;
    std::chrono::steady_clock::time_point expectedMaxWhenElapsed;
    std::chrono::milliseconds repeatInterval;
    std::chrono::milliseconds offset;
    std::string bundleName;

    TimerInfo(uint64_t id, int type,
        std::chrono::milliseconds when,
        std::chrono::steady_clock::time_point whenElapsed,
        std::chrono::milliseconds windowLength,
        std::chrono::steady_clock::time_point maxWhen,
        std::chrono::milliseconds interval,
        std::function<void (const uint64_t)> callback,
        std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
        uint32_t flags,
        int uid,
        int pid,
        const std::string &bundleName);
    virtual ~TimerInfo() = default;
    bool operator==(const TimerInfo &other) const;
    bool Matches(const std::string &packageName) const;
    bool UpdateWhenElapsedFromNow(std::chrono::steady_clock::time_point now, std::chrono::nanoseconds offset);
    bool AdjustTimer(const std::chrono::steady_clock::time_point &now, const uint32_t interval);
    bool RestoreAdjustTimer();
};
} // MiscService
} // OHOS
#endif