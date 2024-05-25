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

#include "timer_info.h"

#include <cinttypes>

#include "time_hilog.h"

namespace OHOS {
namespace MiscServices {
bool TimerInfo::operator==(const TimerInfo &other) const
{
    return this->id == other.id;
}

bool TimerInfo::Matches(const std::string &packageName) const
{
    return false;
}

TimerInfo::TimerInfo(uint64_t _id, int _type,
                     std::chrono::milliseconds _when,
                     std::chrono::steady_clock::time_point _whenElapsed,
                     std::chrono::milliseconds _windowLength,
                     std::chrono::steady_clock::time_point _maxWhen,
                     std::chrono::milliseconds _interval,
                     std::function<void(const uint64_t)> _callback,
                     std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> _wantAgent,
                     uint32_t _flags,
                     int _uid,
                     int _pid,
                     const std::string &_bundleName)
    : id {_id},
      type {_type},
      origWhen {_when},
      wakeup {_type == ITimerManager::ELAPSED_REALTIME_WAKEUP || _type == ITimerManager::RTC_WAKEUP},
      callback {std::move(_callback)},
      wantAgent {_wantAgent},
      flags {_flags},
      uid {_uid},
      pid {_pid},
      when {_when},
      windowLength {_windowLength},
      whenElapsed {_whenElapsed},
      maxWhenElapsed {_maxWhen},
      expectedWhenElapsed {_whenElapsed},
      expectedMaxWhenElapsed {_maxWhen},
      repeatInterval {_interval},
      bundleName {_bundleName}
{
    originWhenElapsed = _whenElapsed;
    originMaxWhenElapsed = _maxWhen;
}

/* Please make sure that the first param is current boottime */
bool TimerInfo::UpdateWhenElapsedFromNow(std::chrono::steady_clock::time_point now, std::chrono::nanoseconds offset)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Update whenElapsed, id=%{public}" PRId64 "", id);
    auto oldWhenElapsed = whenElapsed;
    whenElapsed = now + offset;
    auto oldMaxWhenElapsed = maxWhenElapsed;
    maxWhenElapsed = whenElapsed + windowLength;
    expectedWhenElapsed = whenElapsed;
    expectedMaxWhenElapsed = maxWhenElapsed;
    std::chrono::milliseconds currentTime;
    if (type == ITimerManager::RTC || type == ITimerManager::RTC_WAKEUP) {
        currentTime =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    } else {
        currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    }
    auto offsetMill = std::chrono::duration_cast<std::chrono::milliseconds>(offset);
    when = currentTime + offsetMill;
    return (oldWhenElapsed != whenElapsed) || (oldMaxWhenElapsed != maxWhenElapsed);
}

bool TimerInfo::AdjustTimer(const std::chrono::steady_clock::time_point &now, const uint32_t interval)
{
    auto oldWhenElapsed = whenElapsed;
    auto oldMaxWhenElapsed = maxWhenElapsed;
    std::chrono::duration<int, std::ratio<1, HALF_SECEND>> halfIntervalSec(interval);
    std::chrono::duration<int, std::ratio<1, 1>> intervalSec(interval);
    auto oldTimeSec = std::chrono::duration_cast<std::chrono::seconds>(whenElapsed.time_since_epoch());
    auto timeSec = ((oldTimeSec + halfIntervalSec) / intervalSec) * intervalSec;
    whenElapsed = std::chrono::steady_clock::time_point(timeSec);
    if (windowLength == std::chrono::milliseconds::zero()) {
        maxWhenElapsed = whenElapsed;
    } else {
        auto oldMaxTimeSec = std::chrono::duration_cast<std::chrono::seconds>(maxWhenElapsed.time_since_epoch());
        auto maxTimeSec = ((oldMaxTimeSec + halfIntervalSec) / intervalSec) * intervalSec;
        maxWhenElapsed = std::chrono::steady_clock::time_point(maxTimeSec);
    }
    if (whenElapsed < now) {
        whenElapsed += std::chrono::duration_cast<std::chrono::milliseconds>(intervalSec);
    }
    if (maxWhenElapsed < now) {
        maxWhenElapsed += std::chrono::duration_cast<std::chrono::milliseconds>(intervalSec);
    }
    auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
        whenElapsed.time_since_epoch() - oldWhenElapsed.time_since_epoch());
    when = when + delta;
    return (oldWhenElapsed != whenElapsed) || (oldMaxWhenElapsed != maxWhenElapsed);
}

bool TimerInfo::RestoreAdjustTimer()
{
    auto oldWhenElapsed = whenElapsed;
    auto oldMaxWhenElapsed = maxWhenElapsed;
    whenElapsed = originWhenElapsed;
    maxWhenElapsed = originMaxWhenElapsed;
    auto delta = std::chrono::duration_cast<std::chrono::milliseconds>(
        whenElapsed.time_since_epoch() - oldWhenElapsed.time_since_epoch());
    when = when + delta;
    return (oldWhenElapsed != whenElapsed) || (oldMaxWhenElapsed != maxWhenElapsed);
}
} // MiscServices
} // OHOS