/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "timer_call_back.h"
#include "timer_notify_call_back.h"

namespace OHOS {
namespace MiscServices {
std::mutex TimerCallback::instanceLock_;
sptr<TimerCallback> TimerCallback::instance_;

std::map<uint64_t, std::shared_ptr<ITimerInfo>> TimerCallback::timerInfoMap_;
std::mutex TimerCallback::timerInfoMutex_;

TimerCallback::TimerCallback()
{
}

TimerCallback::~TimerCallback()
{
    timerInfoMap_.clear();
}

sptr<TimerCallback> TimerCallback::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new TimerCallback;
        }
    }
    return instance_;
}

bool TimerCallback::InsertTimerCallbackInfo(const uint64_t timerId, const std::shared_ptr<ITimerInfo> &timerInfo)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (timerInfo == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> lock(timerInfoMutex_);
    auto info = timerInfoMap_.find(timerId);
    if (info != timerInfoMap_.end()) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "timer info already insert.");
        return false;
    } else {
        timerInfoMap_[timerId] = timerInfo;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return true;
}

bool TimerCallback::RemoveTimerCallbackInfo(const uint64_t timerId)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::lock_guard<std::mutex> lock(timerInfoMutex_);
    auto info = timerInfoMap_.find(timerId);
    if (info != timerInfoMap_.end()) {
        timerInfoMap_.erase(info);
        TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
        return true;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return false;
}

void TimerCallback::NotifyTimer(const uint64_t timerId, const sptr<IRemoteObject> &timerCallback)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    std::shared_ptr<ITimerInfo> timerInfo;
    {
        std::lock_guard<std::mutex> lock(timerInfoMutex_);
        auto it = timerInfoMap_.find(timerId);
        if (it != timerInfoMap_.end()) {
            TIME_HILOGD(TIME_MODULE_SERVICE, "ontrigger.");
            timerInfo = it->second;
        }
    }
    if (timerInfo != nullptr) {
        timerInfo->OnTrigger();
    }
    if (timerCallback == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "timerCallback nullptr timerId:%{public}" PRId64 "", timerId);
        return;
    }
    sptr<ITimerNotifyCallback> timerNotifyCallback = iface_cast<ITimerNotifyCallback>(timerCallback);
    if (timerNotifyCallback == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "timerNotifyCallback nullptr timerId:%{public}" PRId64 "", timerId);
        return;
    }
    timerNotifyCallback->Finish(timerId);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
}
} // namespace MiscServices
} // namespace OHOS
