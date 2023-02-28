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

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "time_service_notify.h"

using namespace OHOS::AAFwk;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace MiscServices {
TimeServiceNotify::TimeServiceNotify() {};
TimeServiceNotify::~TimeServiceNotify() {};

bool TimeServiceNotify::RepublishEvents()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "start to Republish events");
    auto currentTime = std::chrono::steady_clock::now().time_since_epoch().count();
    return PublishTimeChangeEvents(currentTime) && PublishTimeZoneChangeEvents(currentTime) &&
           PublishTimeTickEvents(currentTime);
}

bool TimeServiceNotify::PublishEvents(int64_t eventTime, const IntentWant &want, const PublishInfo &publishInfo)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Start to publish event %{public}s at %{public}lld", want.GetAction().c_str(),
        static_cast<long long>(eventTime));
    CommonEventData event(want);
    if (!CommonEventManager::PublishCommonEvent(event, publishInfo, nullptr)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to Publish event %{public}s", want.GetAction().c_str());
        return false;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Publish event %{public}s done", want.GetAction().c_str());
    return true;
}

bool TimeServiceNotify::PublishTimeChangeEvents(int64_t eventTime)
{
    IntentWant timeChangeWant;
    timeChangeWant.SetAction(CommonEventSupport::COMMON_EVENT_TIME_CHANGED);
    return PublishEvents(eventTime, timeChangeWant, CommonEventPublishInfo());
}

bool TimeServiceNotify::PublishTimeZoneChangeEvents(int64_t eventTime)
{
    IntentWant timeZoneChangeWant;
    timeZoneChangeWant.SetAction(CommonEventSupport::COMMON_EVENT_TIMEZONE_CHANGED);
    return PublishEvents(eventTime, timeZoneChangeWant, CommonEventPublishInfo());
}

bool TimeServiceNotify::PublishTimeTickEvents(int64_t eventTime)
{
    IntentWant timeTickWant;
    timeTickWant.SetAction(CommonEventSupport::COMMON_EVENT_TIME_TICK);
    return PublishEvents(eventTime, timeTickWant, CommonEventPublishInfo());
}
} // namespace MiscServices
} // namespace OHOS
