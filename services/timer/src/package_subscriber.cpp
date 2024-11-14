/*
* Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include <string>

#include "package_subscriber.h"
#include "timer_manager.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"

namespace OHOS {
namespace MiscServices {
PackageRemovedSubscriber::PackageRemovedSubscriber(EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : CommonEventSubscriber(subscribeInfo)
{
}

void PackageRemovedSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action != EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_REMOVED &&
        action != EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED) {
        return;
    }
    auto uid = data.GetWant().GetIntParam(std::string("uid"), -1);
    auto timerManager = TimerManager::GetInstance();
    if (timerManager == nullptr) {
        return;
    }
    timerManager->OnPackageRemoved(uid);
}
} // namespace MiscServices
} // namespace OHOS