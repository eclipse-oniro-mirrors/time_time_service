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

#ifndef TIMER_PACKAGE_SUBSCRIBER_H
#define TIMER_PACKAGE_SUBSCRIBER_H

#include "common_event_data.h"
#include "common_event_subscribe_info.h"
#include "common_event_subscriber.h"

namespace OHOS {
namespace MiscServices {
class PackageRemovedSubscriber : public EventFwk::CommonEventSubscriber {
public:
    PackageRemovedSubscriber(EventFwk::CommonEventSubscribeInfo &subscribeInfo);
    ~PackageRemovedSubscriber() = default;
    void OnReceiveEvent(const EventFwk::CommonEventData &data) override;
};

void SubscribeCommonEvent();
} // namespace MiscServices
} // namespace OHOS
#endif // TIMER_PACKAGE_SUBSCRIBER_H
