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

#ifndef SERVICES_INCLUDE_TIME_SERVICE_PROXY_H
#define SERVICES_INCLUDE_TIME_SERVICE_PROXY_H

#include "iremote_proxy.h"
#include "time_service_interface.h"

namespace OHOS {
namespace MiscServices {
class TimeServiceProxy : public IRemoteProxy<ITimeService> {
public:
    explicit TimeServiceProxy(const sptr<IRemoteObject> &object);
    ~TimeServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(TimeServiceProxy);

    int32_t SetTime(int64_t time, APIVersion apiVersion = APIVersion::API_VERSION_7) override;
    int32_t SetTimeZone(const std::string &timeZoneId, APIVersion apiVersion = APIVersion::API_VERSION_7) override;
    int32_t GetTimeZone(std::string &timeZoneId) override;
    int32_t GetWallTimeMs(int64_t &times) override;
    int32_t GetWallTimeNs(int64_t &times) override;
    int32_t GetBootTimeMs(int64_t &times) override;
    int32_t GetBootTimeNs(int64_t &times) override;
    int32_t GetMonotonicTimeMs(int64_t &times) override;
    int32_t GetMonotonicTimeNs(int64_t &times) override;
    int32_t GetThreadTimeMs(int64_t &times) override;
    int32_t GetThreadTimeNs(int64_t &times) override;
    int32_t CreateTimer(const std::shared_ptr<ITimerInfo> &timerOptions, sptr<IRemoteObject> &timerCallback,
        uint64_t &timerId) override;
    int32_t StartTimer(uint64_t timerId, uint64_t triggerTime) override;
    int32_t StopTimer(uint64_t timerId) override;
    int32_t DestroyTimer(uint64_t timerId) override;
    bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger) override;
    bool ResetAllProxy() override;
private:
    static inline BrokerDelegator<TimeServiceProxy> delegator_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_TIME_SERVICE_PROXY_H