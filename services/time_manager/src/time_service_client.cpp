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

#include <cinttypes>
#include <mutex>
#include "time_common.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "time_service_client.h"

namespace OHOS {
namespace MiscServices {
std::mutex TimeServiceClient::instanceLock_;
sptr<TimeServiceClient> TimeServiceClient::instance_;
sptr<TimeSaDeathRecipient> deathRecipient_;
TimeServiceClient::TimeServiceClient()
{
}

TimeServiceClient::~TimeServiceClient()
{
    auto proxy = GetProxy();
    if (proxy != nullptr) {
        auto remoteObject = proxy->AsObject();
        if (remoteObject != nullptr) {
            remoteObject->RemoveDeathRecipient(deathRecipient_);
        }
    }
}

sptr<TimeServiceClient> TimeServiceClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new TimeServiceClient;
        }
    }
    return instance_;
}

bool TimeServiceClient::ConnectService()
{
    if (GetProxy() != nullptr) {
        return true;
    }
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Getting SystemAbilityManager failed.");
        return false;
    }

    auto systemAbility = systemAbilityManager->GetSystemAbility(TIME_SERVICE_ID);
    if (systemAbility == nullptr) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Get SystemAbility failed.");
        return false;
    }
    deathRecipient_ = new TimeSaDeathRecipient();
    systemAbility->AddDeathRecipient(deathRecipient_);
    sptr<ITimeService> proxy = iface_cast<ITimeService>(systemAbility);
    if (proxy == nullptr) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Get TimeServiceProxy from SA failed.");
        return false;
    }
    SetProxy(proxy);
    return true;
}

bool TimeServiceClient::SetTime(const int64_t time)
{
    if (!ConnectService()) {
        return false;
    }
    return GetProxy()->SetTime(time) == ERR_OK;
}

bool TimeServiceClient::SetTime(const int64_t milliseconds, int32_t &code)
{
    if (!ConnectService()) {
        code = E_TIME_SA_DIED;
        return false;
    }
    code = GetProxy()->SetTime(milliseconds);
    return code == ERR_OK;
}

bool TimeServiceClient::SetTimeZone(const std::string timezoneId)
{
    if (!ConnectService()) {
        return false;
    }
    return GetProxy()->SetTimeZone(timezoneId) == ERR_OK;
}

bool TimeServiceClient::SetTimeZone(const std::string timezoneId, int32_t &code)
{
    if (!ConnectService()) {
        code = E_TIME_SA_DIED;
        return false;
    }
    code = GetProxy()->SetTimeZone(timezoneId);
    return code == ERR_OK;
}

uint64_t TimeServiceClient::CreateTimer(std::shared_ptr<ITimerInfo> TimerOptions)
{
    if (TimerOptions == nullptr) {
        TIME_HILOGW(TIME_MODULE_CLIENT, "Input nullptr");
        return 0;
    }
    if (!ConnectService()) {
        return false;
    }
    auto timerCallbackInfoObject = TimerCallback::GetInstance()->AsObject();
    if (!timerCallbackInfoObject) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "New TimerCallback failed");
        return 0;
    }

    auto timerId = GetProxy()->CreateTimer(TimerOptions->type,
                                           TimerOptions->repeat,
                                           TimerOptions->interval,
                                           TimerOptions->wantAgent,
                                           timerCallbackInfoObject);
    if (timerId == 0) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Create timer failed");
        return 0;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "CreateTimer id: %{public}" PRId64 "", timerId);
    auto ret = TimerCallback::GetInstance()->InsertTimerCallbackInfo(timerId, TimerOptions);
    if (!ret) {
        return 0;
    }
    return timerId;
}

bool TimeServiceClient::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    if (!ConnectService()) {
        return false;
    }
    return GetProxy()->StartTimer(timerId, triggerTime);
}

bool TimeServiceClient::StopTimer(uint64_t timerId)
{
    if (!ConnectService()) {
        return false;
    }
    return GetProxy()->StopTimer(timerId);
}

bool TimeServiceClient::DestroyTimer(uint64_t timerId)
{
    if (!ConnectService()) {
        return false;
    }
    if (GetProxy()->DestroyTimer(timerId)) {
        TimerCallback::GetInstance()->RemoveTimerCallbackInfo(timerId);
        return true;
    }
    return false;
}

std::string TimeServiceClient::GetTimeZone()
{
    std::string timeZoneId;
    if (!ConnectService()) {
        return std::string("");
    }
    if (GetProxy()->GetTimeZone(timeZoneId) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return std::string("");
    }
    return timeZoneId;
}

int64_t TimeServiceClient::GetWallTimeMs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    TIME_HILOGW(TIME_MODULE_CLIENT, "timeServiceProxy_: %{public}p", timeServiceProxy_.GetRefPtr());
    if (GetProxy()->GetWallTimeMs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetWallTimeNs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetWallTimeNs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetBootTimeMs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetBootTimeMs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetBootTimeNs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetBootTimeNs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetMonotonicTimeMs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetMonotonicTimeMs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetMonotonicTimeNs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetMonotonicTimeNs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetThreadTimeMs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetThreadTimeMs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

int64_t TimeServiceClient::GetThreadTimeNs()
{
    int64_t times;
    if (!ConnectService()) {
        return -1;
    }
    if (GetProxy()->GetThreadTimeNs(times) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", times);
    return times;
}

void TimeServiceClient::NetworkTimeStatusOff()
{
    TIME_HILOGW(TIME_MODULE_CLIENT, "start");
    if (!ConnectService()) {
        return;
    }
    GetProxy()->NetworkTimeStatusOff();
    TIME_HILOGW(TIME_MODULE_CLIENT, "end");
    return;
}

void TimeServiceClient::NetworkTimeStatusOn()
{
    TIME_HILOGW(TIME_MODULE_CLIENT, "start");
    if (!ConnectService()) {
        return;
    }
    GetProxy()->NetworkTimeStatusOn();
    TIME_HILOGW(TIME_MODULE_CLIENT, "end");
    return;
}

void TimeServiceClient::OnRemoteSaDied(const wptr<IRemoteObject> &remote)
{
    ConnectService();
}

TimeSaDeathRecipient::TimeSaDeathRecipient()
{
}

void TimeSaDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    TIME_HILOGE(TIME_MODULE_CLIENT, "TimeSaDeathRecipient on remote systemAbility died.");
    TimeServiceClient::GetInstance()->OnRemoteSaDied(object);
}

bool TimeServiceClient::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    TIME_HILOGD(TIME_MODULE_CLIENT, "ProxyTimer start uid: %{public}d, isProxy: %{public}d",
        uid, isProxy);
    if (!ConnectService()) {
        return false;
    }
    return GetProxy()->ProxyTimer(uid, isProxy, needRetrigger);
}

bool TimeServiceClient::ResetAllProxy()
{
    TIME_HILOGD(TIME_MODULE_CLIENT, "ResetAllProxy");
    if (timeServiceProxy_ == nullptr) {
        TIME_HILOGW(TIME_MODULE_CLIENT, "ResetAllProxy ConnectService");
        ConnectService();
    }
    if (timeServiceProxy_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "ResetAllProxy ConnectService failed.");
        return false;
    }
    return GetProxy()->ResetAllProxy();
}

sptr<ITimeService> TimeServiceClient::GetProxy()
{
    std::lock_guard<std::mutex> autoLock(proxyLock_);
    return timeServiceProxy_;
}

void TimeServiceClient::SetProxy(sptr<ITimeService> proxy)
{
    std::lock_guard<std::mutex> autoLock(proxyLock_);
    timeServiceProxy_ = proxy;
}
} // namespace MiscServices
} // namespace OHOS
