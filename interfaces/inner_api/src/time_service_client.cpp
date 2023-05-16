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

#include "time_service_client.h"

#include <cinttypes>
#include <mutex>

#include "iremote_object.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "time_common.h"

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
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return false;
    }
    return proxy->SetTime(time) == ERR_OK;
}

bool TimeServiceClient::SetTime(const int64_t milliseconds, int32_t &code)
{
    if (!ConnectService()) {
        code = E_TIME_SA_DIED;
        return false;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        code = E_TIME_NULLPTR;
        return false;
    }
    code = proxy->SetTime(milliseconds);
    return code == ERR_OK;
}

int32_t TimeServiceClient::SetTimeV9(const int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    return proxy->SetTime(time, ITimeService::API_VERSION_9);
}

bool TimeServiceClient::SetTimeZone(const std::string timezoneId)
{
    if (!ConnectService()) {
        return false;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return false;
    }
    return proxy->SetTimeZone(timezoneId) == ERR_OK;
}

bool TimeServiceClient::SetTimeZone(const std::string timezoneId, int32_t &code)
{
    if (!ConnectService()) {
        code = E_TIME_SA_DIED;
        return false;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        code =  E_TIME_NULLPTR;
        return false;
    }
    code = proxy->SetTimeZone(timezoneId);
    TIME_HILOGI(TIME_MODULE_CLIENT, "settimezone end");
    return code == ERR_OK;
}

int32_t TimeServiceClient::SetTimeZoneV9(const std::string timezoneId)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    return proxy->SetTimeZone(timezoneId, ITimeService::API_VERSION_9);
}

uint64_t TimeServiceClient::CreateTimer(std::shared_ptr<ITimerInfo> TimerOptions)
{
    uint64_t timerId = 0;
    auto errCode = CreateTimerV9(TimerOptions, timerId);
    TIME_HILOGI(TIME_MODULE_SERVICE, "CreateTimer id: %{public}" PRId64 "", timerId);
    if (errCode != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Non-system applications, create timer failed");
        return 0;
    }
    if (timerId == 0) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Create timer failed");
        return 0;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "CreateTimer id: %{public}" PRId64 "", timerId);
    return timerId;
}

int32_t TimeServiceClient::CreateTimerV9(std::shared_ptr<ITimerInfo> timerOptions, uint64_t &timerId)
{
    if (timerOptions == nullptr) {
        TIME_HILOGW(TIME_MODULE_CLIENT, "Input nullptr");
        return E_TIME_NULLPTR;
    }
    if (!ConnectService()) {
        return E_TIME_NULLPTR;
    }
    auto timerCallbackInfoObject = TimerCallback::GetInstance()->AsObject();
    if (!timerCallbackInfoObject) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "New TimerCallback failed");
        return E_TIME_NULLPTR;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    auto errCode = proxy->CreateTimer(timerOptions, timerCallbackInfoObject, timerId);
    if (errCode != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "create timer failed");
        return errCode;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "CreateTimer id: %{public}" PRId64 "", timerId);
    auto ret = TimerCallback::GetInstance()->InsertTimerCallbackInfo(timerId, timerOptions);
    if (!ret) {
        return E_TIME_DEAL_FAILED;
    }
    return errCode;
}

bool TimeServiceClient::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    int32_t errCode = StartTimerV9(timerId, triggerTime);
    if (errCode != E_TIME_OK) {
        return false;
    }
    return true;
}

int32_t TimeServiceClient::StartTimerV9(uint64_t timerId, uint64_t triggerTime)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    return proxy->StartTimer(timerId, triggerTime);
}

bool TimeServiceClient::StopTimer(uint64_t timerId)
{
    int32_t errCode = StopTimerV9(timerId);
    if (errCode != E_TIME_OK) {
        return false;
    }
    return true;
}

int32_t TimeServiceClient::StopTimerV9(uint64_t timerId)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    return proxy->StopTimer(timerId);
}

bool TimeServiceClient::DestroyTimer(uint64_t timerId)
{
    int32_t errCode = DestroyTimerV9(timerId);
    if (errCode != E_TIME_OK) {
        return false;
    }
    return true;
}

int32_t TimeServiceClient::DestroyTimerV9(uint64_t timerId)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    auto errCode = proxy->DestroyTimer(timerId);
    if (errCode == E_TIME_OK) {
        TimerCallback::GetInstance()->RemoveTimerCallbackInfo(timerId);
        return E_TIME_OK;
    }
    return errCode;
}

std::string TimeServiceClient::GetTimeZone()
{
    std::string timeZoneId;
    if (!ConnectService()) {
        return std::string("");
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return std::string("");
    }
    if (proxy->GetTimeZone(timeZoneId) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return std::string("");
    }
    return timeZoneId;
}

int32_t TimeServiceClient::GetTimeZone(std::string &timezoneId)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetTimeZone(timezoneId) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetWallTimeMs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetWallTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetWallTimeMs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetWallTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetWallTimeNs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetWallTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetWallTimeNs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetWallTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetBootTimeMs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetBootTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetBootTimeMs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetBootTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetBootTimeNs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetBootTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetBootTimeNs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetBootTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetMonotonicTimeMs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetMonotonicTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetMonotonicTimeMs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetMonotonicTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetMonotonicTimeNs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetMonotonicTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetMonotonicTimeNs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetMonotonicTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetThreadTimeMs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetThreadTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetThreadTimeMs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetThreadTimeMs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
}

int64_t TimeServiceClient::GetThreadTimeNs()
{
    int64_t time;
    if (!ConnectService()) {
        return -1;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetThreadTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return -1;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return time;
}

int32_t TimeServiceClient::GetThreadTimeNs(int64_t &time)
{
    if (!ConnectService()) {
        return E_TIME_SA_DIED;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return E_TIME_NULLPTR;
    }
    if (proxy->GetThreadTimeNs(time) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "get failed.");
        return E_TIME_SA_DIED;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Result: %{public}" PRId64 "", time);
    return E_TIME_OK;
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
    TimeServiceClient::GetInstance()->ClearProxy();
    TimeServiceClient::GetInstance()->OnRemoteSaDied(object);
}

bool TimeServiceClient::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    TIME_HILOGD(TIME_MODULE_CLIENT, "ProxyTimer start uid: %{public}d, isProxy: %{public}d", uid, isProxy);
    if (!ConnectService()) {
        return false;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return false;
    }
    return proxy->ProxyTimer(uid, isProxy, needRetrigger);
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
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        return false;
    }
    return proxy->ResetAllProxy();
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

void TimeServiceClient::ClearProxy()
{
    std::lock_guard<std::mutex> autoLock(proxyLock_);
    timeServiceProxy_ = nullptr;
}
} // namespace MiscServices
} // namespace OHOS