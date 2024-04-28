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

#include "simple_timer_info.h"
#include "time_common.h"
#include "time_service_stub.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::HiviewDFX;
namespace {
static const uint32_t MAX_EXEMPTION_SIZE = 1000;
static const int MAX_PID_LIST_SIZE = 1024;
}


TimeServiceStub::TimeServiceStub()
{
    memberFuncMap_[TimeServiceIpcInterfaceCode::SET_TIME] = &TimeServiceStub::OnSetTime;
    memberFuncMap_[TimeServiceIpcInterfaceCode::SET_TIME_ZONE] = &TimeServiceStub::OnSetTimeZone;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_TIME_ZONE] = &TimeServiceStub::OnGetTimeZone;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_WALL_TIME_MILLI] = &TimeServiceStub::OnGetWallTimeMs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_WALL_TIME_NANO] = &TimeServiceStub::OnGetWallTimeNs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_BOOT_TIME_MILLI] = &TimeServiceStub::OnGetBootTimeMs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_BOOT_TIME_NANO] = &TimeServiceStub::OnGetBootTimeNs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_MONO_TIME_MILLI] = &TimeServiceStub::OnGetMonotonicTimeMs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_MONO_TIME_NANO] = &TimeServiceStub::OnGetMonotonicTimeNs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_THREAD_TIME_MILLI] = &TimeServiceStub::OnGetThreadTimeMs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::GET_THREAD_TIME_NANO] = &TimeServiceStub::OnGetThreadTimeNs;
    memberFuncMap_[TimeServiceIpcInterfaceCode::CREATE_TIMER] = &TimeServiceStub::OnCreateTimer;
    memberFuncMap_[TimeServiceIpcInterfaceCode::START_TIMER] = &TimeServiceStub::OnStartTimer;
    memberFuncMap_[TimeServiceIpcInterfaceCode::STOP_TIMER] = &TimeServiceStub::OnStopTimer;
    memberFuncMap_[TimeServiceIpcInterfaceCode::DESTROY_TIMER] = &TimeServiceStub::OnDestroyTimer;
    memberFuncMap_[TimeServiceIpcInterfaceCode::PROXY_TIMER] = &TimeServiceStub::OnTimerProxy;
    memberFuncMap_[TimeServiceIpcInterfaceCode::PID_PROXY_TIMER] = &TimeServiceStub::OnPidTimerProxy;
    memberFuncMap_[TimeServiceIpcInterfaceCode::ADJUST_TIMER] = &TimeServiceStub::OnAdjustTimer;
    memberFuncMap_[TimeServiceIpcInterfaceCode::SET_TIMER_EXEMPTION] = &TimeServiceStub::OnSetTimerExemption;
    memberFuncMap_[TimeServiceIpcInterfaceCode::RESET_ALL_PROXY] = &TimeServiceStub::OnAllProxyReset;
}

TimeServiceStub::~TimeServiceStub()
{
    memberFuncMap_.clear();
}

int32_t TimeServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start##code = %{public}u", code);
    std::u16string descriptor = TimeServiceStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##descriptor checked fail");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    pid_t p = IPCSkeleton::GetCallingPid();
    pid_t p1 = IPCSkeleton::GetCallingUid();
    TIME_HILOGD(TIME_MODULE_SERVICE, "CallingPid = %{public}d, CallingUid = %{public}d, code = %{public}u", p, p1,
                code);
    if (code >= static_cast<uint32_t>(TimeServiceIpcInterfaceCode::SET_TIME) &&
        code <= static_cast<uint32_t>(TimeServiceIpcInterfaceCode::SET_TIMER_EXEMPTION)) {
        auto itFunc = memberFuncMap_.find(static_cast<TimeServiceIpcInterfaceCode>(code));
        if (itFunc != memberFuncMap_.end()) {
            auto memberFunc = itFunc->second;
            if (memberFunc != nullptr) {
                return (this->*memberFunc)(data, reply);
            }
        }
    }
    int ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
    return ret;
}

int32_t TimeServiceStub::OnSetTime(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time = data.ReadInt64();
    auto apiVersion = data.ReadInt8();
    if (apiVersion == APIVersion::API_VERSION_9) {
        if (!TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "not system applications");
            return E_TIME_NOT_SYSTEM_APP;
        }
    }
    if (!TimePermission::CheckCallingPermission(TimePermission::setTime)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "permission check setTime failed");
        return E_TIME_NO_PERMISSION;
    }
    int32_t ret = SetTime(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
    return ret;
}

int32_t TimeServiceStub::OnSetTimeZone(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    std::string timeZoneId = data.ReadString();
    auto apiVersion = data.ReadInt8();
    if (apiVersion == APIVersion::API_VERSION_9) {
        if (!TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "not system applications");
            return E_TIME_NOT_SYSTEM_APP;
        }
    }
    if (!TimePermission::CheckCallingPermission(TimePermission::setTimeZone)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "permission check setTime failed");
        return E_TIME_NO_PERMISSION;
    }
    int32_t ret = SetTimeZone(timeZoneId);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
    return ret;
}

int32_t TimeServiceStub::OnGetTimeZone(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    std::string timeZoneId;
    int32_t ret = GetTimeZone(timeZoneId);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteString(timeZoneId);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetWallTimeMs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetWallTimeMs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetWallTimeNs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetWallTimeNs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetBootTimeMs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetBootTimeMs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetBootTimeNs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetBootTimeNs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetMonotonicTimeMs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetMonotonicTimeMs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetMonotonicTimeNs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetMonotonicTimeNs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetThreadTimeMs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetThreadTimeMs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnGetThreadTimeNs(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " start.");
    int64_t time;
    int32_t ret = GetThreadTimeNs(time);
    if (ret != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " end##ret = %{public}d", ret);
        return ret;
    }
    reply.WriteInt64(time);
    TIME_HILOGD(TIME_MODULE_SERVICE, " end.");
    return ret;
}

int32_t TimeServiceStub::OnCreateTimer(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (!TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "not system applications");
        return E_TIME_NOT_SYSTEM_APP;
    }
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent{ nullptr };
    auto type = data.ReadInt32();
    auto repeat = data.ReadBool();
    auto interval = data.ReadUint64();
    if (data.ReadBool()) {
        wantAgent = std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent>(
            data.ReadParcelable<OHOS::AbilityRuntime::WantAgent::WantAgent>());
        if (!wantAgent) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Input wantagent nullptr");
            return E_TIME_NULLPTR;
        }
    }
    sptr<IRemoteObject> obj = data.ReadRemoteObject();
    if (obj == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Input nullptr");
        return E_TIME_NULLPTR;
    }
    auto timerOptions = std::make_shared<SimpleTimerInfo>();
    timerOptions->type = type;
    timerOptions->repeat = repeat;
    timerOptions->interval = interval;
    timerOptions->wantAgent = wantAgent;
    uint64_t timerId = data.ReadUint64();
    auto errCode = CreateTimer(timerOptions, obj, timerId);
    if (errCode != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Create timer failed");
        return E_TIME_DEAL_FAILED;
    }
    if (!reply.WriteUint64(timerId)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Failed to write timerId");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnStartTimer(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (!TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "not system applications");
        return E_TIME_NOT_SYSTEM_APP;
    }
    auto timerId = data.ReadUint64();
    auto triggerTime = data.ReadUint64();
    if (StartTimer(timerId, triggerTime) != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Failed to start timer");
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnStopTimer(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (!TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "not system applications");
        return E_TIME_NOT_SYSTEM_APP;
    }
    auto timerId = data.ReadUint64();
    if (StopTimer(timerId) != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Failed to stop timer");
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnDestroyTimer(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (!TimePermission::CheckSystemUidCallingPermission(IPCSkeleton::GetCallingFullTokenID())) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "not system applications");
        return E_TIME_NOT_SYSTEM_APP;
    }
    auto timerId = data.ReadUint64();
    if (DestroyTimer(timerId) != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Failed to destory timer");
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnTimerProxy(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    auto uid = data.ReadInt32();
    if (uid == 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Error param uid.");
        return E_TIME_READ_PARCEL_ERROR;
    }
    auto isProxy = data.ReadBool();
    auto needRetrigger = data.ReadBool();
    if (!ProxyTimer(uid, isProxy, needRetrigger)) {
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnPidTimerProxy(MessageParcel &data, MessageParcel &reply)
{
    auto pidListSize = data.ReadInt32();
    std::set<int> pidList;
    if (pidListSize == 0 || pidListSize > MAX_PID_LIST_SIZE) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Error pid list size.");
        return E_TIME_READ_PARCEL_ERROR;
    }
    for (int i = 0; i < pidListSize; i++) {
        auto pid = data.ReadInt32();
        if (pid != 0) {
            pidList.insert(pid);
        }
    }
    if (pidList.size() == 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Error pidList.");
        return E_TIME_READ_PARCEL_ERROR;
    }
    auto isProxy = data.ReadBool();
    auto needRetrigger = data.ReadBool();
    if (!ProxyTimer(pidList, isProxy, needRetrigger)) {
        return E_TIME_DEAL_FAILED;
    }
    return ERR_OK;
}

int32_t TimeServiceStub::OnAdjustTimer(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "on timer adjust start.");
    if (!TimePermission::CheckProxyCallingPermission()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Adjust Timer permission check failed");
        return E_TIME_NO_PERMISSION;
    }
    bool isAdjust = false;
    uint32_t interval = 0;
    if (!data.ReadBool(isAdjust)) {
        return E_TIME_READ_PARCEL_ERROR;
    }
    if (!data.ReadUint32(interval)) {
        return E_TIME_READ_PARCEL_ERROR;
    }
    if (isAdjust && interval == 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "invalid parameter: interval");
        return E_TIME_READ_PARCEL_ERROR;
    }
    if (AdjustTimer(isAdjust, interval) != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Error adjust timer.");
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "on timer adjust end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnSetTimerExemption(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "set timer exemption start.");
    if (!TimePermission::CheckProxyCallingPermission()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Set Timer Exemption permission check failed");
        return E_TIME_NO_PERMISSION;
    }
    std::unordered_set<std::string> nameArr;
    uint32_t size;
    bool isExemption;
    if (!data.ReadUint32(size)) {
        return E_TIME_READ_PARCEL_ERROR;
    }
    if (size > MAX_EXEMPTION_SIZE) {
        return E_TIME_PARAMETERS_INVALID;
    }
    for (uint32_t i = 0; i < size; ++i) {
        std::string name;
        if (!data.ReadString(name)) {
            return E_TIME_READ_PARCEL_ERROR;
        }
        nameArr.insert(name);
    }

    if (!data.ReadBool(isExemption)) {
        return E_TIME_READ_PARCEL_ERROR;
    }
    SetTimerExemption(nameArr, isExemption);
    TIME_HILOGD(TIME_MODULE_SERVICE, "set timer exemption end.");
    return ERR_OK;
}

int32_t TimeServiceStub::OnAllProxyReset(MessageParcel &data, MessageParcel &reply)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    if (!ResetAllProxy()) {
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
    return ERR_OK;
}
} // namespace MiscServices
} // namespace OHOS