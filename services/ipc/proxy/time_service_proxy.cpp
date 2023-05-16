/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is: distributed on an "AS is:"BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "time_service_proxy.h"

#include "iremote_broker.h"
#include "time_common.h"
#include "time_service_interface.h"

namespace OHOS {
namespace MiscServices {
using namespace OHOS::HiviewDFX;

TimeServiceProxy::TimeServiceProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<ITimeService>(object)
{
}

int32_t TimeServiceProxy::SetTime(const int64_t time, APIVersion apiVersion)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt64(time)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write time");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt8(apiVersion)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write apiVersion");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(SET_TIME, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "SetTime failed, error code is: %{public}d", result);
        return result;
    }
    return result;
}

int32_t TimeServiceProxy::CreateTimer(const std::shared_ptr<ITimerInfo> &timerOptions,
    sptr<IRemoteObject> &timerCallback, uint64_t &timerId)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(timerOptions->type)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write type");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteBool(timerOptions->repeat)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write repeat");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(timerOptions->interval)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write interval");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteBool(timerOptions->wantAgent != nullptr)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write wantAgent status");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (timerOptions->wantAgent != nullptr) {
        if (!data.WriteParcelable(&(*timerOptions->wantAgent))) {
            TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write wantAgent");
            return E_TIME_WRITE_PARCEL_ERROR;
        }
    }
    if (!data.WriteRemoteObject(timerCallback)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write timerCallback");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    auto ret = Remote()->SendRequest(CREATE_TIMER, data, reply, option);
    if (ret == E_TIME_OK) {
        timerId = reply.ReadUint64();
        return E_TIME_OK;
    }
    return ret;
}

int32_t TimeServiceProxy::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(timerId)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write timerId");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(triggerTime)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write triggerTime");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    return Remote()->SendRequest(START_TIMER, data, reply, option);
}

int32_t TimeServiceProxy::StopTimer(uint64_t timerId)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(timerId)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write timerId");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    return Remote()->SendRequest(STOP_TIMER, data, reply, option);
}

int32_t TimeServiceProxy::DestroyTimer(uint64_t timerId)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(timerId)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write timerId");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    return Remote()->SendRequest(DESTROY_TIMER, data, reply, option);
}

int32_t TimeServiceProxy::SetTimeZone(const std::string &timeZoneId, APIVersion apiVersion)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(timeZoneId)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write timeZoneId");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt8(apiVersion)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write apiVersion");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(SET_TIME_ZONE, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "SetTimeZone failed, error code is: %{public}d", result);
        return result;
    }
    return result;
}

int32_t TimeServiceProxy::GetTimeZone(std::string &timeZoneId)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_TIME_ZONE, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetTimeZone failed, error code is: %{public}d", result);
        return result;
    }
    timeZoneId = reply.ReadString();
    return result;
}

int32_t TimeServiceProxy::GetWallTimeMs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_WALL_TIME_MILLI, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetWallTimeMs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetWallTimeNs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_WALL_TIME_NANO, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetWallTimeNs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetBootTimeMs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_BOOT_TIME_MILLI, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetBootTimeMs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetBootTimeNs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_BOOT_TIME_NANO, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetBootTimeNs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetMonotonicTimeMs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_MONO_TIME_MILLI, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetMonotonicTimeMs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetMonotonicTimeNs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_MONO_TIME_NANO, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetMonotonicTimeNs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetThreadTimeMs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_THREAD_TIME_MILLI, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetThreadTimeMs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

int32_t TimeServiceProxy::GetThreadTimeNs(int64_t &times)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return E_TIME_WRITE_PARCEL_ERROR;
    }
    int32_t result = Remote()->SendRequest(GET_THREAD_TIME_NANO, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "GetThreadTimeNs failed, error code is: %{public}d", result);
        return result;
    }
    times = reply.ReadInt64();
    return result;
}

bool TimeServiceProxy::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return false;
    }
    if (!data.WriteInt32(uid)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write uid");
        return false;
    }
    if (!data.WriteBool(isProxy)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write isProxy");
        return false;
    }
    if (!data.WriteBool(needRetrigger)) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write needRetrigger");
        return false;
    }
    int32_t result = Remote()->SendRequest(PROXY_TIMER, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "ProxyTimer failed, error code is: %{public}d", result);
        return false;
    }
    return true;
}

bool TimeServiceProxy::ResetAllProxy()
{
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Failed to write descriptor");
        return false;
    }
    int32_t result = Remote()->SendRequest(RESET_ALL_PROXY, data, reply, option);
    if (result != ERR_NONE) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "ProxyTimer failed, error code is: %{public}d", result);
        return false;
    }
    return true;
}
} // namespace MiscServices
} // namespace OHOS