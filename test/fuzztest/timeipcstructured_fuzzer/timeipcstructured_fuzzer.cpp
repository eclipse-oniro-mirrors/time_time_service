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


#include "timeipcstructured_fuzzer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "iremote_object.h"
#include "itime_service.h"
#include "message_option.h"
#include "message_parcel.h"
#include "time_system_ability.h"

namespace OHOS {
namespace {
const std::u16string TIME_SERVICE_INTERFACE_TOKEN = u"OHOS.MiscServices.ITimeService";
constexpr size_t MAX_STRING_LENGTH = 48;
constexpr size_t MAX_VECTOR_LENGTH = 4;
constexpr size_t MAX_POLICY_LENGTH = 4;
constexpr uint64_t SAMPLE_SMALL_TIMER_ID = 2;
constexpr uint64_t SAMPLE_TIMER_ID = 100;
constexpr uint64_t MAX_TIMER_ID = 4096;
constexpr int32_t TIMER_TYPE_ELAPSED_REALTIME_WAKEUP = 2;
constexpr int32_t TIMER_TYPE_ELAPSED_REALTIME = 3;
constexpr uint64_t HOURS_PER_DAY = 24ULL;
constexpr uint64_t MINUTES_PER_HOUR = 60ULL;
constexpr uint64_t SECONDS_PER_MINUTE = 60ULL;
constexpr uint64_t MILLISECONDS_PER_SECOND = 1000ULL;
constexpr uint64_t MAX_TIMER_INTERVAL_MS = HOURS_PER_DAY * MINUTES_PER_HOUR * SECONDS_PER_MINUTE *
    MILLISECONDS_PER_SECOND;
constexpr int32_t MAX_UID = 4096;
constexpr int32_t MAX_PID = 4096;
constexpr int32_t INVALID_TIMER_TYPE = -1;
constexpr int32_t OUT_OF_RANGE_TIMER_TYPE = 6;
constexpr int32_t MAX_UINT8_TIMER_TYPE = 255;
constexpr uint32_t MAX_POLICY_VALUE = 2;
constexpr int MIN_API_VERSION = 7;
constexpr int MAX_API_VERSION = 12;
constexpr uint32_t MAX_ADJUST_SECONDS = 3600;
constexpr size_t MIN_OPERATION_COUNT = 1;
constexpr size_t MAX_OPERATION_COUNT = 3;

enum IpcFuzzOpcode : uint8_t {
    IPC_SET_TIME = 0,
    IPC_SET_AUTO_TIME,
    IPC_SET_TIME_ZONE,
    IPC_CREATE_TIMER,
    IPC_START_TIMER,
    IPC_STOP_TIMER,
    IPC_DESTROY_TIMER,
    IPC_PROXY_TIMER,
    IPC_ADJUST_TIMER,
    IPC_SET_TIMER_EXEMPTION,
    IPC_SET_ADJUST_POLICY,
    IPC_RESET_ALL_PROXY,
};

constexpr uint8_t MIN_OPERATION_INDEX = IPC_SET_TIME;
constexpr uint8_t MAX_OPERATION_INDEX = IPC_RESET_ALL_PROXY;

std::string ConsumeBoundedString(FuzzedDataProvider &provider, const std::vector<std::string> &values)
{
    if (provider.ConsumeBool()) {
        return values[provider.ConsumeIntegralInRange<size_t>(0, values.size() - 1)];
    }
    return provider.ConsumeRandomLengthString(MAX_STRING_LENGTH);
}

std::string ConsumeTimerName(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> timerNames = {
        "time_service", "settings", "TimerProxyState", "ipc.timer", "ohos.timer.fuzz", ""
    };
    return ConsumeBoundedString(provider, timerNames);
}

std::string ConsumeTimezone(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> timezoneIds = {
        "UTC", "Etc/UTC", "Asia/Shanghai", "Europe/London", "America/New_York", "Invalid/Zone", ""
    };
    return ConsumeBoundedString(provider, timezoneIds);
}

uint64_t ConsumeTimerId(FuzzedDataProvider &provider)
{
    static const std::vector<uint64_t> timerIds = { 0, 1, SAMPLE_SMALL_TIMER_ID, SAMPLE_TIMER_ID, MAX_TIMER_ID };
    if (provider.ConsumeBool()) {
        return timerIds[provider.ConsumeIntegralInRange<size_t>(0, timerIds.size() - 1)];
    }
    return provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TIMER_ID);
}

int32_t ConsumeTimerType(FuzzedDataProvider &provider)
{
    static const std::vector<int32_t> timerTypes = {
        0, 1, TIMER_TYPE_ELAPSED_REALTIME_WAKEUP, TIMER_TYPE_ELAPSED_REALTIME, INVALID_TIMER_TYPE,
        OUT_OF_RANGE_TIMER_TYPE, MAX_UINT8_TIMER_TYPE
    };
    return timerTypes[provider.ConsumeIntegralInRange<size_t>(0, timerTypes.size() - 1)];
}

std::vector<int32_t> ConsumePidVector(FuzzedDataProvider &provider)
{
    std::vector<int32_t> pidVector;
    size_t count = provider.ConsumeIntegralInRange<size_t>(0, MAX_VECTOR_LENGTH);
    pidVector.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        pidVector.emplace_back(provider.ConsumeIntegralInRange<int32_t>(0, MAX_PID));
    }
    return pidVector;
}

std::vector<std::string> ConsumeExemptionNames(FuzzedDataProvider &provider)
{
    // Keep singleton exemption state bounded across fuzz iterations.
    static const std::vector<std::string> exemptionNames = {
        "time_service", "settings", "TimerProxyState", "ipc.timer", "ohos.timer.fuzz", ""
    };
    std::vector<std::string> names;
    size_t count = provider.ConsumeIntegralInRange<size_t>(0, MAX_VECTOR_LENGTH);
    names.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        names.emplace_back(exemptionNames[provider.ConsumeIntegralInRange<size_t>(0, exemptionNames.size() - 1)]);
    }
    return names;
}

std::unordered_map<std::string, uint32_t> ConsumePolicyMap(FuzzedDataProvider &provider)
{
    static const std::vector<std::string> policyNames = {
        "time_service", "settings", "ipc.timer", "TimerProxyState"
    };
    std::unordered_map<std::string, uint32_t> policyMap;
    size_t count = provider.ConsumeIntegralInRange<size_t>(0, MAX_POLICY_LENGTH);
    for (size_t index = 0; index < count; ++index) {
        std::string key = policyNames[provider.ConsumeIntegralInRange<size_t>(0, policyNames.size() - 1)];
        uint32_t policy = provider.ConsumeIntegralInRange<uint32_t>(0, MAX_POLICY_VALUE);
        policyMap[key] = policy;
    }
    return policyMap;
}

void WritePolicyMap(MessageParcel &parcel, const std::unordered_map<std::string, uint32_t> &policyMap)
{
    parcel.WriteUint32(static_cast<uint32_t>(policyMap.size()));
    for (const auto &item : policyMap) {
        parcel.WriteString(item.first);
        parcel.WriteUint32(item.second);
    }
}

uint32_t GetIpcCode(uint8_t opcode)
{
    switch (opcode) {
        case IPC_SET_TIME:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_SET_TIME);
        case IPC_SET_AUTO_TIME:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_SET_AUTO_TIME);
        case IPC_SET_TIME_ZONE:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_SET_TIME_ZONE);
        case IPC_CREATE_TIMER:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_CREATE_TIMER_WITHOUT_W_A);
        case IPC_START_TIMER:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_START_TIMER);
        case IPC_STOP_TIMER:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_STOP_TIMER);
        case IPC_DESTROY_TIMER:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_DESTROY_TIMER);
        case IPC_PROXY_TIMER:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_PROXY_TIMER);
        case IPC_ADJUST_TIMER:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_ADJUST_TIMER);
        case IPC_SET_TIMER_EXEMPTION:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_SET_TIMER_EXEMPTION);
        case IPC_SET_ADJUST_POLICY:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_SET_ADJUST_POLICY);
        default:
            return static_cast<uint32_t>(MiscServices::ITimeServiceIpcCode::COMMAND_RESET_ALL_PROXY);
    }
}

void WriteSetTimePayload(MessageParcel &parcel, FuzzedDataProvider &provider)
{
    parcel.WriteInt64(provider.ConsumeIntegral<int64_t>());
    int apiVersion = provider.ConsumeIntegralInRange<int>(MIN_API_VERSION, MAX_API_VERSION);
    parcel.WriteInt8(static_cast<int8_t>(apiVersion));
}

void WriteSetTimeZonePayload(MessageParcel &parcel, FuzzedDataProvider &provider)
{
    parcel.WriteString(ConsumeTimezone(provider));
    int apiVersion = provider.ConsumeIntegralInRange<int>(MIN_API_VERSION, MAX_API_VERSION);
    parcel.WriteInt8(static_cast<int8_t>(apiVersion));
}

void WriteCreateTimerPayload(MessageParcel &parcel, FuzzedDataProvider &provider, uint64_t timerId)
{
    parcel.WriteString(ConsumeTimerName(provider));
    parcel.WriteInt32(ConsumeTimerType(provider));
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteUint64(provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TIMER_INTERVAL_MS));
    sptr<IRemoteObject> timerCallback;
    parcel.WriteRemoteObject(timerCallback);
    parcel.WriteUint64(timerId);
}

void WriteTimerIdPayload(MessageParcel &parcel, uint64_t timerId)
{
    parcel.WriteUint64(timerId);
}

void WriteStartTimerPayload(MessageParcel &parcel, FuzzedDataProvider &provider, uint64_t timerId)
{
    WriteTimerIdPayload(parcel, timerId);
    parcel.WriteUint64(provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TIMER_INTERVAL_MS));
}

void WriteProxyTimerPayload(MessageParcel &parcel, FuzzedDataProvider &provider)
{
    parcel.WriteInt32(provider.ConsumeIntegralInRange<int32_t>(0, MAX_UID));
    parcel.WriteInt32Vector(ConsumePidVector(provider));
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteBool(provider.ConsumeBool());
}

void WriteAdjustTimerPayload(MessageParcel &parcel, FuzzedDataProvider &provider)
{
    parcel.WriteBool(provider.ConsumeBool());
    parcel.WriteUint32(provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS));
    parcel.WriteUint32(provider.ConsumeIntegralInRange<uint32_t>(0, MAX_ADJUST_SECONDS));
}

void WriteTimerExemptionPayload(MessageParcel &parcel, FuzzedDataProvider &provider)
{
    parcel.WriteStringVector(ConsumeExemptionNames(provider));
    parcel.WriteBool(provider.ConsumeBool());
}

void WriteFullPayload(MessageParcel &parcel, FuzzedDataProvider &provider, uint8_t opcode, uint64_t timerId)
{
    switch (opcode) {
        case IPC_SET_TIME:
            WriteSetTimePayload(parcel, provider);
            break;
        case IPC_SET_AUTO_TIME:
            parcel.WriteBool(provider.ConsumeBool());
            break;
        case IPC_SET_TIME_ZONE:
            WriteSetTimeZonePayload(parcel, provider);
            break;
        case IPC_CREATE_TIMER:
            WriteCreateTimerPayload(parcel, provider, timerId);
            break;
        case IPC_START_TIMER:
            WriteStartTimerPayload(parcel, provider, timerId);
            break;
        case IPC_STOP_TIMER:
        case IPC_DESTROY_TIMER:
            WriteTimerIdPayload(parcel, timerId);
            break;
        case IPC_PROXY_TIMER:
            WriteProxyTimerPayload(parcel, provider);
            break;
        case IPC_ADJUST_TIMER:
            WriteAdjustTimerPayload(parcel, provider);
            break;
        case IPC_SET_TIMER_EXEMPTION:
            WriteTimerExemptionPayload(parcel, provider);
            break;
        case IPC_SET_ADJUST_POLICY:
            WritePolicyMap(parcel, ConsumePolicyMap(provider));
            break;
        default:
            break;
    }
}

void WriteTruncatedPayload(MessageParcel &parcel, FuzzedDataProvider &provider)
{
    if (provider.ConsumeBool()) {
        parcel.WriteString(ConsumeBoundedString(provider, { "truncated", "", "FUZZ" }));
    } else {
        parcel.WriteUint64(provider.ConsumeIntegralInRange<uint64_t>(0, MAX_TIMER_ID));
    }
}

void DispatchStructuredParcel(uint32_t code, MessageParcel &parcel)
{
    parcel.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    auto ability = MiscServices::TimeSystemAbility::GetInstance();
    if (ability == nullptr) {
        return;
    }
    (void)ability->OnRemoteRequest(code, parcel, reply, option);
}

void ExerciseTimerLifecycle(FuzzedDataProvider &provider, uint64_t timerId)
{
    std::vector<uint8_t> lifecycle = { IPC_CREATE_TIMER, IPC_START_TIMER, IPC_STOP_TIMER, IPC_DESTROY_TIMER };
    for (auto opcode : lifecycle) {
        MessageParcel parcel;
        parcel.WriteInterfaceToken(TIME_SERVICE_INTERFACE_TOKEN);
        WriteFullPayload(parcel, provider, opcode, timerId);
        DispatchStructuredParcel(GetIpcCode(opcode), parcel);
    }
}
} // namespace

void RunTimeipcstructuredFuzzer(FuzzedDataProvider &provider)
{
    uint64_t timerId = ConsumeTimerId(provider);
    if (provider.ConsumeBool()) {
        ExerciseTimerLifecycle(provider, timerId);
    }

    size_t operationCount = provider.ConsumeIntegralInRange<size_t>(MIN_OPERATION_COUNT, MAX_OPERATION_COUNT);
    for (size_t index = 0; index < operationCount; ++index) {
        uint8_t opcode = provider.ConsumeIntegralInRange<uint8_t>(MIN_OPERATION_INDEX, MAX_OPERATION_INDEX);
        MessageParcel parcel;
        parcel.WriteInterfaceToken(TIME_SERVICE_INTERFACE_TOKEN);
        if (provider.ConsumeBool()) {
            WriteFullPayload(parcel, provider, opcode, timerId);
        } else {
            WriteTruncatedPayload(parcel, provider);
        }
        DispatchStructuredParcel(GetIpcCode(opcode), parcel);
    }
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimeipcstructuredFuzzer(provider);
    return 0;
}
