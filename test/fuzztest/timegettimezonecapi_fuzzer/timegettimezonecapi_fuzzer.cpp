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

#include "timegettimezonecapi_fuzzer.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include "fuzzer/FuzzedDataProvider.h"
#include "time_service.h"

namespace OHOS {
namespace {
constexpr size_t MAX_TIMEZONE_BUFFER = 64;
constexpr uint32_t EMPTY_TIMEZONE_BUFFER = 0;
constexpr uint32_t TINY_TIMEZONE_BUFFER = 1;
constexpr uint32_t RECOMMENDED_TIMEZONE_BUFFER = 31;

enum TimeZoneCapiOpcode : uint8_t {
    TIMEZONE_NULL_BUFFER = 0,
    TIMEZONE_EMPTY_BUFFER,
    TIMEZONE_TINY_BUFFER,
    TIMEZONE_RECOMMENDED_BUFFER,
    TIMEZONE_MAX_BUFFER,
    TIMEZONE_FUZZED_LENGTH,
};

constexpr uint8_t MIN_OPERATION_INDEX = TIMEZONE_NULL_BUFFER;
constexpr uint8_t MAX_OPERATION_INDEX = TIMEZONE_FUZZED_LENGTH;

void FillBuffer(FuzzedDataProvider &provider, std::array<char, MAX_TIMEZONE_BUFFER> &buffer)
{
    auto bytes = provider.ConsumeBytes<uint8_t>(buffer.size());
    for (size_t index = 0; index < buffer.size(); ++index) {
        buffer[index] = index < bytes.size() ? static_cast<char>(bytes[index]) : '\0';
    }
}

void CallWithBuffer(FuzzedDataProvider &provider, uint32_t len)
{
    std::array<char, MAX_TIMEZONE_BUFFER> buffer {};
    FillBuffer(provider, buffer);
    (void)OH_TimeService_GetTimeZone(buffer.data(), len);
}
} // namespace

void RunTimegettimezonecapiFuzzer(FuzzedDataProvider &provider)
{
    uint8_t opcode = provider.ConsumeIntegralInRange<uint8_t>(MIN_OPERATION_INDEX, MAX_OPERATION_INDEX);
    switch (opcode) {
        case TIMEZONE_NULL_BUFFER:
            (void)OH_TimeService_GetTimeZone(nullptr,
                provider.ConsumeIntegralInRange<uint32_t>(0, MAX_TIMEZONE_BUFFER));
            break;
        case TIMEZONE_EMPTY_BUFFER:
            CallWithBuffer(provider, EMPTY_TIMEZONE_BUFFER);
            break;
        case TIMEZONE_TINY_BUFFER:
            CallWithBuffer(provider, TINY_TIMEZONE_BUFFER);
            break;
        case TIMEZONE_RECOMMENDED_BUFFER:
            CallWithBuffer(provider, RECOMMENDED_TIMEZONE_BUFFER);
            break;
        case TIMEZONE_MAX_BUFFER:
            CallWithBuffer(provider, MAX_TIMEZONE_BUFFER);
            break;
        default:
            CallWithBuffer(provider, provider.ConsumeIntegralInRange<uint32_t>(0, MAX_TIMEZONE_BUFFER));
            break;
    }
}
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimegettimezonecapiFuzzer(provider);
    return 0;
}
