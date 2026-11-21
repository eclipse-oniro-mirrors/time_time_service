/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "timesntpgetters_fuzzer.h"

#include <cstdint>
#include <string>

#include "fuzzer/FuzzedDataProvider.h"

#include "sntp_client.h"

namespace OHOS {
namespace {
constexpr size_t THRESHOLD = 4;
constexpr int MAX_LENGTH = 64;
} // namespace

// Drives the public SNTPClient::RequestTime(host) API with an input-derived
// host string (the same pattern as the sibling timesntp_fuzzer) and then
// reads back the whole exported getter surface. RequestTime covers the full
// production flow (parameter validation, socket path, message create/parse)
// and populates the members every getter returns, so the getters are
// exercised over the real interface state.
bool RunTimesntpgettersFuzzer(FuzzedDataProvider &provider)
{
    std::string host = provider.ConsumeRandomLengthString(MAX_LENGTH);
    MiscServices::SNTPClient client;
    (void)client.RequestTime(host);
    (void)client.getNtpTime();
    (void)client.getNtpTimeReference();
    (void)client.getRoundTripTime();
    (void)client.getClockOffset();
    (void)client.getOriginTimestamp();
    (void)client.getReceiveClientTime();
    (void)client.getReceiveServerTime();
    (void)client.getTransmitServerTime();
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::THRESHOLD) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::RunTimesntpgettersFuzzer(provider);
    return 0;
}
