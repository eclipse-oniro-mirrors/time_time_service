/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "timesntp_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "time_service_fuzz_utils.h"
#define private public
#include "sntp_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t THRESHOLD = 4;
constexpr size_t NTP_PACKAGE_SIZE = 48;
constexpr int MAX_LENGTH = 64;

bool FuzzTimeCreateMessage(FuzzedDataProvider &provider)
{
    char sendBuf[NTP_PACKAGE_SIZE] = { 0 };
    auto bytes = provider.ConsumeBytes<uint8_t>(NTP_PACKAGE_SIZE);
    errno_t ret = memcpy_s(sendBuf, sizeof(sendBuf), bytes.data(), NTP_PACKAGE_SIZE);
    if (ret != EOK) {
        return true;
    }
    SNTPClient client;
    client.CreateMessage(sendBuf);
    return true;
}

bool FuzzTimeReceivedMessage(FuzzedDataProvider &provider)
{
    char sendBuf[NTP_PACKAGE_SIZE] = { 0 };
    auto bytes = provider.ConsumeBytes<uint8_t>(NTP_PACKAGE_SIZE);
    size_t copySize = bytes.size();
    if (copySize > sizeof(sendBuf)) {
        copySize = sizeof(sendBuf);
    }
    errno_t ret = memcpy_s(sendBuf, sizeof(sendBuf), bytes.data(), NTP_PACKAGE_SIZE);
    if (ret != EOK) {
        return true;
    }
    SNTPClient client;
    client.ReceivedMessage(sendBuf);
    return true;
}

bool FuzzTimeRequestTime(FuzzedDataProvider &provider)
{
    std::string host = provider.ConsumeRandomLengthString(MAX_LENGTH);
    SNTPClient client;
    client.RequestTime(host);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTimeCreateMessage(provider);
    OHOS::FuzzTimeReceivedMessage(provider);
    OHOS::FuzzTimeRequestTime(provider);
    return 0;
}