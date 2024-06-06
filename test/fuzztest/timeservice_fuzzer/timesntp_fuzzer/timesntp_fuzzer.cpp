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

#include "time_service_fuzz_utils.h"
#define private public
#include "sntp_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t THRESHOLD = 4;
constexpr size_t NTP_PACKAGE_SIZE = 48;

void Convert(const uint8_t *data, size_t size, char* buf)
{
    size_t copySize = (size < NTP_PACKAGE_SIZE) ? size : NTP_PACKAGE_SIZE;

    for (size_t i = 0; i < copySize; ++i) {
        buf[i] = static_cast<char>(data[i]);
    }
    for (size_t i = copySize; i < NTP_PACKAGE_SIZE; ++i) {
        buf[i] = 0;
    }
}

bool FuzzTimeCreateMessage(const uint8_t *data, size_t size)
{
    char sendBuf[NTP_PACKAGE_SIZE] = { 0 };

    Convert(data, size, sendBuf);

    SNTPClient client;
    client.CreateMessage(sendBuf);
    return true;
}

bool FuzzTimeReceivedMessage(const uint8_t *data, size_t size)
{
    char sendBuf[NTP_PACKAGE_SIZE] = { 0 };

    Convert(data, size, sendBuf);

    SNTPClient client;
    client.ReceivedMessage(sendBuf);
    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::FuzzTimeCreateMessage(data, size);
    OHOS::FuzzTimeReceivedMessage(data, size);
    return 0;
}