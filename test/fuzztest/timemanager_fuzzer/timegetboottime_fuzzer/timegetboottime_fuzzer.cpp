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

#include "timegetboottime_fuzzer.h"
#include "time_common.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "time_service_client.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::MiscServices;

namespace OHOS {

bool FuzzTimeGetBootTime(FuzzedDataProvider &provider)
{
    TimeServiceClient::GetInstance()->GetBootTimeMs();
    int64_t time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetBootTimeMs(time);
    TimeServiceClient::GetInstance()->GetBootTimeNs();
    time = provider.ConsumeIntegral<int64_t>();
    TimeServiceClient::GetInstance()->GetBootTimeNs(time);
    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::FuzzTimeGetBootTime(provider);
    return 0;
}
