/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "timegetboottimenano_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string_ex.h>

#include "time_service_fuzz_utils.h"
#include "time_service_ipc_interface_code.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t THRESHOLD = 4;
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::TimeServiceFuzzUtils::OnRemoteRequestTest(
        static_cast<uint32_t>(TimeServiceIpcInterfaceCode::GET_BOOT_TIME_NANO), data, size);
    return 0;
}