/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "timereceivedmessage_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <securec.h>
#include <string_ex.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "accesstoken_kit.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "time_system_ability.h"
#include "token_setproc.h"

#define private public
#define protected public
#include "sntp_client.h"

using namespace OHOS::MiscServices;

namespace OHOS {
constexpr size_t THRESHOLD = 4;
constexpr size_t NTP_PACKAGE_SIZE = 48;
constexpr int MAX_NUM = 20;
constexpr int MAX_LENGTH = 64;
const std::u16string TIMESERVICE_INTERFACE_TOKEN = u"ohos.miscservices.time.ITimeService";

#ifdef HIDUMPER_ENABLE
bool FuzzTimeDump(FuzzedDataProvider &provider)
{
    std::vector<std::u16string> args;
    int len = provider.ConsumeIntegralInRange<int>(1, MAX_NUM);
    for (int i = 0; i < len; i++) {
        std::string str = provider.ConsumeRandomLengthString(MAX_LENGTH);
        args.push_back(Str8ToStr16(str));
    }
    int fd = 0;
    TimeSystemAbility::GetInstance()->Dump(fd, args);
    return true;
}
#endif

bool FuzzTimeReceivedMessage(FuzzedDataProvider &provider)
{
    char buffer[NTP_PACKAGE_SIZE] = { 0 };
    auto bytes = provider.ConsumeBytes<uint8_t>(NTP_PACKAGE_SIZE);
    errno_t ret = memcpy_s(buffer, sizeof(buffer), bytes.data(), NTP_PACKAGE_SIZE);
    if (ret != EOK) {
        return true;
    }
    auto client = std::make_shared<SNTPClient>();
    client->ReceivedMessage(buffer);
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
#ifdef HIDUMPER_ENABLE
    OHOS::FuzzTimeDump(provider);
#endif
    OHOS::FuzzTimeReceivedMessage(provider);
    return 0;
}