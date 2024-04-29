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

#include "time_file_utils.h"

#include <fcntl.h>
#include <sys/stat.h>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "securec.h"
#include "time_hilog.h"

constexpr int CMDLINE_PATH_LEN = 32;
constexpr int CMDLINE_LEN = 128;

namespace OHOS {
namespace MiscServices {
using AccessTokenKit = OHOS::Security::AccessToken::AccessTokenKit;
using HapTokenInfo = OHOS::Security::AccessToken::HapTokenInfo;
using TypeATokenTypeEnum = OHOS::Security::AccessToken::TypeATokenTypeEnum;
bool TimeFileUtils::IsExistFile(const std::string &file)
{
    if (file.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(file.c_str(), &buf) != 0) {
        return false;
    }
    return S_ISREG(buf.st_mode);
}

std::string TimeFileUtils::GetBundleNameByTokenID(uint32_t tokenID)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    if (tokenType != TypeATokenTypeEnum::TOKEN_HAP) {
        return "";
    }
    HapTokenInfo hapTokenInfo;
    int result = AccessTokenKit::GetHapTokenInfo(tokenID, hapTokenInfo);
    if (result != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to get hap token info, result = %{public}d", result);
        return "";
    }
    return hapTokenInfo.bundleName;
}

std::string TimeFileUtils::GetNameByPid(uint32_t pid)
{
    char path[CMDLINE_PATH_LEN] = { 0 };
    if (snprintf_s(path, CMDLINE_PATH_LEN, CMDLINE_PATH_LEN - 1, "/proc/%u/cmdline", pid) <= 0) {
        return "";
    }
    char cmdline[CMDLINE_LEN] = { 0 };
    int i = 0;
    FILE *fp = fopen(path, "r");
    if (fp == nullptr) {
        return "";
    }
    while (i < (CMDLINE_LEN - 1)) {
        char c = static_cast<char>(fgetc(fp));
        // 0. don't need args of cmdline
        // 1. ignore unvisible character
        if (!isgraph(c)) {
            break;
        }
        cmdline[i] = c;
        i++;
    }
    (void)fclose(fp);
    return cmdline;
}
} // namespace MiscServices
} // namespace OHOS