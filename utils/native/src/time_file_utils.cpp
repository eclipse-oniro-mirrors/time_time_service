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

#include <sys/stat.h>

namespace OHOS {
namespace MiscServices {
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
} // namespace MiscServices
} // namespace OHOS