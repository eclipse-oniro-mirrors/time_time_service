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

#ifndef TIMER_DB_TOP_APP_INFO_H
#define TIMER_DB_TOP_APP_INFO_H

#include <string>
#include <vector>
#include <cstdint>

namespace OHOS {
namespace MiscServices {

struct TimerDbTopAppInfo {
    std::string bundleName;
    std::string timerName;
    int32_t count;
};

struct TimerDbSizeInfo {
    int64_t dbSize;
    int64_t shmSize;
    int64_t walSize;
    int64_t GetTotalSize() const
    {
        return dbSize + shmSize + walSize;
    }
};

} // namespace MiscServices
} // namespace OHOS

#endif // TIMER_DB_TOP_APP_INFO_H
