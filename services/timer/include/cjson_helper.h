/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef TIMER_CJSON_HELPER_H
#define TIMER_CJSON_HELPER_H

#include <stdint.h>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>

#include <cJSON.h>
#include "time_hilog.h"
#include "timer_manager_interface.h"

namespace OHOS {
namespace MiscServices {
constexpr int64_t MILLISECOND_TO_NANO = 1000000;
constexpr int CLOCK_POWEROFF_ALARM = 12;
constexpr const char *HOLD_ON_REBOOT = "hold_on_reboot";
constexpr const char *DROP_ON_REBOOT = "drop_on_reboot";

class CjsonHelper {
public:
    std::string QueryWant(std::string tableName, uint64_t timerId);
    cJSON* QueryTable(std::string tableName, cJSON* db);
    std::vector<std::pair<std::string, int64_t>> QueryAutoReboot();
    bool Insert(std::string tableName, std::shared_ptr<TimerEntry> timerInfo);
    bool UpdateTrigger(std::string tableName, int64_t timerId, int64_t triggerTime);
    bool UpdateState(std::string tableName, int64_t timerId);
    bool Delete(std::string tableName, int64_t timerId);
    void Clear(std::string tableName);
    bool StrToI64(std::string str, int64_t& value);
    static CjsonHelper &GetInstance();

private:
    CjsonHelper();
    void SaveJson(cJSON* data);
    std::mutex mutex_;
};
} // namespace MiscServices
} // namespace OHOS
#endif //TIMER_CJSON_HELPER_H
