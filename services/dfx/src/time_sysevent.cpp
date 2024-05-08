/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

#include "time_sysevent.h"

#include "hisysevent.h"
#include "time_hilog.h"

namespace OHOS {
namespace MiscServices {
namespace {
using HiSysEventNameSpace = OHOS::HiviewDFX::HiSysEvent;
} // namespace

void StatisticReporter(int32_t size, std::shared_ptr<TimerInfo> timer)
{
    int32_t callerPid = timer->pid;
    int32_t callerUid = timer->uid;
    std::string bundleOrProcessName = timer->bundleName;
    int32_t type = timer->type;
    int64_t triggerTime = timer->whenElapsed.time_since_epoch().count();
    auto interval = static_cast<uint64_t>(timer->repeatInterval.count());

    struct HiSysEventParam params[] = {
        {"CALLER_PID",              HISYSEVENT_INT32,   {callerPid},     0},
        {"CALLER_UID",              HISYSEVENT_INT32,   {callerUid},     0},
        {"BUNDLE_OR_PROCESS_NAME",  HISYSEVENT_STRING,
         {bundleOrProcessName.c_str()},   bundleOrProcessName.length() + 1},
        {"TIMER_SIZE",              HISYSEVENT_INT32,   {size},          0},
        {"TIMER_TYPE",              HISYSEVENT_INT32,   {type},          0},
        {"TRIGGER_TIME",            HISYSEVENT_INT64,   {triggerTime},   0},
        {"INTERVAL",                HISYSEVENT_UINT64,  {interval},      0},
    };
    int ret = OH_HiSysEvent_Write(
        "TIME",
        "MISC_TIME_STATISTIC_REPORT",
        HISYSEVENT_STATISTIC,
        params,
        sizeof(params)/sizeof(params[0])
    );
    if (ret != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE,
            "hisysevent Statistic failed! pid %{public}d,uid %{public}d,timer type %{public}d", callerPid, callerUid,
            type);
    }
}
} // namespace MiscServices
} // namespace OHOS