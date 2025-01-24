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
#include "time_file_utils.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace MiscServices {
namespace {
using HiSysEventNameSpace = OHOS::HiviewDFX::HiSysEvent;
} // namespace

std::string GetBundleOrProcessName()
{
    std::string bundleOrProcessName = TimeFileUtils::GetBundleNameByTokenID(IPCSkeleton::GetCallingTokenID());
    if (bundleOrProcessName.empty()) {
        bundleOrProcessName = TimeFileUtils::GetNameByPid(IPCSkeleton::GetCallingPid());
    }
    return bundleOrProcessName;
}

void StatisticReporter(int32_t size, std::shared_ptr<TimerInfo> timer)
{
    if (timer == nullptr) {
        return;
    }
    int32_t callerUid = timer->uid;
    int32_t callerPid = timer->pid;
    std::string bundleOrProcessName = timer->bundleName;
    int32_t type = timer->type;
    int64_t triggerTime = timer->whenElapsed.time_since_epoch().count();
    auto interval = static_cast<uint64_t>(timer->repeatInterval.count());
    struct HiSysEventParam params[] = {
        {"CALLER_PID",             HISYSEVENT_INT32,  {callerPid},     0},
        {"CALLER_UID",             HISYSEVENT_INT32,  {callerUid},     0},
        {"BUNDLE_OR_PROCESS_NAME", HISYSEVENT_STRING, {bundleOrProcessName.c_str()}, bundleOrProcessName.length()},
        {"TIMER_SIZE",             HISYSEVENT_INT32,  {size},          0},
        {"TIMER_TYPE",             HISYSEVENT_INT32,  {type},          0},
        {"TRIGGER_TIME",           HISYSEVENT_INT64,  {triggerTime},   0},
        {"INTERVAL",               HISYSEVENT_UINT64, {interval},      0}
    };
    int ret = OH_HiSysEvent_Write("TIME", "MISC_TIME_STATISTIC_REPORT", HISYSEVENT_STATISTIC, params,
        sizeof(params)/sizeof(params[0]));
    if (ret != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE,
            "hisysevent Statistic failed! pid %{public}d,uid %{public}d,timer type %{public}d", callerPid, callerUid,
            type);
    }
}

void TimeBehaviorReport(ReportEventCode eventCode, std::string originTime, std::string newTime, int64_t ntpTime)
{
    std::string bundleOrProcessName = GetBundleOrProcessName();
    struct HiSysEventParam params[] = {
        {"EVENT_CODE",    HISYSEVENT_INT32,  {eventCode},                    0},
        {"CALLER_UID",    HISYSEVENT_INT32,  {IPCSkeleton::GetCallingUid()}, 0},
        {"CALLER_NAME",   HISYSEVENT_STRING, {bundleOrProcessName.c_str()},  bundleOrProcessName.length()},
        {"ORIGINAL_TIME", HISYSEVENT_STRING, {originTime.c_str()},           originTime.length()},
        {"SET_TIME",      HISYSEVENT_STRING, {newTime.c_str()},              newTime.length()},
        {"NTP_TIME",      HISYSEVENT_INT64,  {ntpTime},                      0}
    };
    int ret = OH_HiSysEvent_Write("TIME", "BEHAVIOR_TIME", HISYSEVENT_BEHAVIOR, params,
        sizeof(params)/sizeof(params[0]));
    if (ret != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "TimeBehaviorReport failed! eventCode %{public}d, name:%{public}s,"
        "ret:%{public}d", eventCode, bundleOrProcessName.c_str(), ret);
    }
}

void TimerBehaviorReport(std::shared_ptr<TimerInfo> timer, bool isStart)
{
    if (timer == nullptr) {
        return;
    }
    int triggerOffset = isStart ? RTC_WAKEUP_EXACT_TIMER_START : RTC_WAKEUP_EXACT_TIMER_TRIGGER;
    int exactOffset = (timer->windowLength == std::chrono::milliseconds::zero()) ? 0 : EXACT_OFFSET;
    ReportEventCode eventCode = static_cast<ReportEventCode>(triggerOffset + timer->type + exactOffset);
    auto bundleOrProcessName = timer->bundleName;
    auto interval = static_cast<uint32_t>(timer->repeatInterval.count());
    struct HiSysEventParam params[] = {
        {"EVENT_CODE",   HISYSEVENT_INT32,  {eventCode},                   0},
        {"TIMER_ID",     HISYSEVENT_UINT32, {timer->id},                   0},
        {"TRIGGER_TIME", HISYSEVENT_INT64,  {timer->when.count()},         0},
        {"CALLER_UID",   HISYSEVENT_INT32,  {timer->uid},                  0},
        {"CALLER_NAME",  HISYSEVENT_STRING, {bundleOrProcessName.c_str()}, bundleOrProcessName.length()},
        {"INTERVAL",     HISYSEVENT_UINT32, {interval},                    0}
    };
    int ret = OH_HiSysEvent_Write("TIME", "BEHAVIOR_TIMER", HISYSEVENT_BEHAVIOR, params,
        sizeof(params)/sizeof(params[0]));
    if (ret != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE,
            "TimerBehaviorReport failed! eventCode %{public}d, name%{public}s,timerid %{public}d", eventCode,
            bundleOrProcessName.c_str(), timer->id);
    }
}

void TimerCountStaticReporter(int count, int* uidArr, int* createTimerCountArr, int* startTimerCountArr)
{
    struct HiSysEventParam params[] = {
        {"TIMER_NUM",     HISYSEVENT_INT32,       {count}, 0},
        {"TOP_UID",       HISYSEVENT_INT32_ARRAY, {uidArr}, 5},
        {"TOP_NUM",       HISYSEVENT_INT32_ARRAY, {createTimerCountArr}, 5},
        {"TOP_STRAT_NUM", HISYSEVENT_INT32_ARRAY, {startTimerCountArr}, 5}
    };
    int ret = OH_HiSysEvent_Write("TIME", "ALARM_COUNT", HISYSEVENT_STATISTIC,
        params, sizeof(params)/sizeof(params[0]));
    if (ret != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "hisysevent Statistic failed! count:%{public}d, uid:[%{public}s],"
        "create count:[%{public}s], startcount:[%{public}s]", count, uidArr, createTimerCountArr, startTimerCountArr);
    }
}

void TimeServiceFaultReporter(ReportEventCode eventCode, int errCode, std::string extraInfo)
{
    int uid = IPCSkeleton::GetCallingUid();
    std::string bundleOrProcessName = GetBundleOrProcessName();
    struct HiSysEventParam params[] = {
        {"EVENT_CODE",  HISYSEVENT_INT32,  {eventCode},                   0},
        {"ERR_CODE",    HISYSEVENT_INT32,  {errCode},                     0},
        {"CALLER_UID",  HISYSEVENT_INT32,  {uid},                         0},
        {"CALLER_NAME", HISYSEVENT_STRING, {bundleOrProcessName.c_str()}, bundleOrProcessName.length()},
        {"EXTRA",       HISYSEVENT_STRING, {extraInfo.c_str()},           extraInfo.length()}
    };
    int ret = OH_HiSysEvent_Write("TIME", "ALARM_COUNT", HISYSEVENT_STATISTIC,
        params, sizeof(params)/sizeof(params[0]));
    if (ret != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "hisysevent Statistic failed! eventCode:%{public}d errorcode:%{public}d"
        "callname:%{public}s", eventCode, errCode, bundleOrProcessName.c_str());
    }
}
} // namespace MiscServices+
} // namespace OHOS