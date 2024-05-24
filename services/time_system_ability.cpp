/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "time_system_ability.h"

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <linux/rtc.h>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>
#include <climits>

#include "iservice_registry.h"
#include "ntp_update_time.h"
#include "pthread.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "time_common.h"
#include "time_tick_notify.h"
#include "time_zone_info.h"
#include "timer_notify_callback.h"
#include "timer_manager_interface.h"
#include "timer_proxy.h"
#include "timer_database.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "power_subscriber.h"
#include "nitz_subscriber.h"
#include "init_param.h"
#include "parameters.h"

using namespace std::chrono;
using namespace OHOS::EventFwk;

namespace OHOS {
namespace MiscServices {
namespace {
// Unit of measure conversion , BASE: second
static const int MILLI_TO_BASE = 1000LL;
static const int MICR_TO_BASE = 1000000LL;
static const int NANO_TO_BASE = 1000000000LL;
static const std::int32_t INIT_INTERVAL = 10000L;
static const uint32_t TIMER_TYPE_REALTIME_MASK = 1 << 0;
static const uint32_t TIMER_TYPE_REALTIME_WAKEUP_MASK = 1 << 1;
static const uint32_t TIMER_TYPE_EXACT_MASK = 1 << 2;
static const uint32_t TIMER_TYPE_IDLE_MASK = 1 << 3;
static const uint32_t TIMER_TYPE_INEXACT_REMINDER_MASK = 1 << 4;
constexpr int32_t MILLI_TO_MICR = MICR_TO_BASE / MILLI_TO_BASE;
constexpr int32_t NANO_TO_MILLI = NANO_TO_BASE / MILLI_TO_BASE;
constexpr int32_t ONE_MILLI = 1000;
constexpr uint64_t TWO_MINUTES_TO_MILLI = 120000;
static const std::vector<std::string> ALL_DATA = { "timerId", "type", "flag", "windowLength", "interval", \
                                                   "uid", "bundleName", "wantAgent", "state", "triggerTime" };
const std::string BOOTEVENT_PARAMETER = "bootevent.boot.completed";
} // namespace

REGISTER_SYSTEM_ABILITY_BY_ID(TimeSystemAbility, TIME_SERVICE_ID, true);

std::mutex TimeSystemAbility::instanceLock_;
sptr<TimeSystemAbility> TimeSystemAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> TimeSystemAbility::serviceHandler_ = nullptr;
std::shared_ptr<TimerManager> TimeSystemAbility::timerManagerHandler_ = nullptr;

TimeSystemAbility::TimeSystemAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate), state_(ServiceRunningState::STATE_NOT_START),
      rtcId(GetWallClockRtcId())
{
    TIME_HILOGD(TIME_MODULE_SERVICE, " TimeSystemAbility Start.");
}

TimeSystemAbility::TimeSystemAbility() : state_(ServiceRunningState::STATE_NOT_START), rtcId(GetWallClockRtcId())
{
}

TimeSystemAbility::~TimeSystemAbility(){};

sptr<TimeSystemAbility> TimeSystemAbility::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new TimeSystemAbility;
        }
    }
    return instance_;
}

std::shared_ptr<TimerManager> TimeSystemAbility::GetManagerHandler()
{
    return timerManagerHandler_;
}

void TimeSystemAbility::InitDumpCmd()
{
    auto cmdTime = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-time" }),
        "dump current time info,include localtime,timezone info",
        [this](int fd, const std::vector<std::string> &input) { DumpAllTimeInfo(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdTime);

    auto cmdTimerAll = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-timer", "-a" }),
        "dump all timer info", [this](int fd, const std::vector<std::string> &input) { DumpTimerInfo(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdTimerAll);

    auto cmdTimerInfo = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-timer", "-i", "[n]" }),
        "dump the timer info with timer id",
        [this](int fd, const std::vector<std::string> &input) { DumpTimerInfoById(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdTimerInfo);

    auto cmdTimerTrigger = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-timer", "-s", "[n]" }),
        "dump current time info,include localtime,timezone info",
        [this](int fd, const std::vector<std::string> &input) { DumpTimerTriggerById(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdTimerTrigger);

    auto cmdTimerIdle = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-idle", "-a" }),
        "dump idle state and timer info, include pending delay timers and delayed info.",
        [this](int fd, const std::vector<std::string> &input) { DumpIdleTimerInfo(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdTimerIdle);

    auto cmdProxyTimer = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-ProxyTimer", "-l" }),
        "dump proxy timer info.",
        [this](int fd, const std::vector<std::string> &input) { DumpProxyTimerInfo(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdProxyTimer);

    auto cmdPidTimer = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-PidTimer", "-l" }),
        "dump pid timer map.",
        [this](int fd, const std::vector<std::string> &input) { DumpPidTimerMapInfo(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdPidTimer);

    auto cmdUidTimer = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-UidTimer", "-l" }),
        "dump uid timer map.",
        [this](int fd, const std::vector<std::string> &input) { DumpUidTimerMapInfo(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdUidTimer);

    auto cmdSetDelayTimer = std::make_shared<TimeCmdParse>(
        std::vector<std::string>({ "-ProxyDelayTime", "-s", "[n]" }),
        "set proxy delay time.",
        [this](int fd, const std::vector<std::string> &input) { SetProxyDelayTime(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdSetDelayTimer);

    auto cmdShowDelayTimer = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-ProxyDelayTime", "-l" }),
        "dump proxy delay time.",
        [this](int fd, const std::vector<std::string> &input) { DumpProxyDelayTime(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdShowDelayTimer);

    auto cmdAdjustTimer = std::make_shared<TimeCmdParse>(std::vector<std::string>({ "-adjust", "-a" }),
        "dump adjust time.",
        [this](int fd, const std::vector<std::string> &input) { DumpAdjustTime(fd, input); });
    TimeCmdDispatcher::GetInstance().RegisterCommand(cmdAdjustTimer);
}

void TimeSystemAbility::OnStart()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "TimeSystemAbility OnStart.");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "TimeSystemAbility is already running.");
        return;
    }
    InitServiceHandler();
    InitTimerHandler();
    TimeTickNotify::GetInstance().Init();
    TimeZoneInfo::GetInstance().Init();
    NtpUpdateTime::GetInstance().Init();
    // This parameter is set to true by init only after all services have been started,
    // and is automatically set to false after shutdown. Otherwise it will not be modified.
    std::string bootCompleted = system::GetParameter(BOOTEVENT_PARAMETER, "");
    TIME_HILOGI(TIME_MODULE_SERVICE, "bootCompleted: %{public}s", bootCompleted.c_str());
    if (bootCompleted != "true") {
        TimeDatabase::GetInstance().ClearDropOnReboot();
    }
    AddSystemAbilityListener(ABILITY_MGR_SERVICE_ID);
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    AddSystemAbilityListener(DEVICE_STANDBY_SERVICE_SYSTEM_ABILITY_ID);
    AddSystemAbilityListener(POWER_MANAGER_SERVICE_ID);
    AddSystemAbilityListener(COMM_NET_CONN_MANAGER_SYS_ABILITY_ID);
    InitDumpCmd();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Start TimeSystemAbility success.");
    if (Init() != ERR_OK) {
        auto callback = [this]() { Init(); };
        serviceHandler_->PostTask(callback, "time_service_init_retry", INIT_INTERVAL);
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init failed. Try again 10s later.");
    }
}

void TimeSystemAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        RegisterCommonEventSubscriber();
    } else if (systemAbilityId == DEVICE_STANDBY_SERVICE_SYSTEM_ABILITY_ID) {
        RegisterRSSDeathCallback();
    } else if (systemAbilityId == POWER_MANAGER_SERVICE_ID) {
        RegisterPowerStateListener();
    } else if (systemAbilityId == COMM_NET_CONN_MANAGER_SYS_ABILITY_ID) {
        NtpUpdateTime::GetInstance().MonitorNetwork();
    } else if (systemAbilityId == ABILITY_MGR_SERVICE_ID) {
        RecoverTimer();
    } else {
        TIME_HILOGE(TIME_MODULE_SERVICE, "OnAddSystemAbility systemAbilityId is not valid, id is %{public}d",
            systemAbilityId);
        return;
    }
}

void TimeSystemAbility::RegisterScreenOnSubscriber()
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<PowerSubscriber> subscriberPtr = std::make_shared<PowerSubscriber>(subscriberInfo);
    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(subscriberPtr);
    if (!subscribeResult) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Register COMMON_EVENT_SCREEN_ON failed");
    } else {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Register COMMON_EVENT_SCREEN_ON success.");
    }
}

void TimeSystemAbility::RegisterNitzTimeSubscriber()
{
    MatchingSkills matchingNITZSkills;
    matchingNITZSkills.AddEvent(CommonEventSupport::COMMON_EVENT_NITZ_TIME_CHANGED);
    CommonEventSubscribeInfo subscriberNITZInfo(matchingNITZSkills);
    std::shared_ptr<NITZSubscriber> subscriberNITZPtr = std::make_shared<NITZSubscriber>(subscriberNITZInfo);
    bool subscribeNITZResult = CommonEventManager::SubscribeCommonEvent(subscriberNITZPtr);
    if (!subscribeNITZResult) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Register COMMON_EVENT_NITZ_TIME_CHANGED failed");
    } else {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Register COMMON_EVENT_NITZ_TIME_CHANGED success.");
    }
}

void TimeSystemAbility::RegisterCommonEventSubscriber()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "RegisterCommonEventSubscriber Started");
    bool subRes = TimeServiceNotify::GetInstance().RepublishEvents();
    if (!subRes) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to RegisterCommonEventSubscriber");
        auto callback = [this]() { TimeServiceNotify::GetInstance().RepublishEvents(); };
        serviceHandler_->PostTask(callback, "time_service_subscriber_retry", INIT_INTERVAL);
    }
    RegisterScreenOnSubscriber();
    RegisterNitzTimeSubscriber();
}

int32_t TimeSystemAbility::Init()
{
    bool ret = Publish(TimeSystemAbility::GetInstance());
    if (!ret) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init Failed.");
        return E_TIME_PUBLISH_FAIL;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "Init Success.");
    state_ = ServiceRunningState::STATE_RUNNING;
    return ERR_OK;
}

void TimeSystemAbility::OnStop()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "OnStop Started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "state is running.");
        return;
    }
    serviceHandler_ = nullptr;
    TimeTickNotify::GetInstance().Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
    TIME_HILOGD(TIME_MODULE_SERVICE, "OnStop End.");
}

void TimeSystemAbility::InitServiceHandler()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "InitServiceHandler started.");
    if (serviceHandler_ != nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " Already init.");
        return;
    }
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(TIME_SERVICE_NAME);
    serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    TIME_HILOGD(TIME_MODULE_SERVICE, "InitServiceHandler Succeeded.");
}

void TimeSystemAbility::InitTimerHandler()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Init Timer started.");
    if (timerManagerHandler_ != nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " Already init.");
        return;
    }
    timerManagerHandler_ = TimerManager::Create();
}

void TimeSystemAbility::ParseTimerPara(const std::shared_ptr<ITimerInfo> &timerOptions, TimerPara &paras)
{
    auto uIntType = static_cast<uint32_t>(timerOptions->type);
    bool isRealtime = (uIntType & TIMER_TYPE_REALTIME_MASK) > 0;
    bool isWakeup = (uIntType & TIMER_TYPE_REALTIME_WAKEUP_MASK) > 0;
    paras.windowLength = (uIntType & TIMER_TYPE_EXACT_MASK) > 0 ? 0 : -1;
    paras.flag = (uIntType & TIMER_TYPE_EXACT_MASK) > 0 ? 1 : 0;
    if (isRealtime && isWakeup) {
        paras.timerType = ITimerManager::TimerType::ELAPSED_REALTIME_WAKEUP;
    } else if (isRealtime) {
        paras.timerType = ITimerManager::TimerType::ELAPSED_REALTIME;
    } else if (isWakeup) {
        paras.timerType = ITimerManager::TimerType::RTC_WAKEUP;
    } else {
        paras.timerType = ITimerManager::TimerType::RTC;
    }
    if ((uIntType & TIMER_TYPE_IDLE_MASK) > 0) {
        paras.flag += ITimerManager::TimerFlag::IDLE_UNTIL;
    }
    if ((uIntType & TIMER_TYPE_INEXACT_REMINDER_MASK) > 0) {
        paras.flag += ITimerManager::TimerFlag::INEXACT_REMINDER;
    }
    paras.interval = timerOptions->repeat ? timerOptions->interval : 0;
}

int32_t TimeSystemAbility::CreateTimer(const std::shared_ptr<ITimerInfo> &timerOptions, sptr<IRemoteObject> &obj,
    uint64_t &timerId)
{
    if (obj == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Input nullptr.");
        return E_TIME_NULLPTR;
    }
    sptr<ITimerCallback> timerCallback = iface_cast<ITimerCallback>(obj);
    if (timerCallback == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "ITimerCallback nullptr.");
        return E_TIME_NULLPTR;
    }
    struct TimerPara paras {};
    ParseTimerPara(timerOptions, paras);
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return E_TIME_NULLPTR;
        }
    }
    auto callbackFunc = [timerCallback, timerOptions](uint64_t id) {
        #ifdef POWER_MANAGER_ENABLE
        if (timerOptions->type == ITimerManager::TimerType::RTC_WAKEUP ||
            timerOptions->type == ITimerManager::TimerType::ELAPSED_REALTIME_WAKEUP) {
            auto notifyCallback = TimerNotifyCallback::GetInstance(timerManagerHandler_);
            timerCallback->NotifyTimer(id, notifyCallback->AsObject());
        } else {
            timerCallback->NotifyTimer(id, nullptr);
        }
        #else
        timerCallback->NotifyTimer(id, nullptr);
        #endif
    };
    if ((static_cast<uint32_t>(paras.flag) & static_cast<uint32_t>(ITimerManager::TimerFlag::IDLE_UNTIL)) > 0 &&
        !TimePermission::CheckProxyCallingPermission()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "App not support create idle timer.");
        paras.flag = 0;
    }
    auto type = DatabaseType::NOT_STORE;
    if (timerOptions->wantAgent != nullptr) {
        type = DatabaseType::STORE;
    }
    int uid = IPCSkeleton::GetCallingUid();
    int pid = IPCSkeleton::GetCallingPid();
    return timerManagerHandler_->CreateTimer(paras, callbackFunc, timerOptions->wantAgent,
                                             uid, pid, timerId, type);
}

int32_t TimeSystemAbility::CreateTimer(TimerPara &paras, std::function<void(const uint64_t)> callback,
    uint64_t &timerId)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return E_TIME_NULLPTR;
        }
    }
    return timerManagerHandler_->CreateTimer(paras, std::move(callback), nullptr, 0, 0, timerId, NOT_STORE);
}

int32_t TimeSystemAbility::StartTimer(uint64_t timerId, uint64_t triggerTime)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return false;
        }
    }
    auto ret = timerManagerHandler_->StartTimer(timerId, triggerTime);
    return ret;
}

int32_t TimeSystemAbility::StopTimer(uint64_t timerId)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return false;
        }
    }
    auto ret = timerManagerHandler_->StopTimer(timerId);
    return ret;
}

int32_t TimeSystemAbility::DestroyTimer(uint64_t timerId)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return false;
        }
    }
    auto ret = timerManagerHandler_->DestroyTimer(timerId);
    return ret;
}

bool TimeSystemAbility::IsValidTime(int64_t time)
{
#if __SIZEOF_POINTER__ == 4
    if (time / MILLI_TO_BASE > LONG_MAX) {
        return false;
    }
#endif
    return true;
}

bool TimeSystemAbility::SetRealTime(int64_t time)
{
    if (!IsValidTime(time)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "time is invalid: %{public}s", std::to_string(time).c_str());
        return false;
    }
    sptr<TimeSystemAbility> instance = TimeSystemAbility::GetInstance();
    int64_t beforeTime = 0;
    instance->GetWallTimeMs(beforeTime);
    int64_t bootTime = 0;
    instance->GetBootTimeMs(bootTime);
    TIME_HILOGI(TIME_MODULE_SERVICE,
        "Before Current Time: %{public}s"
        " Set time: %{public}s"
        " Difference: %{public}s"
        " uid:%{public}d pid:%{public}d ",
        std::to_string(beforeTime).c_str(), std::to_string(time).c_str(), std::to_string(time - bootTime).c_str(),
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingPid());
    if (time < 0 || time / 1000LL >= LLONG_MAX) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "input param error %{public}" PRId64 "", time);
        return false;
    }
    int64_t currentTime = 0;
    if (GetWallTimeMs(currentTime) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "currentTime get failed");
        return false;
    }
    struct timeval tv {};
    tv.tv_sec = (time_t)(time / MILLI_TO_BASE);
    tv.tv_usec = (suseconds_t)((time % MILLI_TO_BASE) * MILLI_TO_MICR);
    int result = settimeofday(&tv, nullptr);
    if (result < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "settimeofday time fail: %{public}d. error: %{public}s", result,
            strerror(errno));
        return false;
    }
    auto ret = SetRtcTime(tv.tv_sec);
    if (ret == E_TIME_SET_RTC_FAILED) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "set rtc fail: %{public}d.", ret);
        return false;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "getting currentTime to milliseconds: %{public}" PRId64 "", currentTime);
    if (currentTime < (time - ONE_MILLI) || currentTime > (time + ONE_MILLI)) {
        TimeServiceNotify::GetInstance().PublishTimeChangeEvents(currentTime);
    }
    return true;
}

int32_t TimeSystemAbility::SetTime(int64_t time, APIVersion apiVersion)
{
    if (!SetRealTime(time)) {
        return E_TIME_DEAL_FAILED;
    }
    return ERR_OK;
}

int TimeSystemAbility::Dump(int fd, const std::vector<std::u16string> &args)
{
    int uid = static_cast<int>(IPCSkeleton::GetCallingUid());
    const int maxUid = 10000;
    if (uid > maxUid) {
        return E_TIME_DEAL_FAILED;
    }

    std::vector<std::string> argsStr;
    for (auto &item : args) {
        argsStr.emplace_back(Str16ToStr8(item));
    }

    TimeCmdDispatcher::GetInstance().Dispatch(fd, argsStr);
    return ERR_OK;
}

void TimeSystemAbility::DumpAllTimeInfo(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump all time info :\n");
    struct timespec ts{};
    struct tm timestr{};
    char date_time[64];
    if (GetTimeByClockId(CLOCK_BOOTTIME, ts)) {
        auto localTime = localtime_r(&ts.tv_sec, &timestr);
        if (localTime == nullptr) {
            return;
        }
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localTime);
        dprintf(fd, " * date time = %s\n", date_time);
    } else {
        dprintf(fd, " * dump date time error.\n");
    }
    dprintf(fd, " - dump the time Zone:\n");
    std::string timeZone;
    int32_t bRet = GetTimeZone(timeZone);
    if (bRet == ERR_OK) {
        dprintf(fd, " * time zone = %s\n", timeZone.c_str());
    } else {
        dprintf(fd, " * dump time zone error,is %s\n", timeZone.c_str());
    }
}

void TimeSystemAbility::DumpTimerInfo(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump all timer info :\n");
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return;
        }
    }
    timerManagerHandler_->ShowTimerEntryMap(fd);
}

void TimeSystemAbility::DumpTimerInfoById(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump the timer info with timer id:\n");
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return;
        }
    }
    int paramNumPos = 2;
    timerManagerHandler_->ShowTimerEntryById(fd, std::atoi(input.at(paramNumPos).c_str()));
}

void TimeSystemAbility::DumpTimerTriggerById(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump timer trigger statics with timer id:\n");
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return;
        }
    }
    int paramNumPos = 2;
    timerManagerHandler_->ShowTimerTriggerById(fd, std::atoi(input.at(paramNumPos).c_str()));
}

void TimeSystemAbility::DumpIdleTimerInfo(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump idle timer info :\n");
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return;
        }
    }
    timerManagerHandler_->ShowIdleTimerInfo(fd);
}

void TimeSystemAbility::DumpProxyTimerInfo(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump proxy map:\n");
    int64_t times;
    GetBootTimeNs(times);
    TimerProxy::GetInstance().ShowProxyTimerInfo(fd, times);
}

void TimeSystemAbility::DumpUidTimerMapInfo(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump uid timer map:\n");
    int64_t times;
    GetBootTimeNs(times);
    TimerProxy::GetInstance().ShowUidTimerMapInfo(fd, times);
}

void TimeSystemAbility::SetProxyDelayTime(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - set proxy delay time:\n");
    int paramNumPos = 2;
    TimerProxy::GetInstance().SetProxyDelayTime(fd, std::atoi(input.at(paramNumPos).c_str()));
}

void TimeSystemAbility::DumpProxyDelayTime(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump proxy delay time:\n");
    TimerProxy::GetInstance().ShowProxyDelayTime(fd);
}

void TimeSystemAbility::DumpPidTimerMapInfo(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump pid timer map:\n");
    int64_t times;
    GetBootTimeNs(times);
    TimerProxy::GetInstance().ShowPidTimerMapInfo(fd, times);
}

void TimeSystemAbility::DumpAdjustTime(int fd, const std::vector<std::string> &input)
{
    dprintf(fd, "\n - dump adjust timer info:\n");
    TimerProxy::GetInstance().ShowAdjustTimerInfo(fd);
}

int TimeSystemAbility::SetRtcTime(time_t sec)
{
    struct rtc_time rtc {};
    struct tm tm {};
    struct tm *gmtime_res = nullptr;
    int fd = -1;
    int res;
    if (rtcId < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "invalid rtc id: %{public}s:", strerror(ENODEV));
        return E_TIME_SET_RTC_FAILED;
    }
    std::stringstream strs;
    strs << "/dev/rtc" << rtcId;
    auto rtcDev = strs.str();
    TIME_HILOGI(TIME_MODULE_SERVICE, "rtc_dev : %{public}s:", rtcDev.data());
    auto rtcData = rtcDev.data();
    fd = open(rtcData, O_RDWR);
    if (fd < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "open failed %{public}s: %{public}s", rtcDev.data(), strerror(errno));
        return E_TIME_SET_RTC_FAILED;
    }
    gmtime_res = gmtime_r(&sec, &tm);
    if (gmtime_res) {
        rtc.tm_sec = tm.tm_sec;
        rtc.tm_min = tm.tm_min;
        rtc.tm_hour = tm.tm_hour;
        rtc.tm_mday = tm.tm_mday;
        rtc.tm_mon = tm.tm_mon;
        rtc.tm_year = tm.tm_year;
        rtc.tm_wday = tm.tm_wday;
        rtc.tm_yday = tm.tm_yday;
        rtc.tm_isdst = tm.tm_isdst;
        res = ioctl(fd, RTC_SET_TIME, &rtc);
        if (res < 0) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "ioctl RTC_SET_TIME failed,errno: %{public}s, res: %{public}d",
                strerror(errno), res);
        }
    } else {
        TIME_HILOGE(TIME_MODULE_SERVICE, "convert rtc time failed: %{public}s", strerror(errno));
        res = E_TIME_SET_RTC_FAILED;
    }
    close(fd);
    return res;
}

bool TimeSystemAbility::CheckRtc(const std::string &rtcPath, uint64_t rtcId)
{
    std::stringstream strs;
    strs << rtcPath << "/rtc" << rtcId << "/hctosys";
    auto hctosys_path = strs.str();

    std::fstream file(hctosys_path.data(), std::ios_base::in);
    if (file.is_open()) {
        return true;
    } else {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to open %{public}s", hctosys_path.data());
        return false;
    }
}

int TimeSystemAbility::GetWallClockRtcId()
{
    std::string rtcPath = "/sys/class/rtc";

    std::unique_ptr<DIR, int (*)(DIR *)> dir(opendir(rtcPath.c_str()), closedir);
    if (!dir.get()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to open %{public}s: %{public}s", rtcPath.c_str(), strerror(errno));
        return -1;
    }

    struct dirent *dirent;
    std::string s = "rtc";
    while (errno = 0, dirent = readdir(dir.get())) {
        std::string name(dirent->d_name);
        unsigned long rtcId = 0;
        auto index = name.find(s);
        if (index == std::string::npos) {
            continue;
        } else {
            auto rtcIdStr = name.substr(index + s.length());
            rtcId = std::stoul(rtcIdStr);
        }
        if (CheckRtc(rtcPath, rtcId)) {
            TIME_HILOGD(TIME_MODULE_SERVICE, "found wall clock rtc %{public}ld", rtcId);
            return rtcId;
        }
    }

    if (errno == 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "no wall clock rtc found");
    } else {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to check rtc: %{public}s", strerror(errno));
    }
    return -1;
}

int32_t TimeSystemAbility::SetTimeZone(const std::string &timeZoneId, APIVersion apiVersion)
{
    if (!TimeZoneInfo::GetInstance().SetTimezone(timeZoneId)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Set timezone failed :%{public}s", timeZoneId.c_str());
        return E_TIME_DEAL_FAILED;
    }
    int64_t currentTime = 0;
    GetBootTimeMs(currentTime);
    TimeServiceNotify::GetInstance().PublishTimeZoneChangeEvents(currentTime);
    return ERR_OK;
}

int32_t TimeSystemAbility::GetTimeZone(std::string &timeZoneId)
{
    if (!TimeZoneInfo::GetInstance().GetTimezone(timeZoneId)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get timezone failed");
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "Current timezone : %{public}s", timeZoneId.c_str());
    return ERR_OK;
}

int32_t TimeSystemAbility::GetWallTimeMs(int64_t &time)
{
    struct timespec tv {};
    if (GetTimeByClockId(CLOCK_REALTIME, tv)) {
        time = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetWallTimeNs(int64_t &time)
{
    struct timespec tv {};
    if (GetTimeByClockId(CLOCK_REALTIME, tv)) {
        time = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetBootTimeMs(int64_t &time)
{
    struct timespec tv {};
    if (GetTimeByClockId(CLOCK_BOOTTIME, tv)) {
        time = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetBootTimeNs(int64_t &time)
{
    struct timespec tv {};
    if (GetTimeByClockId(CLOCK_BOOTTIME, tv)) {
        time = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetMonotonicTimeMs(int64_t &time)
{
    struct timespec tv {};
    if (GetTimeByClockId(CLOCK_MONOTONIC, tv)) {
        time = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetMonotonicTimeNs(int64_t &time)
{
    struct timespec tv {};
    if (GetTimeByClockId(CLOCK_MONOTONIC, tv)) {
        time = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetThreadTimeMs(int64_t &time)
{
    struct timespec tv {};
    clockid_t cid;
    int ret = pthread_getcpuclockid(pthread_self(), &cid);
    if (ret != E_TIME_OK) {
        return E_TIME_PARAMETERS_INVALID;
    }
    if (GetTimeByClockId(cid, tv)) {
        time = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetThreadTimeNs(int64_t &time)
{
    struct timespec tv {};
    clockid_t cid;
    int ret = pthread_getcpuclockid(pthread_self(), &cid);
    if (ret != E_TIME_OK) {
        return E_TIME_PARAMETERS_INVALID;
    }
    if (GetTimeByClockId(cid, tv)) {
        time = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return E_TIME_DEAL_FAILED;
}

bool TimeSystemAbility::GetTimeByClockId(clockid_t clockId, struct timespec &tv)
{
    if (clock_gettime(clockId, &tv) < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Failed clock_gettime.");
        return false;
    }
    return true;
}

bool TimeSystemAbility::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    if (!TimePermission::CheckProxyCallingPermission()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "ProxyTimer permission check failed");
        return E_TIME_NO_PERMISSION;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "ProxyTimer service start uid: %{public}d, isProxy: %{public}d", uid, isProxy);
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "ProxyTimer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Proxytimer manager init failed.");
            return false;
        }
    }
    return timerManagerHandler_->ProxyTimer(uid, isProxy, needRetrigger);
}

int32_t TimeSystemAbility::AdjustTimer(bool isAdjust, uint32_t interval)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Adjust Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Adjust Timer manager init failed.");
            return E_TIME_NULLPTR;
        }
    }
    if (!timerManagerHandler_->AdjustTimer(isAdjust, interval)) {
        return E_TIME_NO_TIMER_ADJUST;
    }
    return E_TIME_OK;
}

bool TimeSystemAbility::ProxyTimer(std::set<int> pidList, bool isProxy, bool needRetrigger)
{
    if (!TimePermission::CheckProxyCallingPermission()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "ProxyTimer permission check failed");
        return E_TIME_NO_PERMISSION;
    }
    
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "ProxyTimer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Proxytimer manager init failed.");
            return false;
        }
    }
    return timerManagerHandler_->ProxyTimer(pidList, isProxy, needRetrigger);
}

int32_t TimeSystemAbility::SetTimerExemption(const std::unordered_set<std::string> &nameArr, bool isExemption)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Set Timer Exemption manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Set Timer Exemption manager init failed.");
            return E_TIME_NULLPTR;
        }
    }
    timerManagerHandler_->SetTimerExemption(nameArr, isExemption);
    return E_TIME_OK;
}

bool TimeSystemAbility::ResetAllProxy()
{
    if (!TimePermission::CheckProxyCallingPermission()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "ResetAllProxy permission check failed");
        return E_TIME_NO_PERMISSION;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "ResetAllProxy service");
    if (timerManagerHandler_ == nullptr) {
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "ResetAllProxy timer manager init failed");
            return false;
        }
    }
    return timerManagerHandler_->ResetAllProxy();
}

void TimeSystemAbility::RSSSaDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    if (timerManagerHandler_ != nullptr) {
        timerManagerHandler_->HandleRSSDeath();
    }
}

void TimeSystemAbility::RegisterRSSDeathCallback()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "register rss death callback");
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Getting SystemAbilityManager failed.");
        return;
    }

    auto systemAbility = systemAbilityManager->GetSystemAbility(DEVICE_STANDBY_SERVICE_SYSTEM_ABILITY_ID);
    if (systemAbility == nullptr) {
        TIME_HILOGE(TIME_MODULE_CLIENT, "Get SystemAbility failed.");
        return;
    }

    if (deathRecipient_ == nullptr) {
        deathRecipient_ = new RSSSaDeathRecipient();
    }

    systemAbility->AddDeathRecipient(deathRecipient_);
}

void TimeSystemAbility::TimePowerStateListener::OnSyncShutdown()
{
    // Clears `drop_on_reboot` table.
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnSyncShutdown");
    TimeSystemAbility::GetInstance()->SetAutoReboot();
    TimeDatabase::GetInstance().ClearDropOnReboot();
}

void TimeSystemAbility::RegisterPowerStateListener()
{
    TIME_HILOGI(TIME_MODULE_CLIENT, "RegisterPowerStateListener");
    auto& powerManagerClient = OHOS::PowerMgr::ShutdownClient::GetInstance();
    sptr<OHOS::PowerMgr::ISyncShutdownCallback> syncShutdownCallback = new TimePowerStateListener();
    if (!syncShutdownCallback) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Get TimePowerStateListener failed.");
        return;
    }
    powerManagerClient.RegisterShutdownCallback(syncShutdownCallback, PowerMgr::ShutdownPriority::HIGH);
    TIME_HILOGI(TIME_MODULE_CLIENT, "RegisterPowerStateListener end");
}

bool TimeSystemAbility::RecoverTimer()
{
    auto database = TimeDatabase::GetInstance();
    OHOS::NativeRdb::RdbPredicates holdRdbPredicates(HOLD_ON_REBOOT);
    auto holdResultSet = database.Query(holdRdbPredicates, ALL_DATA);
    if (holdResultSet == nullptr || holdResultSet->GoToFirstRow() != OHOS::NativeRdb::E_OK) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "hold result set is nullptr or go to first row failed");
    } else {
        RecoverTimerInner(holdResultSet);
    }

    OHOS::NativeRdb::RdbPredicates dropRdbPredicates(DROP_ON_REBOOT);
    auto dropResultSet = database.Query(dropRdbPredicates, ALL_DATA);
    if (dropResultSet == nullptr || dropResultSet->GoToFirstRow() != OHOS::NativeRdb::E_OK) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "drop result set is nullptr or go to first row failed");
    } else {
        RecoverTimerInner(dropResultSet);
    }
    return true;
}

void TimeSystemAbility::RecoverTimerInner(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet)
{
    do {
        auto timerId = static_cast<uint64_t>(GetLong(resultSet, 0));
        auto timerInfo = std::make_shared<TimerEntry>(TimerEntry {
            // Line 0 is 'timerId'
            timerId,
            // Line 1 is 'type'
            GetInt(resultSet, 1),
            // Line 3 is 'windowLength'
            static_cast<uint64_t>(GetLong(resultSet, 3)),
            // Line 4 is 'interval'
            static_cast<uint64_t>(GetLong(resultSet, 4)),
            // Line 2 is 'flag'
            GetInt(resultSet, 2),
            // Callback can't recover.
            nullptr,
            // Line 7 is 'wantAgent'
            OHOS::AbilityRuntime::WantAgent::WantAgentHelper::FromString(GetString(resultSet, 7)),
            // Line 5 is 'uid'
            GetInt(resultSet, 5),
            0,
            // Line 6 is 'bundleName'
            GetString(resultSet, 6)
        });
        timerManagerHandler_->ReCreateTimer(timerId, timerInfo);
        // Line 8 is 'state'
        auto state = static_cast<uint8_t>(GetInt(resultSet, 8));
        if (state == 1) {
            // Line 9 is 'triggerTime'
            auto triggerTime = static_cast<uint64_t>(GetLong(resultSet, 9));
            timerManagerHandler_->StartTimer(timerId, triggerTime);
        }
    } while (resultSet->GoToNextRow() == OHOS::NativeRdb::E_OK);
    resultSet->Close();
}

void TimeSystemAbility::SetAutoReboot()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Find the most recent trigger time");
    auto database = TimeDatabase::GetInstance();
    OHOS::NativeRdb::RdbPredicates holdRdbPredicates(HOLD_ON_REBOOT);
    holdRdbPredicates.EqualTo("state", 1)->OrderByAsc("triggerTime");
    auto resultSet = database.Query(holdRdbPredicates, ALL_DATA);
    if (resultSet == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Find the most recent trigger time failed");
        return;
    }
    int64_t currentTime = 0;
    TimeSystemAbility::GetInstance()->GetWallTimeMs(currentTime);
    do {
        auto bundleName = GetString(resultSet, 6);
        uint64_t triggerTime = static_cast<uint64_t>(GetLong(resultSet, 9));
        if (triggerTime < static_cast<uint64_t>(currentTime)) {
            TIME_HILOGI(TIME_MODULE_SERVICE,
                        "triggerTime: %{public}" PRIu64" currentTime: %{public}" PRId64"", triggerTime, currentTime);
            continue;
        }
        if (bundleName == NEED_RECOVER_ON_REBOOT) {
            int tmfd = timerfd_create(CLOCK_POWEROFF_ALARM, TFD_NONBLOCK);
            if (tmfd < 0) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "timerfd_create error: %{public}s", strerror(errno));
                resultSet->Close();
                return;
            }
            if (static_cast<uint64_t>(currentTime) + TWO_MINUTES_TO_MILLI > triggerTime) {
                TIME_HILOGI(TIME_MODULE_SERVICE, "interval less than 2min");
                triggerTime = static_cast<uint64_t>(currentTime) + TWO_MINUTES_TO_MILLI;
            }
            struct itimerspec new_value;
            std::chrono::nanoseconds nsec(triggerTime * MILLISECOND_TO_NANO);
            auto second = std::chrono::duration_cast<std::chrono::seconds>(nsec);
            new_value.it_value.tv_sec = second.count();
            new_value.it_value.tv_nsec = (nsec - second).count();
            TIME_HILOGI(TIME_MODULE_SERVICE, "currentTime:%{public}" PRId64 ", second:%{public}" PRId64 ","
                        "nanosecond:%{public}" PRId64"", currentTime, static_cast<int64_t>(new_value.it_value.tv_sec),
                        static_cast<int64_t>(new_value.it_value.tv_nsec));
            int ret = timerfd_settime(tmfd, TFD_TIMER_ABSTIME, &new_value, nullptr);
            if (ret < 0) {
                TIME_HILOGE(TIME_MODULE_SERVICE, "timerfd_settime error: %{public}s", strerror(errno));
                close(tmfd);
            }
            resultSet->Close();
            return;
        }
    } while (resultSet->GoToNextRow() == OHOS::NativeRdb::E_OK);
    resultSet->Close();
}
} // namespace MiscServices
} // namespace OHOS