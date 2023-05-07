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
#include <climits>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <linux/rtc.h>
#include <mutex>
#include <singleton.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "iservice_registry.h"
#include "ntp_update_time.h"
#include "pthread.h"
#include "system_ability.h"
#include "system_ability_definition.h"
#include "time_common.h"
#include "time_tick_notify.h"
#include "time_zone_info.h"

using namespace std::chrono;

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
constexpr int32_t MILLI_TO_MICR = MICR_TO_BASE / MILLI_TO_BASE;
constexpr int32_t NANO_TO_MILLI = NANO_TO_BASE / MILLI_TO_BASE;
constexpr int32_t ONE_MILLI = 1000;
}

REGISTER_SYSTEM_ABILITY_BY_ID(TimeSystemAbility, TIME_SERVICE_ID, true);

std::mutex TimeSystemAbility::instanceLock_;
sptr<TimeSystemAbility> TimeSystemAbility::instance_;
std::shared_ptr<AppExecFwk::EventHandler> TimeSystemAbility::serviceHandler_ = nullptr;
std::shared_ptr<TimerManager> TimeSystemAbility::timerManagerHandler_  = nullptr;

TimeSystemAbility::TimeSystemAbility(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate),
      state_(ServiceRunningState::STATE_NOT_START),
      rtcId(GetWallClockRtcId())
{
    TIME_HILOGI(TIME_MODULE_SERVICE, " TimeService Start.");
}

TimeSystemAbility::TimeSystemAbility()
    :state_(ServiceRunningState::STATE_NOT_START), rtcId(GetWallClockRtcId())
{
}

TimeSystemAbility::~TimeSystemAbility() {};

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
}

void TimeSystemAbility::OnStart()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, " TimeService OnStart.");
    if (state_ == ServiceRunningState::STATE_RUNNING) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " TimeService is already running.");
        return;
    }

    InitServiceHandler();
    InitTimerHandler();
    DelayedSingleton<TimeTickNotify>::GetInstance()->Init();
    DelayedSingleton<TimeZoneInfo>::GetInstance()->Init();
    DelayedSingleton<NtpUpdateTime>::GetInstance()->Init();
    AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);
    InitDumpCmd();
    TIME_HILOGI(TIME_MODULE_SERVICE, "Start TimeService success.");
    if (Init() != ERR_OK) {
        auto callback = [this]() { Init(); };
        serviceHandler_->PostTask(callback, INIT_INTERVAL);
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init failed. Try again 10s later.");
        return;
    }
}

void TimeSystemAbility::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnAddSystemAbility systemAbilityId:%{public}d added!", systemAbilityId);
    if (systemAbilityId == COMMON_EVENT_SERVICE_ID) {
        RegisterSubscriber();
    } else {
        TIME_HILOGE(TIME_MODULE_SERVICE, "OnAddSystemAbility systemAbilityId is not COMMON_EVENT_SERVICE_ID");
        return;
    }
}

void TimeSystemAbility::RegisterSubscriber()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "RegisterSubscriber Started");
    bool subRes = DelayedSingleton<TimeServiceNotify>::GetInstance()->RepublishEvents();
    if (!subRes) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to RegisterSubscriber");
        auto callback = [this]() { DelayedSingleton<TimeServiceNotify>::GetInstance()->RepublishEvents(); };
        serviceHandler_->PostTask(callback, "time_service_subscriber_retry", INIT_INTERVAL);
    } else {
        TIME_HILOGI(TIME_MODULE_SERVICE, "RegisterSubscriber success.");
    }
}

int32_t TimeSystemAbility::Init()
{
    bool ret = Publish(TimeSystemAbility::GetInstance());
    if (!ret) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Init Failed.");
        return E_TIME_PUBLISH_FAIL;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Init Success.");
    state_ = ServiceRunningState::STATE_RUNNING;
    return ERR_OK;
}

void TimeSystemAbility::OnStop()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnStop Started.");
    if (state_ != ServiceRunningState::STATE_RUNNING) {
        return;
    }
    serviceHandler_ = nullptr;
    DelayedSingleton<TimeTickNotify>::GetInstance()->Stop();
    state_ = ServiceRunningState::STATE_NOT_START;
    TIME_HILOGI(TIME_MODULE_SERVICE, "OnStop End.");
}

void TimeSystemAbility::InitServiceHandler()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "InitServiceHandler started.");
    if (serviceHandler_ != nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " Already init.");
        return;
    }
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(TIME_SERVICE_NAME);
    serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    TIME_HILOGI(TIME_MODULE_SERVICE, "InitServiceHandler Succeeded.");
}

void TimeSystemAbility::InitTimerHandler()
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Init Timer started.");
    if (timerManagerHandler_ != nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, " Already init.");
        return;
    }
    timerManagerHandler_ = TimerManager::Create();
}

void TimeSystemAbility::ParseTimerPara(std::shared_ptr<ITimerInfo> timerOptions, TimerPara &paras)
{
    auto uIntType = static_cast<uint32_t>(timerOptions->type);
    bool isRealtime = (uIntType & TIMER_TYPE_REALTIME_MASK) > 0 ? true : false;
    bool isWakeup = (uIntType & TIMER_TYPE_REALTIME_WAKEUP_MASK) > 0 ? true : false;
    paras.windowLength = (uIntType & TIMER_TYPE_EXACT_MASK) > 0 ? 0 : -1;
    paras.flag = 0;
    if (isRealtime && isWakeup) {
        paras.timerType = ITimerManager::TimerType::ELAPSED_REALTIME_WAKEUP;
    } else if (isRealtime) {
        paras.timerType = ITimerManager::TimerType::ELAPSED_REALTIME;
    } else if (isWakeup) {
        paras.timerType = ITimerManager::TimerType::RTC_WAKEUP;
    } else {
        paras.timerType = ITimerManager::TimerType::RTC;
    }
    paras.interval = timerOptions->repeat ? timerOptions->interval : 0;
    return;
}

int32_t TimeSystemAbility::CreateTimer(const std::shared_ptr<ITimerInfo> &timerOptions, sptr<IRemoteObject> &obj,
    uint64_t &timerId)
{
    int uid = IPCSkeleton::GetCallingUid();
    if (obj == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Input nullptr.");
        return E_TIME_NULLPTR;
    }
    struct TimerPara paras {};
    ParseTimerPara(timerOptions, paras);
    sptr<ITimerCallback> timerCallback = iface_cast<ITimerCallback>(obj);
    if (timerCallback == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "ITimerCallback nullptr.");
        return E_TIME_NULLPTR;
    }
    TIME_HILOGI(TIME_MODULE_SERVICE, "Start create timer.");
    auto callbackFunc = [timerCallback](uint64_t id) {
        timerCallback->NotifyTimer(id, nullptr);
    };
    int64_t triggerTime = 0;
    GetWallTimeMs(triggerTime);
    StatisticReporter(IPCSkeleton::GetCallingPid(), uid, timerOptions->type, triggerTime, timerOptions->interval);
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return E_TIME_NULLPTR;
        }
    }
    return timerManagerHandler_->CreateTimer(paras, callbackFunc, timerOptions->wantAgent, uid, timerId);
}

int32_t TimeSystemAbility::CreateTimer(
    TimerPara &paras, std::function<void(const uint64_t)> Callback, uint64_t &timerId)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return E_TIME_NULLPTR;
        }
    }
    return timerManagerHandler_->CreateTimer(paras, Callback, nullptr, 0, timerId);
}

int32_t TimeSystemAbility::StartTimer(uint64_t timerId, uint64_t triggerTimes)
{
    if (timerManagerHandler_ == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Timer manager nullptr.");
        timerManagerHandler_ = TimerManager::Create();
        if (timerManagerHandler_ == nullptr) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "Redo Timer manager Init Failed.");
            return false;
        }
    }
    auto ret = timerManagerHandler_->StartTimer(timerId, triggerTimes);
    if (ret != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "TimerId Not found.");
    }
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
    if (ret != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "TimerId Not found.");
    }
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
    if (ret != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "TimerId Not found.");
    }
    return ret;
}

bool TimeSystemAbility::SetRealTime(int64_t time)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Setting time of day to milliseconds: %{public}" PRId64 "", time);
    if (time < 0 || time / 1000LL >= LLONG_MAX) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "input param error");
        return false;
    }
    int64_t currentTime = 0;
    if (GetWallTimeMs(currentTime) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "currentTime get failed");
        return false;
    }
    struct timeval tv {};
    tv.tv_sec = (time_t) (time / MILLI_TO_BASE);
    tv.tv_usec = (suseconds_t)((time % MILLI_TO_BASE) * MILLI_TO_MICR);

    int result = settimeofday(&tv, NULL);
    if (result < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "settimeofday time fail: %{public}d.", result);
        return false;
    }
    auto ret = SetRtcTime(tv.tv_sec);
    if (ret == E_TIME_SET_RTC_FAILED) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "set rtc fail: %{public}d.", ret);
        return false;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "getting currentTime to milliseconds: %{public}" PRId64 "", currentTime);
    if (currentTime < (time - ONE_MILLI) || currentTime > (time + ONE_MILLI)) {
        DelayedSingleton<TimeServiceNotify>::GetInstance()->PublishTimeChangeEvents(currentTime);
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
    struct timespec ts;
    struct tm timestr;
    char date_time[64];
    if (GetTimeByClockid(CLOCK_BOOTTIME, ts)) {
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", localtime_r(&ts.tv_sec, &timestr));
        dprintf(fd, " * date time = %s\n", date_time);
    } else {
        dprintf(fd, " * dump date time error.\n");
    }
    dprintf(fd, " - dump the time Zone:\n");
    std::string timeZone = "";
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
    timerManagerHandler_->ShowtimerEntryMap(fd);
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
            TIME_HILOGE(TIME_MODULE_SERVICE, "ioctl RTC_SET_TIME failed: %{public}s", strerror(errno));
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
    auto hctosysPath = strs.str();

    std::fstream file(hctosysPath.data(), std::ios_base::in);
    if (file.is_open()) {
        return true;
    } else {
        TIME_HILOGE(TIME_MODULE_SERVICE, "failed to open %{public}s", hctosysPath.data());
        return false;
    }
    return true;
}

int TimeSystemAbility::GetWallClockRtcId()
{
    std::string rtcPath = "/sys/class/rtc";

    std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir(rtcPath.c_str()), closedir);
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
    if (!DelayedSingleton<TimeZoneInfo>::GetInstance()->SetTimezone(timeZoneId)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Set timezone failed :%{public}s", timeZoneId.c_str());
        return E_TIME_DEAL_FAILED;
    }
    int64_t currentTime = 0;
    GetBootTimeMs(currentTime);
    DelayedSingleton<TimeServiceNotify>::GetInstance()->PublishTimeZoneChangeEvents(currentTime);
    return ERR_OK;
}

int32_t TimeSystemAbility::GetTimeZone(std::string &timeZoneId)
{
    if (!DelayedSingleton<TimeZoneInfo>::GetInstance()->GetTimezone(timeZoneId)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get timezone failed.");
        return E_TIME_DEAL_FAILED;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "Current timezone : %{public}s", timeZoneId.c_str());
    return ERR_OK;
}

int32_t TimeSystemAbility::GetWallTimeMs(int64_t &times)
{
    struct timespec tv {};
    if (GetTimeByClockid(CLOCK_REALTIME, tv)) {
        times = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetWallTimeNs(int64_t &times)
{
    struct timespec tv {};
    if (GetTimeByClockid(CLOCK_REALTIME, tv)) {
        times = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetBootTimeMs(int64_t &times)
{
    struct timespec tv {};
    if (GetTimeByClockid(CLOCK_BOOTTIME, tv)) {
        times = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetBootTimeNs(int64_t &times)
{
    struct timespec tv {};
    if (GetTimeByClockid(CLOCK_BOOTTIME, tv)) {
        times = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetMonotonicTimeMs(int64_t &times)
{
    struct timespec tv {};
    if (GetTimeByClockid(CLOCK_MONOTONIC, tv)) {
        times = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetMonotonicTimeNs(int64_t &times)
{
    struct timespec tv {};
    if (GetTimeByClockid(CLOCK_MONOTONIC, tv)) {
        times = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetThreadTimeMs(int64_t &times)
{
    struct timespec tv {};
    int ret;
    clockid_t cid;
    ret = pthread_getcpuclockid(pthread_self(), &cid);
    if (ret != 0) {
        return E_TIME_PARAMETERS_INVALID;
    }

    if (GetTimeByClockid(cid, tv)) {
        times = tv.tv_sec * MILLI_TO_BASE + tv.tv_nsec / NANO_TO_MILLI;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

int32_t TimeSystemAbility::GetThreadTimeNs(int64_t &times)
{
    struct timespec tv {};
    int ret;
    clockid_t cid;
    ret = pthread_getcpuclockid(pthread_self(), &cid);
    if (ret != 0) {
        return E_TIME_PARAMETERS_INVALID;
    }

    if (GetTimeByClockid(cid, tv)) {
        times = tv.tv_sec * NANO_TO_BASE + tv.tv_nsec;
        return ERR_OK;
    }
    return  E_TIME_DEAL_FAILED;
}

bool TimeSystemAbility::GetTimeByClockid(clockid_t clockId, struct timespec &tv)
{
    if (clock_gettime(clockId, &tv) < 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "Failed clock_gettime.");
        return false;
    }
    return true;
}

bool TimeSystemAbility::ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger)
{
    if (!DelayedSingleton<TimePermission>::GetInstance()->CheckProxyCallingPermission()) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "ProxyTimer permission check failed");
        return E_TIME_NO_PERMISSION;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "ProxyTimer service start uid: %{public}d, isProxy: %{public}d",
        uid, isProxy);
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

bool TimeSystemAbility::ResetAllProxy()
{
    if (!DelayedSingleton<TimePermission>::GetInstance()->CheckProxyCallingPermission()) {
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
} // namespace MiscServices
} // namespace OHOS