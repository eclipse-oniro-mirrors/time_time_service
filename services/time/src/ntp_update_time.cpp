/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "ntp_update_time.h"

#include <chrono>
#include <cinttypes>
#include <string>
#include <thread>
#include <unistd.h>

#include "init_param.h"
#include "json/json.h"
#include "net_conn_callback_observer.h"
#include "net_conn_client.h"
#include "net_specifier.h"
#include "nitz_subscriber.h"
#include "ntp_trusted_time.h"
#include "parameters.h"
#include "time_common.h"
#include "time_system_ability.h"

using namespace std::chrono;
using namespace OHOS::NetManagerStandard;

namespace OHOS {
namespace MiscServices {
namespace {
constexpr int64_t NANO_TO_MILLISECOND = 1000000;
constexpr int64_t DAY_TO_MILLISECOND = 86400000;
const std::string AUTOTIME_FILE_PATH = "/data/service/el1/public/time/autotime.json";
const std::string NTP_SERVER_SYSTEM_PARAMETER = "persist.time.ntpserver";
const std::string NTP_SERVER_SPECIFIC_SYSTEM_PARAMETER = "persist.time.ntpserver_specific";
const int64_t INVALID_TIMES = -1;
const uint32_t NTP_MAX_SIZE = 5;
const std::string AUTO_TIME_SYSTEM_PARAMETER = "persist.time.auto_time";
const std::string AUTO_TIME_STATUS_ON = "ON";
const std::string AUTO_TIME_STATUS_OFF = "OFF";
constexpr uint64_t TWO_SECONDS = 2000;
const std::string DEFAULT_NTP_SERVER = "1.cn.pool.ntp.org";
} // namespace

AutoTimeInfo NtpUpdateTime::autoTimeInfo_{};
std::atomic<bool> NtpUpdateTime::isRequesting_ = false;

NtpUpdateTime::NtpUpdateTime() : timerId_(0), nitzUpdateTimeMilli_(0), nextTriggerTime_(0), lastNITZUpdateTime_(0){};

NtpUpdateTime& NtpUpdateTime::GetInstance()
{
    static NtpUpdateTime instance;
    return instance;
}

void NtpUpdateTime::Init()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp Update Time start.");
    SubscriberNITZTimeChangeCommonEvent();
    std::string ntpServer = system::GetParameter(NTP_SERVER_SYSTEM_PARAMETER, DEFAULT_NTP_SERVER);
    std::string ntpServerSpec = system::GetParameter(NTP_SERVER_SPECIFIC_SYSTEM_PARAMETER, "");
    std::string autoTime = system::GetParameter(AUTO_TIME_SYSTEM_PARAMETER, "ON");
    if ((ntpServer.empty() && ntpServerSpec.empty()) || autoTime.empty()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "No found parameter from system parameter.");
        return;
    }
    RegisterSystemParameterListener();
    if (!GetAutoTimeInfoFromFile(autoTimeInfo_)) {
        autoTimeInfo_.lastUpdateTime = INVALID_TIMES;
    }
    autoTimeInfo_.ntpServer = ntpServer;
    autoTimeInfo_.ntpServerSpec = ntpServerSpec;
    autoTimeInfo_.status = autoTime;
    SaveAutoTimeInfoToFile(autoTimeInfo_);
    std::thread th = std::thread([this]() {
        pthread_setname_np(pthread_self(), "time_monitor_network");
        if (this->MonitorNetwork() != NETMANAGER_SUCCESS) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "monitor network failed");
        }
    });
    th.detach();
    auto callback = [this](uint64_t id) {
        this->RefreshNetworkTimeByTimer(id);
    };
    TimerPara timerPara{};
    timerPara.timerType = static_cast<int>(ITimerManager::TimerType::ELAPSED_REALTIME);
    timerPara.windowLength = 0;
    timerPara.interval = DAY_TO_MILLISECOND;
    timerPara.flag = 0;
    TimeSystemAbility::GetInstance()->CreateTimer(timerPara, callback, timerId_);
    RefreshNextTriggerTime();
    TimeSystemAbility::GetInstance()->StartTimer(timerId_, nextTriggerTime_);
    TIME_HILOGI(TIME_MODULE_SERVICE, "ntp update timerId: %{public}" PRIu64 "triggertime: %{public}" PRId64 "",
                timerId_, nextTriggerTime_);
}

int32_t NtpUpdateTime::MonitorNetwork()
{
    // observer net connection
    TIME_HILOGD(TIME_MODULE_SERVICE, "NtpUpdateTime::MonitorNetwork");
    NetSpecifier netSpecifier;
    NetAllCapabilities netAllCapabilities;
    netAllCapabilities.netCaps_.insert(NetManagerStandard::NetCap::NET_CAPABILITY_INTERNET);
    netSpecifier.netCapabilities_ = netAllCapabilities;
    sptr<NetSpecifier> specifier = new (std::nothrow) NetSpecifier(netSpecifier);
    if (specifier == nullptr) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "new operator error.specifier is nullptr");
        return NET_CONN_ERR_INPUT_NULL_PTR;
    }
    sptr<NetConnCallbackObserver> observer = new (std::nothrow) NetConnCallbackObserver();
    if (observer == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "new operator error.observer is nullptr");
        return NET_CONN_ERR_INPUT_NULL_PTR;
    }
    int nRet = NetConnClient::GetInstance().RegisterNetConnCallback(specifier, observer, 0);
    TIME_HILOGD(TIME_MODULE_SERVICE, "RegisterNetConnCallback retcode= %{public}d", nRet);

    return nRet;
}

void NtpUpdateTime::SubscriberNITZTimeChangeCommonEvent()
{
    // Broadcast subscription
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_NITZ_TIME_CHANGED);
    CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    std::shared_ptr<NITZSubscriber> subscriberPtr = std::make_shared<NITZSubscriber>(subscriberInfo);
    bool subscribeResult = CommonEventManager::SubscribeCommonEvent(subscriberPtr);
    if (!subscribeResult) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "SubscribeCommonEvent failed");
    }
}

void NtpUpdateTime::RefreshNetworkTimeByTimer(uint64_t timerId)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "The timer is up");
    if (!CheckStatus()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "Auto Sync Switch Off");
        return;
    }

    if (IsValidNITZTime()) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "NITZ is valid");
        return;
    }

    SetSystemTime();
    SaveAutoTimeInfoToFile(autoTimeInfo_);
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp next triggertime: %{public}" PRId64 "", nextTriggerTime_);
}

void NtpUpdateTime::UpdateNITZSetTime()
{
    auto bootTimeNano = steady_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILLISECOND;
    if (TimeSystemAbility::GetInstance()->GetBootTimeMs(lastNITZUpdateTime_) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get boot time fail.");
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "nitz time changed.");
    nitzUpdateTimeMilli_ = static_cast<uint64_t>(bootTimeMilli);
}

std::vector<std::string> NtpUpdateTime::SplitNtpAddrs(const std::string &ntpStr)
{
    std::vector<std::string> ntpList;
    size_t start = 0;
    do {
        if (ntpList.size() == NTP_MAX_SIZE) {
            break;
        }
        size_t end = ntpStr.find(',', start);
        std::string temp = ntpStr.substr(start, end - start);
        if (temp.empty()) {
            ++start;
            continue;
        }
        if (end == std::string::npos) {
            ntpList.emplace_back(temp);
            break;
        }
        ntpList.emplace_back(temp);
        start = end + 1;
    } while (start < ntpStr.size());
    return ntpList;
}

void NtpUpdateTime::SetSystemTime()
{
    if (autoTimeInfo_.status != AUTO_TIME_STATUS_ON) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "auto sync switch off");
        return;
    }
    if (isRequesting_.exchange(true)) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "The NTP request is in progress.");
        return;
    }
    bool ret = false;
    std::vector<std::string> ntpSpecList = SplitNtpAddrs(autoTimeInfo_.ntpServerSpec);
    std::vector<std::string> ntpList = SplitNtpAddrs(autoTimeInfo_.ntpServer);
    ntpSpecList.insert(ntpSpecList.end(), ntpList.begin(), ntpList.end());
    for (size_t i = 0; i < ntpSpecList.size(); i++) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "ntpServer is : %{public}s", ntpSpecList[i].c_str());
        ret = NtpTrustedTime::GetInstance().ForceRefresh(ntpSpecList[i]);
        if (ret) {
            break;
        }
    }
    if (!ret) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get ntp time failed.");
        isRequesting_ = false;
        return;
    }
    int64_t currentTime = NtpTrustedTime::GetInstance().CurrentTimeMillis();
    if (currentTime <= 0) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "current time is invalid: %{public}" PRIu64 "", currentTime);
        isRequesting_ = false;
        return;
    }
    int64_t curBootTime = 0;
    if (TimeSystemAbility::GetInstance()->GetBootTimeMs(curBootTime) != ERR_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get boot time fail.");
        isRequesting_ = false;
        return;
    }
    if (curBootTime - NtpUpdateTime::GetInstance().GetNITZUpdateTime() <= TWO_SECONDS) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "nitz updated time");
        isRequesting_ = false;
        return;
    }
    TimeSystemAbility::GetInstance()->SetTime(currentTime);
    autoTimeInfo_.lastUpdateTime = currentTime;
    isRequesting_ = false;
}

void NtpUpdateTime::RefreshNextTriggerTime()
{
    auto bootTimeNano = steady_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILLISECOND;
    nextTriggerTime_ = static_cast<uint64_t>(bootTimeMilli + DAY_TO_MILLISECOND);
}

bool NtpUpdateTime::CheckStatus()
{
    return autoTimeInfo_.status == AUTO_TIME_STATUS_ON;
}

bool NtpUpdateTime::IsValidNITZTime()
{
    if (nitzUpdateTimeMilli_ == 0) {
        return false;
    }
    auto bootTimeNano = steady_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILLISECOND;
    TIME_HILOGI(TIME_MODULE_SERVICE, "nitz update time: %{public}" PRIu64 " currentTime: %{public}" PRId64 "",
        nitzUpdateTimeMilli_, bootTimeMilli);
    return (bootTimeMilli - static_cast<int64_t>(nitzUpdateTimeMilli_)) < DAY_TO_MILLISECOND;
}

void NtpUpdateTime::StartTimer()
{
    TimeSystemAbility::GetInstance()->StartTimer(timerId_, nextTriggerTime_);
}

void NtpUpdateTime::Stop()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    TimeSystemAbility::GetInstance()->DestroyTimer(timerId_);
}

bool NtpUpdateTime::GetAutoTimeInfoFromFile(AutoTimeInfo &info)
{
    Json::Value jsonValue;
    std::ifstream ifs;
    ifs.open(AUTOTIME_FILE_PATH);
    Json::CharReaderBuilder builder;
    builder["collectComments"] = true;
    JSONCPP_STRING errs;
    if (!parseFromStream(builder, ifs, &jsonValue, &errs)) {
        ifs.close();
        TIME_HILOGE(TIME_MODULE_SERVICE, "Read file failed %{public}s.", errs.c_str());
        return false;
    }
    info.status = jsonValue["status"].asString();
    info.ntpServer = jsonValue["ntpServer"].asString();
    info.ntpServerSpec = jsonValue["ntpServerSpec"].asString();
    info.lastUpdateTime = jsonValue["lastUpdateTime"].asInt64();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Read file %{public}s.", info.status.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Read file %{public}s.", info.ntpServer.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Read file %{public}s.", info.ntpServerSpec.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Read file %{public}" PRId64 "", info.lastUpdateTime);
    ifs.close();
    return true;
}

bool NtpUpdateTime::SaveAutoTimeInfoToFile(const AutoTimeInfo &info)
{
    Json::Value jsonValue;
    std::ofstream ofs;
    ofs.open(AUTOTIME_FILE_PATH);
    jsonValue["status"] = info.status;
    jsonValue["ntpServer"] = info.ntpServer;
    jsonValue["ntpServerSpec"] = info.ntpServerSpec;
    jsonValue["lastUpdateTime"] = info.lastUpdateTime;
    Json::StreamWriterBuilder builder;
    const std::string json_file = Json::writeString(builder, jsonValue);
    ofs << json_file;
    ofs.close();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}s.", info.status.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}s.", info.ntpServer.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}s.", info.ntpServerSpec.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}" PRId64 "", info.lastUpdateTime);
    return true;
}

void NtpUpdateTime::RegisterSystemParameterListener()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "register system parameter modify lister");
    if (SystemWatchParameter(NTP_SERVER_SPECIFIC_SYSTEM_PARAMETER.c_str(), ChangeNtpServerCallback, nullptr)
        != E_TIME_OK) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "register specific ntp server lister fail");
    }

    if (SystemWatchParameter(NTP_SERVER_SYSTEM_PARAMETER.c_str(), ChangeNtpServerCallback, nullptr) != E_TIME_OK) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "register ntp server lister fail");
    }

    if (SystemWatchParameter(AUTO_TIME_SYSTEM_PARAMETER.c_str(), ChangeAutoTimeCallback, nullptr) != E_TIME_OK) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "register auto sync switch lister fail");
    }
}

void NtpUpdateTime::ChangeNtpServerCallback(const char *key, const char *value, void *context)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Ntp server changed");
    std::string ntpServer = system::GetParameter(NTP_SERVER_SYSTEM_PARAMETER, DEFAULT_NTP_SERVER);
    std::string ntpServerSpec = system::GetParameter(NTP_SERVER_SPECIFIC_SYSTEM_PARAMETER, "");
    if (ntpServer.empty() && ntpServerSpec.empty()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "No found ntp server from system parameter.");
        return;
    }
    autoTimeInfo_.ntpServer = ntpServer;
    autoTimeInfo_.ntpServerSpec = ntpServerSpec;
    SetSystemTime();
    SaveAutoTimeInfoToFile(autoTimeInfo_);
}

void NtpUpdateTime::ChangeAutoTimeCallback(const char *key, const char *value, void *context)
{
    TIME_HILOGI(TIME_MODULE_SERVICE, "Auto sync switch changed");
    if (key == nullptr || value == nullptr) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "key or value is nullptr");
        return;
    }
    if (AUTO_TIME_SYSTEM_PARAMETER.compare(key) != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "incorrect key:%{public}s", key);
        return;
    }

    if (AUTO_TIME_STATUS_ON.compare(value) != 0 && AUTO_TIME_STATUS_OFF.compare(value) != 0) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "incorrect value:%{public}s", value);
        return;
    }
    autoTimeInfo_.status = std::string(value);
    SetSystemTime();
    SaveAutoTimeInfoToFile(autoTimeInfo_);
}

uint64_t NtpUpdateTime::GetNITZUpdateTime()
{
    return static_cast<uint64_t>(lastNITZUpdateTime_);
}
} // namespace MiscServices
} // namespace OHOS