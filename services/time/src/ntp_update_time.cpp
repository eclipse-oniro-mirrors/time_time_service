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
const std::string NETWORK_TIME_STATUS_ON = "ON";
const std::string NETWORK_TIME_STATUS_OFF = "OFF";
const std::string NTP_SERVER_SYSTEM_PARAMETER = "persist.time.ntpserver";
const int64_t INVALID_TIMES = -1;
const uint32_t NTP_MAX_SIZE = 5;
} // namespace

AutoTimeInfo NtpUpdateTime::autoTimeInfo_ {};

NtpUpdateTime::NtpUpdateTime() : timerId_(0), nitzUpdateTimeMilli_(0), nextTriggerTime_(0){};

NtpUpdateTime& NtpUpdateTime::GetInstance()
{
    static NtpUpdateTime instance;
    return instance;
}

void NtpUpdateTime::Init()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp Update Time start.");
    SubscriberNITZTimeChangeCommonEvent();
    std::string ntpServer = system::GetParameter(NTP_SERVER_SYSTEM_PARAMETER, "ntp.aliyun.com");
    if (ntpServer.empty()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "No found ntp server from system parameter.");
        return;
    }
    RegisterNtpServerListener();
    if (!GetAutoTimeInfoFromFile(autoTimeInfo_)) {
        autoTimeInfo_.lastUpdateTime = INVALID_TIMES;
        autoTimeInfo_.NTP_SERVER = ntpServer;
        autoTimeInfo_.status = NETWORK_TIME_STATUS_ON;
        if (!SaveAutoTimeInfoToFile(autoTimeInfo_)) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "end, SaveAutoTimeInfoToFile failed.");
            return;
        }
        if (!GetAutoTimeInfoFromFile(autoTimeInfo_)) {
            TIME_HILOGE(TIME_MODULE_SERVICE, "end, GetAutoTimeInfoFromFile failed.");
            return;
        }
    }

    std::thread th = std::thread([this]() {
        pthread_setname_np(pthread_self(), "time_monitor_network");
        constexpr int RETRY_MAX_TIMES = 100;
        int retryCount = 0;
        constexpr int RETRY_TIME_INTERVAL_MILLISECOND = 1 * 1000 * 1000; // retry after 2 second
        do {
            if (this->MonitorNetwork() == NETMANAGER_SUCCESS) {
                break;
            }
            retryCount++;
            usleep(RETRY_TIME_INTERVAL_MILLISECOND);
        } while (retryCount < RETRY_MAX_TIMES);
    });
    th.detach();

    int32_t timerType = ITimerManager::TimerType::ELAPSED_REALTIME;
    auto callback = [this](uint64_t id) { this->RefreshNetworkTimeByTimer(id); };

    TimerPara timerPara{};
    timerPara.timerType = timerType;
    timerPara.windowLength = 0;
    timerPara.interval = DAY_TO_MILLISECOND;
    timerPara.flag = 0;

    TimeSystemAbility::GetInstance()->CreateTimer(timerPara, callback, timerId_);
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp update timerId: %{public}" PRId64 "", timerId_);
    RefreshNextTriggerTime();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp update triggertime: %{public}" PRId64 "", nextTriggerTime_);
    TimeSystemAbility::GetInstance()->StartTimer(timerId_, nextTriggerTime_);
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
        TIME_HILOGD(TIME_MODULE_SERVICE, "new operator error.observer is nullptr");
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
    if (!(CheckStatus())) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Network time status off.");
        return;
    }
    if (IsValidNITZTime()) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "NITZ Time is valid.");
        return;
    }
    SetSystemTime();
    SaveAutoTimeInfoToFile(autoTimeInfo_);
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp update triggertime: %{public}" PRId64 "", nextTriggerTime_);
}

void NtpUpdateTime::UpdateNITZSetTime()
{
    auto bootTimeNano = steady_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILLISECOND;
    TIME_HILOGD(TIME_MODULE_SERVICE, "nitz time changed.");
    nitzUpdateTimeMilli_ = static_cast<uint64_t>(bootTimeMilli);
}

std::vector<std::string> NtpUpdateTime::SplitNtpAddrs(const std::string &ntpStr)
{
    std::vector<std::string> ntpList;
    size_t start = 0;
    do {
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
    TIME_HILOGD(TIME_MODULE_SERVICE, "start.");
    bool ret = false;
    std::vector<std::string> ntpList = SplitNtpAddrs(autoTimeInfo_.NTP_SERVER);
    size_t size = ntpList.size() < NTP_MAX_SIZE ? ntpList.size() : NTP_MAX_SIZE;
    for (size_t i = 0; i < size; i++) {
        TIME_HILOGI(TIME_MODULE_SERVICE, "ntpServer is : %{public}s", ntpList[i].c_str());
        ret = NtpTrustedTime::GetInstance().ForceRefresh(ntpList[i]);
        if (ret) {
            break;
        }
    }
    if (!ret) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "get ntp time failed.");
        return;
    }
    int64_t currentTime = NtpTrustedTime::GetInstance().CurrentTimeMillis();
    if (currentTime == INVALID_TIMES) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp update time failed");
        return;
    }
    if (currentTime <= 0) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "current time invalid.");
        return;
    }
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp UTC Time: %{public}" PRId64 "", currentTime);
    TimeSystemAbility::GetInstance()->SetTime(currentTime);
    autoTimeInfo_.lastUpdateTime = currentTime;
    TIME_HILOGD(TIME_MODULE_SERVICE, "Ntp update currentTime: %{public}" PRId64 "", currentTime);
    TIME_HILOGD(TIME_MODULE_SERVICE, "end.");
}

void NtpUpdateTime::RefreshNextTriggerTime()
{
    auto bootTimeNano = steady_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILLISECOND;
    nextTriggerTime_ = static_cast<uint64_t>(bootTimeMilli + DAY_TO_MILLISECOND);
}

bool NtpUpdateTime::CheckStatus()
{
    return autoTimeInfo_.status == NETWORK_TIME_STATUS_ON;
}

bool NtpUpdateTime::IsValidNITZTime()
{
    if (nitzUpdateTimeMilli_ == 0) {
        return false;
    }
    auto bootTimeNano = steady_clock::now().time_since_epoch().count();
    auto bootTimeMilli = bootTimeNano / NANO_TO_MILLISECOND;
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
    info.NTP_SERVER = jsonValue["ntpServer"].asString();
    info.lastUpdateTime = jsonValue["lastUpdateTime"].asInt64();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Read file %{public}s.", info.status.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Read file %{public}s.", info.NTP_SERVER.c_str());
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
    jsonValue["ntpServer"] = info.NTP_SERVER;
    jsonValue["lastUpdateTime"] = info.lastUpdateTime;
    Json::StreamWriterBuilder builder;
    const std::string json_file = Json::writeString(builder, jsonValue);
    ofs << json_file;
    ofs.close();
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}s.", info.status.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}s.", info.NTP_SERVER.c_str());
    TIME_HILOGD(TIME_MODULE_SERVICE, "Write file %{public}" PRId64 "", info.lastUpdateTime);
    return true;
}

void NtpUpdateTime::RegisterNtpServerListener()
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "register ntp server lister");
    if (SystemWatchParameter(NTP_SERVER_SYSTEM_PARAMETER.c_str(), ChangeNtpServerCallback, nullptr) != E_TIME_OK) {
        TIME_HILOGD(TIME_MODULE_SERVICE, "register ntp server lister fail");
    }
}

void NtpUpdateTime::ChangeNtpServerCallback(const char *key, const char *value, void *context)
{
    TIME_HILOGD(TIME_MODULE_SERVICE, "set time for ntp server changed");
    std::string ntpServer = system::GetParameter(NTP_SERVER_SYSTEM_PARAMETER.c_str(), "ntp.aliyun.com");
    if (ntpServer.empty()) {
        TIME_HILOGW(TIME_MODULE_SERVICE, "No found ntp server from system parameter.");
        return;
    }
    if (!GetAutoTimeInfoFromFile(autoTimeInfo_)) {
        autoTimeInfo_.lastUpdateTime = INVALID_TIMES;
        autoTimeInfo_.status = NETWORK_TIME_STATUS_ON;
    }
    autoTimeInfo_.NTP_SERVER = ntpServer;
    if (!SaveAutoTimeInfoToFile(autoTimeInfo_)) {
        TIME_HILOGE(TIME_MODULE_SERVICE, "end, SaveAutoTimeInfoToFile failed.");
        return;
    }
    SetSystemTime();
}
} // namespace MiscServices
} // namespace OHOS