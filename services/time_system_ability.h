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

#ifndef SERVICES_INCLUDE_TIME_SERVICES_H
#define SERVICES_INCLUDE_TIME_SERVICES_H

#include <cinttypes>
#include <mutex>

#include "ctime"
#include "event_handler.h"
#include "securec.h"
#include "system_ability.h"
#include "time_cmd_dispatcher.h"
#include "time_cmd_parse.h"
#include "time_service_notify.h"
#include "time_service_stub.h"
#include "time_sysevent.h"
#include "timer_manager.h"

namespace OHOS {
namespace MiscServices {
enum class ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class TimeSystemAbility : public SystemAbility, public TimeServiceStub {
    DECLARE_SYSTEM_ABILITY(TimeService);
public:
    DISALLOW_COPY_AND_MOVE(TimeSystemAbility);
    TimeSystemAbility(int32_t systemAbilityId, bool runOnCreate);
    TimeSystemAbility();
    ~TimeSystemAbility();
    static sptr<TimeSystemAbility> GetInstance();
    int32_t SetTime(int64_t time, APIVersion apiVersion = APIVersion::API_VERSION_7) override;
    bool SetRealTime(int64_t time);
    int32_t SetTimeZone(const std::string &timeZoneId, APIVersion apiVersion = APIVersion::API_VERSION_7) override;
    int32_t GetTimeZone(std::string &timeZoneId) override;
    int32_t GetWallTimeMs(int64_t &times) override;
    int32_t GetWallTimeNs(int64_t &times) override;
    int32_t GetBootTimeMs(int64_t &times) override;
    int32_t GetBootTimeNs(int64_t &times) override;
    int32_t GetMonotonicTimeMs(int64_t &times) override;
    int32_t GetMonotonicTimeNs(int64_t &times) override;
    int32_t GetThreadTimeMs(int64_t &times) override;
    int32_t GetThreadTimeNs(int64_t &times) override;

    int32_t CreateTimer(const std::shared_ptr<ITimerInfo> &timerOptions, sptr<IRemoteObject> &obj,
        uint64_t &timerId) override;
    int32_t CreateTimer(TimerPara &paras, std::function<void(const uint64_t)> Callback, uint64_t &timerId);
    int32_t StartTimer(uint64_t timerId, uint64_t triggerTimes) override;
    int32_t StopTimer(uint64_t timerId) override;
    int32_t DestroyTimer(uint64_t timerId) override;
    bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger) override;
    bool ResetAllProxy() override;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    void DumpAllTimeInfo(int fd, const std::vector<std::string> &input);
    void DumpTimerInfo(int fd, const std::vector<std::string> &input);
    void DumpTimerInfoById(int fd, const std::vector<std::string> &input);
    void DumpTimerTriggerById(int fd, const std::vector<std::string> &input);
    void InitDumpCmd();
    void RegisterSubscriber();

protected:
    void OnStart() override;
    void OnStop() override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    int32_t Init();
    void InitServiceHandler();
    void InitTimerHandler();
    void ParseTimerPara(std::shared_ptr<ITimerInfo> timerOptions, TimerPara &paras);
    bool GetTimeByClockid(clockid_t clockId, struct timespec &tv);
    int SetRtcTime(time_t sec);

    bool CheckRtc(const std::string &rtcPath, uint64_t rtcId);
    int GetWallClockRtcId();

    ServiceRunningState state_;
    static std::mutex instanceLock_;
    static sptr<TimeSystemAbility> instance_;
    const int rtcId;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static std::shared_ptr<TimerManager> timerManagerHandler_;
};
} // MiscServices
} // OHOS
#endif // SERVICES_INCLUDE_TIME_SERVICES_H