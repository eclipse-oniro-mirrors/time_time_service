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

#include <mutex>
#include <inttypes.h>

#include "time_service_stub.h"
#include "time_service_notify.h"
#include "timer_manager.h"
#include "system_ability.h"
#include "event_handler.h"
#include "time.h"
#include "securec.h"
#include "time_cmd_dispatcher.h"
#include "time_cmd_parse.h"
#include "time_sysevent.h"

namespace OHOS {
namespace MiscServices {
enum class ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

class TimeService : public SystemAbility, public TimeServiceStub {
    DECLARE_SYSTEM_ABILITY(TimeService);
public:
    DISALLOW_COPY_AND_MOVE(TimeService);
    TimeService(int32_t systemAbilityId, bool runOnCreate);
    TimeService();
    ~TimeService();
    static sptr<TimeService> GetInstance();
    int32_t SetTime(const int64_t time) override;
    bool SetRealTime(const int64_t time);
    int32_t SetTimeZone(const std::string timezoneId) override;
    int32_t GetTimeZone(std::string &timezoneId) override;
    int32_t GetWallTimeMs(int64_t &times) override;
    int32_t GetWallTimeNs(int64_t &times) override;
    int32_t GetBootTimeMs(int64_t &times) override;
    int32_t GetBootTimeNs(int64_t &times) override;
    int32_t GetMonotonicTimeMs(int64_t &times) override;
    int32_t GetMonotonicTimeNs(int64_t &times) override;
    int32_t GetThreadTimeMs(int64_t &times) override;
    int32_t GetThreadTimeNs(int64_t &times) override;

    uint64_t CreateTimer(int32_t type, bool repeat, uint64_t interval,
        std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent,
        sptr<IRemoteObject> &timerCallback) override;
    uint64_t CreateTimer(int32_t type, uint64_t windowLength, uint64_t interval, int flag,
        std::function<void (const uint64_t)> Callback);
    bool StartTimer(uint64_t timerId, uint64_t triggerTime) override;
    bool StopTimer(uint64_t  timerId) override;
    bool DestroyTimer(uint64_t  timerId) override;
    void NetworkTimeStatusOff() override;
    void NetworkTimeStatusOn() override;
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
    struct TimerPara {
        int timerType;
        int64_t windowLength;
        uint64_t interval;
        int flag;
    };
    int32_t Init();
    void InitServiceHandler();
    void InitNotifyHandler();
    void InitTimeZone();
    void InitTimerHandler();
    void PaserTimerPara(int32_t type, bool repeat, uint64_t interval, TimerPara &paras);
    bool GetTimeByClockid(clockid_t clockID, struct timespec &tv);
    int set_rtc_time(time_t sec);

    bool check_rtc(std::string rtc_path, uint64_t rtc_id);
    int get_wall_clock_rtc_id();

    ServiceRunningState state_;
    static std::mutex instanceLock_;
    static sptr<TimeService> instance_;
    const int rtc_id;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static std::shared_ptr<TimerManager> timerManagerHandler_;
};
} // MiscServices
} // OHOS
#endif // SERVICES_INCLUDE_TIME_SERVICES_H
