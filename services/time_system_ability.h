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
#include <unordered_set>

#include "event_handler.h"
#include "securec.h"
#include "system_ability.h"
#include "ctime"
#include "time_cmd_dispatcher.h"
#include "time_cmd_parse.h"
#include "time_service_notify.h"
#include "time_service_stub.h"
#include "timer_manager.h"
#include "shutdown/sync_shutdown_callback_stub.h"
#include "shutdown/shutdown_client.h"
#include "rdb_helper.h"

namespace OHOS {
namespace MiscServices {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };

class TimeSystemAbility : public SystemAbility, public TimeServiceStub {
    DECLARE_SYSTEM_ABILITY(TimeSystemAbility);

public:
    class TimePowerStateListener : public OHOS::PowerMgr::SyncShutdownCallbackStub {
    public:
        ~TimePowerStateListener() override = default;
        void OnSyncShutdown() override;
    };
    DISALLOW_COPY_AND_MOVE(TimeSystemAbility);
    TimeSystemAbility(int32_t systemAbilityId, bool runOnCreate);
    TimeSystemAbility();
    ~TimeSystemAbility();
    static sptr<TimeSystemAbility> GetInstance();
    static std::shared_ptr<TimerManager> GetManagerHandler();
    int32_t SetTime(int64_t time, APIVersion apiVersion = APIVersion::API_VERSION_7) override;
    bool SetRealTime(int64_t time);
    int32_t SetTimeZone(const std::string &timeZoneId, APIVersion apiVersion = APIVersion::API_VERSION_7) override;
    int32_t GetTimeZone(std::string &timeZoneId) override;
    int32_t GetWallTimeMs(int64_t &time) override;
    int32_t GetWallTimeNs(int64_t &time) override;
    int32_t GetBootTimeMs(int64_t &time) override;
    int32_t GetBootTimeNs(int64_t &time) override;
    int32_t GetMonotonicTimeMs(int64_t &time) override;
    int32_t GetMonotonicTimeNs(int64_t &time) override;
    int32_t GetThreadTimeMs(int64_t &time) override;
    int32_t GetThreadTimeNs(int64_t &time) override;
    int32_t CreateTimer(const std::shared_ptr<ITimerInfo> &timerOptions, sptr<IRemoteObject> &obj,
        uint64_t &timerId) override;
    int32_t CreateTimer(TimerPara &paras, std::function<void(const uint64_t)> callback, uint64_t &timerId);
    int32_t StartTimer(uint64_t timerId, uint64_t triggerTime) override;
    int32_t StopTimer(uint64_t timerId) override;
    int32_t DestroyTimer(uint64_t timerId) override;
    bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger) override;
    bool ProxyTimer(std::set<int> pidList, bool isProxy, bool needRetrigger) override;
    int32_t AdjustTimer(bool isAdjust, uint32_t interval) override;
    int32_t SetTimerExemption(const std::unordered_set<std::string> &nameArr, bool isExemption) override;
    bool ResetAllProxy() override;
    int Dump(int fd, const std::vector<std::u16string> &args) override;
    void DumpAllTimeInfo(int fd, const std::vector<std::string> &input);
    void DumpTimerInfo(int fd, const std::vector<std::string> &input);
    void DumpTimerInfoById(int fd, const std::vector<std::string> &input);
    void DumpTimerTriggerById(int fd, const std::vector<std::string> &input);
    void DumpIdleTimerInfo(int fd, const std::vector<std::string> &input);
    void DumpProxyTimerInfo(int fd, const std::vector<std::string> &input);
    void DumpUidTimerMapInfo(int fd, const std::vector<std::string> &input);
    void DumpPidTimerMapInfo(int fd, const std::vector<std::string> &input);
    void SetProxyDelayTime(int fd, const std::vector<std::string> &input);
    void DumpProxyDelayTime(int fd, const std::vector<std::string> &input);
    void DumpAdjustTime(int fd, const std::vector<std::string> &input);
    void InitDumpCmd();
    void RegisterCommonEventSubscriber();
    bool RecoverTimer();

protected:
    void OnStart() override;
    void OnStop() override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;

private:
    class RSSSaDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit RSSSaDeathRecipient()= default;;
        ~RSSSaDeathRecipient() override = default;
        void OnRemoteDied(const wptr<IRemoteObject> &object) override;
    };

    int32_t Init();
    void InitServiceHandler();
    void InitTimerHandler();
    void ParseTimerPara(const std::shared_ptr<ITimerInfo> &timerOptions, TimerPara &paras);
    bool GetTimeByClockId(clockid_t clockId, struct timespec &tv);
    int SetRtcTime(time_t sec);
    bool CheckRtc(const std::string &rtcPath, uint64_t rtcId);
    int GetWallClockRtcId();
    void RegisterRSSDeathCallback();
    void RegisterPowerStateListener();
    void RegisterScreenOnSubscriber();
    void RegisterNitzTimeSubscriber();
    bool IsValidTime(int64_t time);
    void RecoverTimerInner(std::shared_ptr<OHOS::NativeRdb::ResultSet> resultSet);
    void SetAutoReboot();

    ServiceRunningState state_;
    static std::mutex instanceLock_;
    static sptr<TimeSystemAbility> instance_;
    const int rtcId;
    static std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static std::shared_ptr<TimerManager> timerManagerHandler_;
    sptr<RSSSaDeathRecipient> deathRecipient_ {};
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_TIME_SERVICES_H