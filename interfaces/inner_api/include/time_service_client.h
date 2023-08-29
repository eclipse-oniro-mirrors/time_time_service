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

#ifndef SERVICES_INCLUDE_TIME_SERVICES_MANAGER_H
#define SERVICES_INCLUDE_TIME_SERVICES_MANAGER_H

#include <mutex>

#include "refbase.h"
#include "time_service_interface.h"
#include "time_common.h"
#include "timer_call_back.h"

namespace OHOS {
namespace MiscServices {
class TimeServiceClient : public RefBase {
public:
    DISALLOW_COPY_AND_MOVE(TimeServiceClient);
    TIME_API static sptr<TimeServiceClient> GetInstance();

    /**
     * @brief Set time
     *
     * This api is used to set system time.
     *
     * @param UTC time in milliseconds.
     * @return true on success, false on failure.
     */
    TIME_API bool SetTime(int64_t milliseconds);

    /**
     * @brief Set system time
     *
     * This api is used to set system time.
     *
     * @param UTC time in milliseconds.
     * @param error code.
     * @return true on success, false on failure.
     */
    TIME_API bool SetTime(int64_t milliseconds, int32_t &code);

    /**
     * @brief Set system time
     *
     * This api is used to set system time.
     *
     * @param UTC time in milliseconds.
     * @return error code.
     */
    TIME_API int32_t SetTimeV9(int64_t time);

    /**
     * @brief Set Timezone
     *
     * This api is used to set timezone.
     *
     * @param const std::string time zone. example: "Beijing, China".
     * @return true on success, false on failure.
     */
    TIME_API bool SetTimeZone(const std::string &timeZoneId);

    /**
     * @brief Set Timezone
     *
     * This api is used to set timezone.
     *
     * @param const std::string time zone. example: "Beijing, China".
     * @param error code.
     * @return true on success, false on failure.
     */
    TIME_API bool SetTimeZone(const std::string &timezoneId, int32_t &code);

    /**
     * @brief Set Timezone
     *
     * This api is used to set timezone.
     *
     * @param const std::string time zone. example: "Beijing, China".
     * @return error code.
     */
    TIME_API int32_t SetTimeZoneV9(const std::string &timezoneId);

    /**
     * @brief Get Timezone
     *
     * This api is used to get current system timezone.
     *
     * @return time zone example: "Beijing, China", if result length == 0 on failed.
     */
    TIME_API std::string GetTimeZone();

    /**
     * @brief Get Timezone
     *
     * This api is used to get current system timezone.
     *
     * @param The current system time zone, example: "Beijing, China", if failed the value is nullptr.
     * @return error code.
     */
    TIME_API int32_t GetTimeZone(std::string &timezoneId);

    /**
     * @brief GetWallTimeMs
     *
     * Get the wall time(the UTC time from 1970 0H:0M:0S) in milliseconds
     *
     * @return milliseconds in wall time, ret < 0 on failed.
     */
    TIME_API int64_t GetWallTimeMs();

    /**
     * @brief GetWallTimeMs
     *
     * Get the wall time(the UTC time from 1970 0H:0M:0S) in milliseconds.
     *
     * @param milliseconds in wall time.
     * @return error code.
     */
    TIME_API int32_t GetWallTimeMs(int64_t &time);

    /**
     * @brief GetWallTimeNs
     *
     * Get the wall time(the UTC time from 1970 0H:0M:0S) in nanoseconds.
     *
     * @return nanoseconds in wall time, ret < 0 on failed.
     */
    TIME_API int64_t GetWallTimeNs();

    /**
     * @brief GetWallTimeNs
     *
     * Get the wall time(the UTC time from 1970 0H:0M:0S) in nanoseconds.
     *
     * @param nanoseconds in wall time.
     * @return error code.
     */
    TIME_API int32_t GetWallTimeNs(int64_t &time);

    /**
     * @brief GetBootTimeMs
     *
     * Get the time since boot(include time spent in sleep) in milliseconds.
     *
     * @return milliseconds in boot time, ret < 0 on failed.
     */
    TIME_API int64_t GetBootTimeMs();

    /**
     * @brief GetBootTimeMs
     *
     * Get the time since boot(include time spent in sleep) in milliseconds.
     *
     * @param milliseconds in boot time.
     * @param error code.
     */
    TIME_API int32_t GetBootTimeMs(int64_t &time);

    /**
     * @brief GetBootTimeNs
     *
     * Get the time since boot(include time spent in sleep) in nanoseconds.
     *
     * @return nanoseconds in boot time, ret < 0 on failed.
     */
    TIME_API int64_t GetBootTimeNs();

    /**
     * @brief GetBootTimeNs
     *
     * Get the time since boot(include time spent in sleep) in nanoseconds.
     *
     * @param nanoseconds in boot time.
     * @return error code.
     */
    TIME_API int32_t GetBootTimeNs(int64_t &time);

    /**
     * @brief GetMonotonicTimeMs
     *
     * Get the time since boot(exclude time spent in sleep) in milliseconds.
     *
     * @return milliseconds in Monotonic time, ret < 0 on failed.
     */
    TIME_API int64_t GetMonotonicTimeMs();

    /**
     * @brief GetMonotonicTimeMs
     *
     * Get the time since boot(exclude time spent in sleep) in milliseconds.
     *
     * @param milliseconds in Monotonic time.
     * @return error code.
     */
    TIME_API int32_t GetMonotonicTimeMs(int64_t &time);

    /**
     * @brief GetMonotonicTimeNs
     *
     * Get the time since boot(exclude time spent in sleep) in nanoseconds.
     *
     * @return nanoseconds in Monotonic time, ret < 0 on failed.
     */
    TIME_API int64_t GetMonotonicTimeNs();

    /**
     * @brief GetMonotonicTimeNs
     *
     * Get the time since boot(exclude time spent in sleep) in nanoseconds.
     *
     * @param nanoseconds in Monotonic time.
     * @return error code.
     */
    TIME_API int32_t GetMonotonicTimeNs(int64_t &time);

    /**
     * @brief GetThreadTimeMs
     *
     * Get the thread time in milliseconds.
     *
     * @return milliseconds in Thread-specific CPU-time, ret < 0 on failed.
     */
    TIME_API int64_t GetThreadTimeMs();

    /**
     * @brief GetThreadTimeMs
     *
     * Get the thread time in milliseconds.
     *
     * @param the Thread-specific CPU-time in milliseconds.
     * @return error code.
     */
    TIME_API int32_t GetThreadTimeMs(int64_t &time);

    /**
     * @brief GetThreadTimeNs
     *
     * Get the thread time in nanoseconds.
     *
     * @return nanoseconds in Thread-specific CPU-time, ret < 0 on failed.
     */
    TIME_API int64_t GetThreadTimeNs();

    /**
     * @brief GetThreadTimeNs
     *
     * Get the thread time in nanoseconds.
     *
     * @param get the Thread-specific CPU-time in nanoseconds.
     * @return error code.
     */
    TIME_API int32_t GetThreadTimeNs(int64_t &time);

    /**
     * @brief CreateTimer
     *
     * Creates a timer.
     *
     * @param indicates the timer options.
     * @return timer id.
     */
    TIME_API uint64_t CreateTimer(std::shared_ptr<ITimerInfo> timerInfo);

    /**
     * @brief Create Timer
     *
     * Creates a timer.
     *
     * @param indicates the timer options.
     * @param timer id.
     * @return error code.
     */
    TIME_API int32_t CreateTimerV9(std::shared_ptr<ITimerInfo> timerOptions, uint64_t &timerId);

    /**
     * @brief StartTimer
     *
     * Starts a timer.
     *
     * @param indicate timerId
     * @param trigger time
     * @return true on success, false on failure.
     */
    TIME_API bool StartTimer(uint64_t timerId, uint64_t triggerTime);

    /**
     * @brief Start Timer
     *
     * Starts a timer.
     *
     * @param indicate timerId.
     * @param trigger time.
     * @return true on success, false on failure.
     */
    TIME_API int32_t StartTimerV9(uint64_t timerId, uint64_t triggerTime);

    /**
     * @brief Stop Timer
     *
     * Starts a timer.
     *
     * @param indicate timerId.
     * @return true on success, false on failure.
     */
    TIME_API bool StopTimer(uint64_t timerId);

    /**
     * @brief StopTimer
     *
     * Stops a timer.
     *
     * @param indicate timerId.
     * @return error code.
     */
    TIME_API int32_t StopTimerV9(uint64_t timerId);

    /**
     * @brief DestroyTimer
     *
     * Destroy a timer.
     *
     * @param indicate timerId.
     * @return true on success, false on failure.
     */
    TIME_API bool DestroyTimer(uint64_t timerId);

    /**
     * @brief DestroyTimer
     *
     * Destroy a timer.
     *
     * @param indicate timerId.
     * @return error code.
     */
    TIME_API int32_t DestroyTimerV9(uint64_t timerId);

    /**
     * @brief ProxyTimer
     *
     * Wake up all timers for provided uid by proxy.
     *
     * @param uid the uid.
     * @param true if set proxy, false if remove proxy.
     * @param true if need retrigger, false if not.
     * @return true on success, false on failure.
     */
    TIME_API bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger);

    /**
     * @brief ResetAllProxy
     *
     * Wake up all timers by proxy.
     *
     * @return bool true on success, false on failure.
     */
    TIME_API bool ResetAllProxy();
private:
    class TimeSaDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        explicit TimeSaDeathRecipient(){};
        ~TimeSaDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject> &object) override
        {
            TIME_HILOGE(TIME_MODULE_CLIENT, "TimeSaDeathRecipient on remote systemAbility died.");
            TimeServiceClient::GetInstance()->ClearProxy();
            TimeServiceClient::GetInstance()->ConnectService();
        };

    private:
        DISALLOW_COPY_AND_MOVE(TimeSaDeathRecipient);
    };

    TimeServiceClient();
    ~TimeServiceClient();
    bool ConnectService();
    void ClearProxy();
    sptr<ITimeService> GetProxy();
    void SetProxy(sptr<ITimeService> proxy);

    static std::mutex instanceLock_;
    static sptr<TimeServiceClient> instance_;
    std::mutex proxyLock_;
    std::mutex deathLock_;
    sptr<ITimeService> timeServiceProxy_;
    sptr<TimeSaDeathRecipient> deathRecipient_ {};
};
} // MiscServices
} // OHOS
#endif // SERVICES_INCLUDE_TIME_SERVICES_MANAGER_H