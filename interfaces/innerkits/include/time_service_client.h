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
#include "timer_call_back.h"

namespace OHOS {
namespace MiscServices {
class TimeServiceClient : public RefBase {
public:
    DISALLOW_COPY_AND_MOVE(TimeServiceClient);
    static sptr<TimeServiceClient> GetInstance();

    /**
     * SetTime
     * @description
     * @param milliseconds int64_t UTC time in milliseconds.
     * @return bool true on success, false on failure.
     */
    bool SetTime(const int64_t milliseconds);

    /**
     * SetTime
     * @description
     * @param milliseconds int64_t UTC time in milliseconds.
     * @param code error code return.
     * @return bool true on success, false on failure.
     */
    bool SetTime(const int64_t milliseconds, int32_t &code);

    /**
     * SetTimeZone
     * @description
     * @param timeZoneId const std::string time zone. example: "Beijing, China".
     * @return bool true on success, false on failure.
     */
    bool SetTimeZone(const std::string timeZoneId);

    /**
     * SetTimeZone
     * @description
     * @param timeZoneId const std::string time zone. example: "Beijing, China".
     * @param code error code return.
     * @return bool true on success, false on failure.
     */
    bool SetTimeZone(const std::string timezoneId, int32_t &code);

    /**
     * GetTimeZone
     * @description
     * @return std::string, time zone example: "Beijing, China", if result length == 0 on failed.
     */
    std::string GetTimeZone();
    /**
     * GetWallTimeMs
     * @description get the wall time(the UTC time from 1970 0H:0M:0S) in milliseconds
     * @return int64_t, milliseconds in wall time, ret < 0 on failed.
     */
    int64_t GetWallTimeMs();

    /**
     * GetWallTimeNs
     * @description get the wall time(the UTC time from 1970 0H:0M:0S) in nanoseconds
     * @return int64_t, nanoseconds in wall time, ret < 0 on failed.
     */
    int64_t GetWallTimeNs();

    /**
     * GetBootTimeMs
     * @description get the time since boot(include time spent in sleep) in milliseconds.
     * @return int64_t, milliseconds in boot time, ret < 0 on failed.
     */
    int64_t GetBootTimeMs();

    /**
     * GetBootTimeNs
     * @description // get the time since boot(include time spent in sleep) in nanoseconds.
     * @return int64_t, nanoseconds in boot time, ret < 0 on failed.
     */
    int64_t GetBootTimeNs();

    /**
     * GetMonotonicTimeMs
     * @description get the time since boot(exclude time spent in sleep) in milliseconds.
     * @return int64_t, milliseconds in Monotonic time, ret < 0 on failed.
     */
    int64_t GetMonotonicTimeMs();

    /**
     * GetMonotonicTimeNs
     * @description get the time since boot(exclude time spent in sleep) in nanoseconds.
     * @return int64_t, nanoseconds in Monotonic time, ret < 0 on failed.
     */
    int64_t GetMonotonicTimeNs();

    /**
     * GetThreadTimeMs
     * @description get the Thread-specific CPU-time in milliseconds.
     * @return int64_t, milliseconds in Thread-specific CPU-time, ret < 0 on failed.
     */
    int64_t GetThreadTimeMs();

    /**
     * GetThreadTimeNs
     * @description get the Thread-specific CPU-time in nanoseconds.
     * @return int64_t, nanoseconds in Thread-specific CPU-time, ret < 0 on failed.
     */
    int64_t GetThreadTimeNs();

    /**
     * CreateTimer
     * @param TimerInfo  timer info
     * @return uint64_t > 0 on success, == 0 failure.
     */
    uint64_t CreateTimer(std::shared_ptr<ITimerInfo> TimerInfo);
    int32_t CreateTimerV9(std::shared_ptr<ITimerInfo> timerOptions, uint64_t &timerId);

    /**
    * StartTimer
    * @param timerId indicate timerId
    * @param triggerTime  trigger times
    * @return bool true on success, false on failure.
    */
    bool StartTimer(uint64_t timerId, uint64_t triggerTime);
    int32_t StartTimerV9(uint64_t timerId, uint64_t triggerTime);

    /**
    * StopTimer
    * @param timerId indicate timerId
    * @return bool true on success, false on failure.
    */
    bool StopTimer(uint64_t timerId);
    int32_t StopTimerV9(uint64_t timerId);

    /**
    * DestroyTimer
    * @param timerId indicate timerId
    * @return bool true on success, false on failure.
    */
    bool DestroyTimer(uint64_t timerId);
    int32_t DestroyTimerV9(uint64_t timerId);

    /**
    * NetworkTimeStatusOff
    * @return void.
    */
    void NetworkTimeStatusOff();

    /**
    * NetworkTimeStatusOn
    * @return void.
    */
    void NetworkTimeStatusOn();

    /**
     * ProxyTimer
     * @param uid the uid
     * @param isProxy true if set proxy, false if remove proxy.
     * @param needRetrigger true if need retrigger, false if not.
     * @return bool true on success, false on failure.
     */
    bool ProxyTimer(int32_t uid, bool isProxy, bool needRetrigger);

    /**
     * ResetAllProxy
     * @return bool true on success, false on failure.
     */
    bool ResetAllProxy();
    bool ConnectService();

private:
    TimeServiceClient();
    ~TimeServiceClient();
    sptr<ITimeService> GetProxy();
    void SetProxy(sptr<ITimeService> proxy);

    static std::mutex instanceLock_;
    static sptr<TimeServiceClient> instance_;
    std::mutex proxyLock_;
    sptr<ITimeService> timeServiceProxy_;
};
} // MiscServices
} // OHOS
#endif // SERVICES_INCLUDE_TIME_SERVICES_MANAGER_H