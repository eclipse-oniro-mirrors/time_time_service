/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "time_fuzzer.h"

#include "securec.h"
#include <algorithm>
#include <chrono>
#include <climits>
#include <thread>

namespace OHOS {
namespace MiscServices {

namespace {
const size_t MIN_FUZZ_DATA_LEN = 2;
const size_t MAX_STRING_LEN = 256;
const size_t MAX_VECTOR_SIZE = 10;
const int64_t MIN_TIME_MS = 0;
const int64_t MAX_TIME_MS = 253402300799000LL; // 9999-12-31 23:59:59
const int32_t MAX_TIMER_TYPE = 4;
const int32_t MAX_THREADS = 5;
} // namespace

// ==================== 构造和析构 ====================
TimeFuzzer::TimeFuzzer()
{
    client_ = TimeServiceClient::GetInstance();
}

TimeFuzzer::~TimeFuzzer()
{
    // 清理所有创建的Timer
    for (auto timerId : createdTimers_) {
        if (client_ != nullptr) {
            client_->DestroyTimer(timerId);
        }
    }
    createdTimers_.clear();
}

// ==================== 主入口 ====================
void TimeFuzzer::FuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < MIN_FUZZ_DATA_LEN) {
        return;
    }

    if (client_ == nullptr) {
        return;
    }

    // 第一个字节作为操作码
    FuzzOperationType opType =
        static_cast<FuzzOperationType>(data[0] % static_cast<uint8_t>(FuzzOperationType::OP_MAX));

    switch (opType) {
        // Time API测试
        case FuzzOperationType::SET_TIME:
            FuzzSetTime(data + 1, size - 1);
            break;
        case FuzzOperationType::SET_TIME_V9:
            FuzzSetTimeV9(data + 1, size - 1);
            break;
        case FuzzOperationType::SET_AUTO_TIME:
            FuzzSetAutoTime(data + 1, size - 1);
            break;
        case FuzzOperationType::SET_TIMEZONE:
            FuzzSetTimeZone(data + 1, size - 1);
            break;
        case FuzzOperationType::SET_TIMEZONE_V9:
            FuzzSetTimeZoneV9(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_TIMEZONE:
            FuzzGetTimeZone(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_WALL_TIME_MS:
            FuzzGetWallTimeMs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_WALL_TIME_NS:
            FuzzGetWallTimeNs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_BOOT_TIME_MS:
            FuzzGetBootTimeMs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_BOOT_TIME_NS:
            FuzzGetBootTimeNs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_MONOTONIC_TIME_MS:
            FuzzGetMonotonicTimeMs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_MONOTONIC_TIME_NS:
            FuzzGetMonotonicTimeNs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_THREAD_TIME_MS:
            FuzzGetThreadTimeMs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_THREAD_TIME_NS:
            FuzzGetThreadTimeNs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_NTP_TIME_MS:
            FuzzGetNtpTimeMs(data + 1, size - 1);
            break;
        case FuzzOperationType::GET_REAL_TIME_MS:
            FuzzGetRealTimeMs(data + 1, size - 1);
            break;

        // Timer API测试
        case FuzzOperationType::CREATE_TIMER:
            FuzzCreateTimer(data + 1, size - 1);
            break;
        case FuzzOperationType::CREATE_TIMER_V9:
            FuzzCreateTimerV9(data + 1, size - 1);
            break;
        case FuzzOperationType::START_TIMER:
            FuzzStartTimer(data + 1, size - 1);
            break;
        case FuzzOperationType::START_TIMER_V9:
            FuzzStartTimerV9(data + 1, size - 1);
            break;
        case FuzzOperationType::STOP_TIMER:
            FuzzStopTimer(data + 1, size - 1);
            break;
        case FuzzOperationType::STOP_TIMER_V9:
            FuzzStopTimerV9(data + 1, size - 1);
            break;
        case FuzzOperationType::DESTROY_TIMER:
            FuzzDestroyTimer(data + 1, size - 1);
            break;
        case FuzzOperationType::DESTROY_TIMER_ASYNC:
            FuzzDestroyTimerAsync(data + 1, size - 1);
            break;
        case FuzzOperationType::PROXY_TIMER:
            FuzzProxyTimer(data + 1, size - 1);
            break;
        case FuzzOperationType::RESET_ALL_PROXY:
            FuzzResetAllProxy(data + 1, size - 1);
            break;
        case FuzzOperationType::ADJUST_TIMER:
            FuzzAdjustTimer(data + 1, size - 1);
            break;
        case FuzzOperationType::SET_TIMER_EXEMPTION:
            FuzzSetTimerExemption(data + 1, size - 1);
            break;
        case FuzzOperationType::SET_ADJUST_POLICY:
            FuzzSetAdjustPolicy(data + 1, size - 1);
            break;

        // 特殊场景测试
        case FuzzOperationType::BOUNDARY_TEST:
            FuzzBoundaryTest(data + 1, size - 1);
            break;
        case FuzzOperationType::CONCURRENT_TEST:
            FuzzConcurrentTest(data + 1, size - 1);
            break;
        case FuzzOperationType::COMBO_SCENARIO:
            FuzzComboScenario(data + 1, size - 1);
            break;
        case FuzzOperationType::TIMER_LIFECYCLE:
            FuzzTimerLifecycle(data + 1, size - 1);
            break;
        case FuzzOperationType::STRESS_TEST:
            FuzzStressTest(data + 1, size - 1);
            break;

        default:
            break;
    }
}

// ==================== 工具方法实现 ====================
bool TimeFuzzer::IsOffsetValid(size_t offset, size_t size, size_t needSize)
{
    return (offset + needSize <= size);
}

int64_t TimeFuzzer::ExtractInt64(const uint8_t* data, size_t& offset, size_t size)
{
    if (!IsOffsetValid(offset, size, sizeof(int64_t))) {
        return 0;
    }
    int64_t value;
    if (memcpy_s(&value, sizeof(int64_t), data + offset, sizeof(int64_t)) != EOK) {
        return 0;
    }
    offset += sizeof(int64_t);
    return value;
}

uint64_t TimeFuzzer::ExtractUint64(const uint8_t* data, size_t& offset, size_t size)
{
    if (!IsOffsetValid(offset, size, sizeof(uint64_t))) {
        return 0;
    }
    uint64_t value;
    if (memcpy_s(&value, sizeof(uint64_t), data + offset, sizeof(uint64_t)) != EOK) {
        return 0;
    }
    offset += sizeof(uint64_t);
    return value;
}

int32_t TimeFuzzer::ExtractInt32(const uint8_t* data, size_t& offset, size_t size)
{
    if (!IsOffsetValid(offset, size, sizeof(int32_t))) {
        return 0;
    }
    int32_t value;
    if (memcpy_s(&value, sizeof(int32_t), data + offset, sizeof(int32_t)) != EOK) {
        return 0;
    }
    offset += sizeof(int32_t);
    return value;
}

uint32_t TimeFuzzer::ExtractUint32(const uint8_t* data, size_t& offset, size_t size)
{
    if (!IsOffsetValid(offset, size, sizeof(uint32_t))) {
        return 0;
    }
    uint32_t value;
    if (memcpy_s(&value, sizeof(uint32_t), data + offset, sizeof(uint32_t)) != EOK) {
        return 0;
    }
    offset += sizeof(uint32_t);
    return value;
}

uint8_t TimeFuzzer::ExtractUint8(const uint8_t* data, size_t& offset, size_t size)
{
    if (!IsOffsetValid(offset, size, sizeof(uint8_t))) {
        return 0;
    }
    uint8_t value = data[offset];
    offset += sizeof(uint8_t);
    return value;
}

bool TimeFuzzer::ExtractBool(const uint8_t* data, size_t& offset, size_t size)
{
    if (!IsOffsetValid(offset, size, sizeof(uint8_t))) {
        return false;
    }
    bool value = (data[offset] != 0);
    offset += sizeof(uint8_t);
    return value;
}

std::string TimeFuzzer::ExtractString(const uint8_t* data, size_t& offset, size_t size, size_t maxLen)
{
    if (!IsOffsetValid(offset, size, sizeof(uint8_t))) {
        return "";
    }

    size_t strLen = ExtractUint8(data, offset, size);
    strLen = std::min(strLen, maxLen);
    strLen = std::min(strLen, size - offset);

    if (strLen == 0 || !IsOffsetValid(offset, size, strLen)) {
        return "";
    }

    std::string result(reinterpret_cast<const char*>(data + offset), strLen);
    offset += strLen;
    return result;
}

std::vector<int> TimeFuzzer::ExtractIntVector(const uint8_t* data, size_t& offset, size_t size)
{
    std::vector<int> result;
    if (!IsOffsetValid(offset, size, sizeof(uint8_t))) {
        return result;
    }

    size_t count = ExtractUint8(data, offset, size);
    count = std::min(count, MAX_VECTOR_SIZE);

    for (size_t i = 0; i < count && offset < size; ++i) {
        result.push_back(ExtractInt32(data, offset, size));
    }

    return result;
}

std::vector<std::string> TimeFuzzer::ExtractStringVector(const uint8_t* data, size_t& offset, size_t size)
{
    std::vector<std::string> result;
    if (!IsOffsetValid(offset, size, sizeof(uint8_t))) {
        return result;
    }

    size_t count = ExtractUint8(data, offset, size);
    count = std::min(count, MAX_VECTOR_SIZE);

    for (size_t i = 0; i < count && offset < size; ++i) {
        result.push_back(ExtractString(data, offset, size, MAX_STRING_LEN));
    }

    return result;
}

std::unordered_set<std::string> TimeFuzzer::ExtractStringSet(const uint8_t* data, size_t& offset, size_t size)
{
    std::unordered_set<std::string> result;
    if (!IsOffsetValid(offset, size, sizeof(uint8_t))) {
        return result;
    }

    size_t count = ExtractUint8(data, offset, size);
    count = std::min(count, MAX_VECTOR_SIZE);

    for (size_t i = 0; i < count && offset < size; ++i) {
        result.insert(ExtractString(data, offset, size, MAX_STRING_LEN));
    }

    return result;
}

// ==================== Time API Fuzz方法实现 ====================
void TimeFuzzer::FuzzSetTime(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    int64_t time = ExtractInt64(data, offset, size);

    client_->SetTime(time);
}

void TimeFuzzer::FuzzSetTimeV9(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    int64_t time = ExtractInt64(data, offset, size);

    client_->SetTimeV9(time);
}

void TimeFuzzer::FuzzSetAutoTime(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    bool autoTime = ExtractBool(data, offset, size);

    client_->SetAutoTime(autoTime);
}

void TimeFuzzer::FuzzSetTimeZone(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    std::string timeZoneId = ExtractString(data, offset, size, MAX_STRING_LEN);

    client_->SetTimeZone(timeZoneId);
}

void TimeFuzzer::FuzzSetTimeZoneV9(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    std::string timeZoneId = ExtractString(data, offset, size, MAX_STRING_LEN);

    client_->SetTimeZoneV9(timeZoneId);
}

void TimeFuzzer::FuzzGetTimeZone(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    std::string timeZone1 = client_->GetTimeZone();

    std::string timeZone2;
    client_->GetTimeZone(timeZone2);
}

void TimeFuzzer::FuzzGetWallTimeMs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetWallTimeMs();

    int64_t time2;
    client_->GetWallTimeMs(time2);
}

void TimeFuzzer::FuzzGetWallTimeNs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetWallTimeNs();

    int64_t time2;
    client_->GetWallTimeNs(time2);
}

void TimeFuzzer::FuzzGetBootTimeMs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetBootTimeMs();

    int64_t time2;
    client_->GetBootTimeMs(time2);
}

void TimeFuzzer::FuzzGetBootTimeNs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetBootTimeNs();

    int64_t time2;
    client_->GetBootTimeNs(time2);
}

void TimeFuzzer::FuzzGetMonotonicTimeMs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetMonotonicTimeMs();

    int64_t time2;
    client_->GetMonotonicTimeMs(time2);
}

void TimeFuzzer::FuzzGetMonotonicTimeNs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetMonotonicTimeNs();

    int64_t time2;
    client_->GetMonotonicTimeNs(time2);
}

void TimeFuzzer::FuzzGetThreadTimeMs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetThreadTimeMs();

    int64_t time2;
    client_->GetThreadTimeMs(time2);
}

void TimeFuzzer::FuzzGetThreadTimeNs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试两个重载版本
    (void)client_->GetThreadTimeNs();

    int64_t time2;
    client_->GetThreadTimeNs(time2);
}

void TimeFuzzer::FuzzGetNtpTimeMs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    int64_t time;
    client_->GetNtpTimeMs(time);
}

void TimeFuzzer::FuzzGetRealTimeMs(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    int64_t time;
    client_->GetRealTimeMs(time);
}

// ==================== Timer API Fuzz方法实现 ====================
void TimeFuzzer::FuzzCreateTimer(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;

    // 创建SimpleTimerInfo
    int timerType = ExtractInt32(data, offset, size) % MAX_TIMER_TYPE;
    bool repeat = ExtractBool(data, offset, size);
    uint64_t interval = ExtractUint64(data, offset, size);
    if (interval == 0) {
        interval = 1000; // 默认1秒
    }

    auto timerInfo = std::make_shared<SimpleTimerInfo>("FuzzTimer", timerType, repeat, false, false, interval, nullptr);
    if (timerInfo == nullptr) {
        return;
    }

    uint64_t timerId = client_->CreateTimer(timerInfo);
    if (timerId > 0) {
        createdTimers_.push_back(timerId);
    }
}

void TimeFuzzer::FuzzCreateTimerV9(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;

    // 创建SimpleTimerInfo
    int timerType = ExtractInt32(data, offset, size) % MAX_TIMER_TYPE;
    bool repeat = ExtractBool(data, offset, size);
    uint64_t interval = ExtractUint64(data, offset, size);
    if (interval == 0) {
        interval = 1000; // 默认1秒
    }

    auto timerInfo =
        std::make_shared<SimpleTimerInfo>("FuzzTimerV9", timerType, repeat, false, false, interval, nullptr);
    if (timerInfo == nullptr) {
        return;
    }

    uint64_t timerId = 0;
    int32_t ret = client_->CreateTimerV9(timerInfo, timerId);
    if (ret == 0 && timerId > 0) {
        createdTimers_.push_back(timerId);
    }
}

void TimeFuzzer::FuzzStartTimer(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint64_t timerId = ExtractUint64(data, offset, size);
    uint64_t triggerTime = ExtractUint64(data, offset, size);

    // 如果有已创建的Timer，使用它
    if (!createdTimers_.empty() && ExtractBool(data, offset, size)) {
        size_t index = ExtractUint8(data, offset, size) % createdTimers_.size();
        timerId = createdTimers_[index];
    }

    client_->StartTimer(timerId, triggerTime);
}

void TimeFuzzer::FuzzStartTimerV9(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint64_t timerId = ExtractUint64(data, offset, size);
    uint64_t triggerTime = ExtractUint64(data, offset, size);

    // 如果有已创建的Timer，使用它
    if (!createdTimers_.empty() && ExtractBool(data, offset, size)) {
        size_t index = ExtractUint8(data, offset, size) % createdTimers_.size();
        timerId = createdTimers_[index];
    }

    client_->StartTimerV9(timerId, triggerTime);
}

void TimeFuzzer::FuzzStopTimer(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint64_t timerId = ExtractUint64(data, offset, size);

    // 如果有已创建的Timer，使用它
    if (!createdTimers_.empty() && ExtractBool(data, offset, size)) {
        size_t index = ExtractUint8(data, offset, size) % createdTimers_.size();
        timerId = createdTimers_[index];
    }

    client_->StopTimer(timerId);
}

void TimeFuzzer::FuzzStopTimerV9(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint64_t timerId = ExtractUint64(data, offset, size);

    // 如果有已创建的Timer，使用它
    if (!createdTimers_.empty() && ExtractBool(data, offset, size)) {
        size_t index = ExtractUint8(data, offset, size) % createdTimers_.size();
        timerId = createdTimers_[index];
    }

    client_->StopTimerV9(timerId);
}

void TimeFuzzer::FuzzDestroyTimer(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint64_t timerId = ExtractUint64(data, offset, size);

    // 如果有已创建的Timer，使用它并从列表中移除
    if (!createdTimers_.empty() && ExtractBool(data, offset, size)) {
        size_t index = ExtractUint8(data, offset, size) % createdTimers_.size();
        timerId = createdTimers_[index];
        createdTimers_.erase(createdTimers_.begin() + index);
    }

    client_->DestroyTimer(timerId);
}

void TimeFuzzer::FuzzDestroyTimerAsync(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint64_t timerId = ExtractUint64(data, offset, size);

    // 如果有已创建的Timer，使用它并从列表中移除
    if (!createdTimers_.empty() && ExtractBool(data, offset, size)) {
        size_t index = ExtractUint8(data, offset, size) % createdTimers_.size();
        timerId = createdTimers_[index];
        createdTimers_.erase(createdTimers_.begin() + index);
    }

    client_->DestroyTimerAsync(timerId);
}

void TimeFuzzer::FuzzProxyTimer(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    int32_t uid = ExtractInt32(data, offset, size);
    std::vector<int> pidList = ExtractIntVector(data, offset, size);
    std::set<int> pidSet(pidList.begin(), pidList.end());
    bool isProxy = ExtractBool(data, offset, size);
    bool needRetrigger = ExtractBool(data, offset, size);

    client_->ProxyTimer(uid, pidSet, isProxy, needRetrigger);
}

void TimeFuzzer::FuzzResetAllProxy(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    client_->ResetAllProxy();
}

void TimeFuzzer::FuzzAdjustTimer(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    bool isAdjust = ExtractBool(data, offset, size);
    uint32_t interval = ExtractUint32(data, offset, size);
    uint32_t delta = ExtractUint32(data, offset, size);

    client_->AdjustTimer(isAdjust, interval, delta);
}

void TimeFuzzer::FuzzSetTimerExemption(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    std::unordered_set<std::string> nameArr = ExtractStringSet(data, offset, size);
    bool isExemption = ExtractBool(data, offset, size);

    client_->SetTimerExemption(nameArr, isExemption);
}

void TimeFuzzer::FuzzSetAdjustPolicy(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    std::unordered_map<std::string, uint32_t> policyMap;

    size_t count = ExtractUint8(data, offset, size);
    count = std::min(count, MAX_VECTOR_SIZE);

    for (size_t i = 0; i < count && offset < size; ++i) {
        std::string key = ExtractString(data, offset, size, MAX_STRING_LEN);
        uint32_t value = ExtractUint32(data, offset, size);
        if (!key.empty()) {
            policyMap[key] = value;
        }
    }

    client_->SetAdjustPolicy(policyMap);
}

// ==================== 特殊场景Fuzz方法实现 ====================
void TimeFuzzer::FuzzBoundaryTest(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    // 测试时间边界值
    std::vector<int64_t> timeValues = {
        INT64_MIN, INT64_MIN + 1, -1, 0, 1, MIN_TIME_MS, MAX_TIME_MS, INT64_MAX - 1, INT64_MAX};

    size_t offset = 0;
    uint8_t testCase = ExtractUint8(data, offset, size);
    int64_t testTime = timeValues[testCase % timeValues.size()];

    // 测试SetTime边界
    client_->SetTime(testTime);
    client_->SetTimeV9(testTime);

    // 测试时区边界
    std::vector<std::string> timezoneValues = {
        "", "X", "Asia/Shanghai", "America/New_York", std::string(MAX_STRING_LEN, 'A'), // 超长字符串
        "Invalid/TimeZone", "UTC+8",
        "\x00\x01\x02", // 特殊字符
    };

    for (const auto& tz : timezoneValues) {
        client_->SetTimeZone(tz);
        client_->SetTimeZoneV9(tz);
    }

    // 测试Timer ID边界
    std::vector<uint64_t> timerIds = {0, 1, UINT64_MAX - 1, UINT64_MAX};
    for (auto timerId : timerIds) {
        client_->StartTimer(timerId, 1000);
        client_->StopTimer(timerId);
        client_->DestroyTimer(timerId);
    }
}

void TimeFuzzer::FuzzConcurrentTest(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint8_t threadCount = ExtractUint8(data, offset, size);
    threadCount = (threadCount % MAX_THREADS) + 1; // 1-5个线程

    std::vector<std::thread> threads;

    for (uint8_t i = 0; i < threadCount && offset < size; ++i) {
        int64_t time = ExtractInt64(data, offset, size);
        std::string timezone = ExtractString(data, offset, size, MAX_STRING_LEN);

        threads.emplace_back([this, time, timezone]() {
            if (client_ != nullptr) {
                // 并发调用各种Time接口
                client_->GetWallTimeMs();
                client_->GetBootTimeMs();
                client_->GetMonotonicTimeMs();

                // 并发设置时间和时区（可能失败）
                client_->SetTime(time);
                client_->SetTimeZone(timezone);

                // 并发获取时区
                std::string tz = client_->GetTimeZone();
            }
        });
    }

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void TimeFuzzer::FuzzComboScenario(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;

    // 场景1: 完整的时间设置流程
    int64_t time = ExtractInt64(data, offset, size);
    std::string timezone = ExtractString(data, offset, size, MAX_STRING_LEN);

    client_->SetTime(time);
    client_->SetTimeZone(timezone);

    int64_t wallTime;
    client_->GetWallTimeMs(wallTime);

    std::string currentTz;
    client_->GetTimeZone(currentTz);

    // 场景2: 测试AutoTime开关
    bool autoTime = ExtractBool(data, offset, size);
    client_->SetAutoTime(autoTime);

    if (autoTime) {
        int64_t ntpTime;
        client_->GetNtpTimeMs(ntpTime);
        client_->GetRealTimeMs(ntpTime);
    }

    // 场景3: 获取各种时间类型
    int64_t bootTime, monotonicTime, threadTime;
    client_->GetBootTimeMs(bootTime);
    client_->GetMonotonicTimeMs(monotonicTime);
    client_->GetThreadTimeMs(threadTime);
}

void TimeFuzzer::FuzzTimerLifecycle(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;

    // 创建Timer
    int timerType = ExtractInt32(data, offset, size) % MAX_TIMER_TYPE;
    bool repeat = ExtractBool(data, offset, size);
    uint64_t interval = ExtractUint64(data, offset, size);
    if (interval == 0) {
        interval = 1000;
    }

    auto timerInfo =
        std::make_shared<SimpleTimerInfo>("FuzzTimerLifecycle", timerType, repeat, false, false, interval, nullptr);
    if (timerInfo == nullptr) {
        return;
    }

    uint64_t timerId = 0;
    int32_t ret = client_->CreateTimerV9(timerInfo, timerId);

    if (ret == 0 && timerId > 0) {
        // 启动Timer
        uint64_t triggerTime = ExtractUint64(data, offset, size);
        if (triggerTime == 0) {
            triggerTime = 1000;
        }
        client_->StartTimerV9(timerId, triggerTime);

        // 可选：停止Timer
        if (ExtractBool(data, offset, size)) {
            client_->StopTimerV9(timerId);
        }

        // 销毁Timer
        bool async = ExtractBool(data, offset, size);
        if (async) {
            client_->DestroyTimerAsync(timerId);
        } else {
            client_->DestroyTimer(timerId);
        }
    }
}

void TimeFuzzer::FuzzStressTest(const uint8_t* data, size_t size)
{
    if (client_ == nullptr) {
        return;
    }

    size_t offset = 0;
    uint8_t iterations = ExtractUint8(data, offset, size);
    iterations = (iterations % 10) + 1; // 1-10次迭代

    for (uint8_t i = 0; i < iterations && offset < size; ++i) {
        // 快速连续调用各种接口
        int64_t time = ExtractInt64(data, offset, size);
        client_->SetTime(time);
        client_->GetWallTimeMs();
        client_->GetBootTimeMs();
        client_->GetMonotonicTimeMs();

        // 快速创建和销毁Timer
        auto timerInfo = std::make_shared<SimpleTimerInfo>("FuzzStressTimer", 0, false, false, false, 1000, nullptr);
        if (timerInfo != nullptr) {
            uint64_t timerId = client_->CreateTimer(timerInfo);
            if (timerId > 0) {
                client_->StartTimer(timerId, 100);
                client_->StopTimer(timerId);
                client_->DestroyTimer(timerId);
            }
        }
    }
}

} // namespace MiscServices
} // namespace OHOS

// ==================== Fuzzer入口点 ====================
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    static OHOS::MiscServices::TimeFuzzer fuzzer;
    fuzzer.FuzzTest(data, size);

    return 0;
}
