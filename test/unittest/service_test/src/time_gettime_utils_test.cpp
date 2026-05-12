/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <thread>
#include <vector>
#include <algorithm>
#include <atomic>

#include "time_gettime_utils.h"

using namespace OHOS::MiscServices::Time;
using namespace testing::ext;

namespace {
constexpr int64_t NANO_PER_MILLI = 1000000;
constexpr int64_t FIRST_RANDOM_MAX = 900000;
constexpr int64_t INCREMENT_MIN = 300;
constexpr int64_t INCREMENT_MAX = 500;
constexpr int64_t NO_INCREMENT_THRESHOLD = 990000;
} // namespace

class TimeGettimeUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: GetMonotoneWallTimeNs001
 * @tc.desc: 基本功能 — 返回正数纳秒时间戳
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs001, TestSize.Level0)
{
    int64_t ns = GetMonotoneWallTimeNs();
    EXPECT_GT(ns, 0);
}

/**
 * @tc.name: GetMonotoneWallTimeNs002
 * @tc.desc: 返回值纳秒部分在 [0, NANO_PER_MILLI - 1] 范围内
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs002, TestSize.Level0)
{
    int64_t ns = GetMonotoneWallTimeNs();
    int64_t fraction = ns % NANO_PER_MILLI;
    EXPECT_GE(fraction, 0);
    EXPECT_LT(fraction, NANO_PER_MILLI);
}

/**
 * @tc.name: GetMonotoneWallTimeNs003
 * @tc.desc: 同毫秒内连续调用严格递增
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs003, TestSize.Level0)
{
    constexpr int kSamples = 1000;
    std::vector<int64_t> samples;
    samples.reserve(kSamples);
    for (int i = 0; i < kSamples; i++) {
        samples.push_back(GetMonotoneWallTimeNs());
    }

    for (size_t i = 1; i < samples.size(); i++) {
        EXPECT_GT(samples[i], samples[i - 1])
            << "非严格递增，位置 " << i << ": prev=" << samples[i - 1] << ", cur=" << samples[i];
    }
}

/**
 * @tc.name: GetMonotoneWallTimeNs004
 * @tc.desc: 同毫秒递增幅度验证 — 初始阶段余数<990000 时增量 ∈ [300, 500]
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs004, TestSize.Level0)
{
    constexpr int kSamples = 200;
    std::vector<int64_t> samples;
    samples.reserve(kSamples);
    for (int i = 0; i < kSamples; i++) {
        samples.push_back(GetMonotoneWallTimeNs());
    }

    // 收集同毫秒内的递增增量
    std::vector<int64_t> increments;
    for (size_t i = 1; i < samples.size(); i++) {
        int64_t curMs = samples[i] / NANO_PER_MILLI;
        int64_t prevMs = samples[i - 1] / NANO_PER_MILLI;
        if (curMs == prevMs) {
            int64_t delta = samples[i] - samples[i - 1];
            int64_t prevFrac = samples[i - 1] % NANO_PER_MILLI;
            if (prevFrac < NO_INCREMENT_THRESHOLD) {
                increments.push_back(delta);
            }
        }
    }

    // 至少收集到一些增量样本
    ASSERT_GT(increments.size(), 0u) << "同毫秒采样不足，无法验证增量";

    for (int64_t delta : increments) {
        EXPECT_GE(delta, INCREMENT_MIN) << "增量 " << delta << " 小于最小值 " << INCREMENT_MIN;
        EXPECT_LE(delta, INCREMENT_MAX) << "增量 " << delta << " 大于最大值 " << INCREMENT_MAX;
    }
}

/**
 * @tc.name: GetMonotoneWallTimeNs005
 * @tc.desc: 跨毫秒切换时纳秒部分在 [1, FIRST_RANDOM_MAX] 范围内
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs005, TestSize.Level0)
{
    constexpr int kSamples = 1000;
    std::vector<int64_t> samples;
    samples.reserve(kSamples);
    for (int i = 0; i < kSamples; i++) {
        samples.push_back(GetMonotoneWallTimeNs());
    }

    // 收集跨毫秒切换时的第一个纳秒部分
    std::vector<int64_t> firstFractions;
    for (size_t i = 1; i < samples.size(); i++) {
        int64_t curMs = samples[i] / NANO_PER_MILLI;
        int64_t prevMs = samples[i - 1] / NANO_PER_MILLI;
        if (curMs != prevMs) {
            firstFractions.push_back(samples[i] % NANO_PER_MILLI);
        }
    }

    // 可能在同一毫秒内完成所有采样，但如果有跨毫秒就验证
    for (int64_t frac : firstFractions) {
        EXPECT_GE(frac, 1) << "跨毫秒纳秒部分不应为 0";
        EXPECT_LE(frac, FIRST_RANDOM_MAX)
            << "跨毫秒纳秒部分不应超过 " << FIRST_RANDOM_MAX;
    }
}

/**
 * @tc.name: GetMonotoneWallTimeNs006
 * @tc.desc: 跨毫秒纳秒部分随机化 — 多次跨毫秒调用出现不同纳秒值
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs006, TestSize.Level0)
{
    constexpr int kIterations = 10;
    std::vector<int64_t> fractions;
    fractions.reserve(kIterations);

    for (int i = 0; i < kIterations; i++) {
        fractions.push_back(GetMonotoneWallTimeNs() % NANO_PER_MILLI);
        // 等待以确保毫秒切换
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    // 可能有相同值（同毫秒），但至少出现 2 个不同的
    std::sort(fractions.begin(), fractions.end());
    int uniqueCount = static_cast<int>(
        std::unique(fractions.begin(), fractions.end()) - fractions.begin());
    EXPECT_GE(uniqueCount, 2) << "纳秒部分缺乏随机性，独特值仅 " << uniqueCount;
}

/**
 * @tc.name: GetMonotoneWallTimeNs007
 * @tc.desc: 多线程并发调用 — 无死锁，所有线程正常返回
 * @tc.type: FUNC
 */
HWTEST_F(TimeGettimeUtilsTest, GetMonotoneWallTimeNs007, TestSize.Level0)
{
    constexpr int kThreads = 4;
    constexpr int kCallsPerThread = 200;
    std::atomic<int> successCount{0};

    auto worker = [&successCount]() {
        for (int i = 0; i < kCallsPerThread; i++) {
            int64_t ns = GetMonotoneWallTimeNs();
            if (ns > 0) {
                successCount.fetch_add(1, std::memory_order_relaxed);
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (int i = 0; i < kThreads; i++) {
        threads.emplace_back(worker);
    }
    for (auto &t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), kThreads * kCallsPerThread);
}
