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

// @ts-nocheck
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import systemTime from '@ohos.systemTime'

describe('SystemTimeGetTest', function () {
    const MILLI_TO_BASE = 1000;
    const NANO_TO_BASE = 1000000000;
    const NANO_TO_MILLI = NANO_TO_BASE / MILLI_TO_BASE;

    /**
     * @tc.number: TestGetCurrentTimeMs001
     * @tc.name: TestGetCurrentTimeMs001
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds using Promise
     * @tc.precon: SystemTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference using Date.getTime()
     *           2. Call getCurrentTime API using Promise (default milliseconds)
     *           3. Verify returned time is number type and not less than reference time
     * @tc.expect: getCurrentTime returns valid millisecond timestamp greater than or equal to reference time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeMs001', 0, async function (done) {
        console.log("testGetCurrentTimeMs001 start");
        const nowTime = new Date().getTime();
        const milliTime = await systemTime.getCurrentTime();
        console.log('Get current time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime >= nowTime).assertTrue();
        console.log('testGetCurrentTimeMs001 end');
        done();
    })

    /**
     * @tc.number: TestGetCurrentTimeMs002
     * @tc.name: TestGetCurrentTimeMs002
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds using Callback
     * @tc.precon: SystemTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference using Date.getTime()
     *           2. Call getCurrentTime API using Callback (default milliseconds)
     *           3. Verify returned time is number type and not less than reference time
     * @tc.expect: getCurrentTime callback returns valid millisecond timestamp greater than or equal to reference time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeMs002', 0, async function (done) {
        console.log("testGetCurrentTimeMs002 start");
        const nowTime = new Date().getTime();
        systemTime.getCurrentTime((err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'number' && data >= nowTime).assertTrue();
            done();
        })
        console.log('testGetCurrentTimeMs002 end');
    })

    /**
     * @tc.number: TestGetCurrentTimeMs003
     * @tc.name: TestGetCurrentTimeMs003
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds with explicit isNano=false using Promise
     * @tc.precon: SystemTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference using Date.getTime()
     *           2. Call getCurrentTime API with isNano=false using Promise
     *           3. Verify returned time is number type and not less than reference time
     * @tc.expect: getCurrentTime returns valid millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeMs003', 0, async function (done) {
        console.log("testGetCurrentTimeMs003 start");
        const nowTime = new Date().getTime();
        const milliTime = await systemTime.getCurrentTime(false);
        console.log('Get current time is ' + milliTime);
        expect(milliTime >= nowTime && typeof (milliTime) === 'number').assertTrue();
        console.log('testGetCurrentTimeMs003 end');
        done();
    })

    /**
     * @tc.number: TestGetCurrentTimeMs004
     * @tc.name: TestGetCurrentTimeMs004
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds with explicit isNano=false using Callback
     * @tc.precon: SystemTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference using Date.getTime()
     *           2. Call getCurrentTime API with isNano=false using Callback
     *           3. Verify returned time is number type and not less than reference time
     * @tc.expect: getCurrentTime callback returns valid millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeMs004', 0, async function (done) {
        console.log("testGetCurrentTimeMs004 start");
        const nowTime = new Date().getTime();
        systemTime.getCurrentTime(false, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'number' && data >= nowTime).assertTrue();
            done();
        });
        console.log('testGetCurrentTimeMs004 end');
    })

    /**
     * @tc.number: TestGetCurrentTimeNs001
     * @tc.name: TestGetCurrentTimeNs001
     * @tc.desc: Test getCurrentTime API returns current time in nanoseconds with isNano=true using Promise
     * @tc.precon: SystemTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference using Date.getTime()
     *           2. Call getCurrentTime API with isNano=true using Promise
     *           3. Convert nanoseconds to milliseconds and verify not less than reference time
     * @tc.expect: getCurrentTime returns valid nanosecond timestamp that converts to correct millisecond value
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeNs001', 0, async function (done) {
        console.log("testGetCurrentTimeNs001 start");
        const nowTime = new Date().getTime();
        const nanoTime = await systemTime.getCurrentTime(true);
        console.log('Get current nano time is ' + nanoTime);
        const milliTime = nanoTime / NANO_TO_MILLI;
        expect(milliTime >= nowTime).assertTrue();
        console.log('testGetCurrentTimeNs001 end');
        done();
    })

    /**
     * @tc.number: TestGetCurrentTimeNs002
     * @tc.name: TestGetCurrentTimeNs002
     * @tc.desc: Test getCurrentTime API returns current time in nanoseconds with isNano=true using Callback
     * @tc.precon: SystemTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference using Date.getTime()
     *           2. Call getCurrentTime API with isNano=true using Callback
     *           3. Convert nanoseconds to milliseconds and verify not less than reference time
     * @tc.expect: getCurrentTime callback returns valid nanosecond timestamp that converts to correct millisecond value
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeNs002', 0, async function (done) {
        console.log("testGetCurrentTimeNs002 start");
        const nowTime = new Date().getTime();
        systemTime.getCurrentTime(true, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect((data / NANO_TO_MILLI) >= nowTime).assertTrue();
            done();
        })
        console.log('testGetCurrentTimeNs002 end');
    })

    /**
     * @tc.number: TestGetRealActiveTimeMs001
     * @tc.name: TestGetRealActiveTimeMs001
     * @tc.desc: Test getRealActiveTime API returns active time in milliseconds using Promise
     * @tc.precon: SystemTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API using Promise (default milliseconds)
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealActiveTime returns valid positive millisecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeMs001', 0, async function (done) {
        console.log("testGetRealActiveTimeMs001 start");
        const milliTime = await systemTime.getRealActiveTime();
        console.log('Get real active time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeMs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealActiveTimeMs002
     * @tc.name: TestGetRealActiveTimeMs002
     * @tc.desc: Test getRealActiveTime API returns active time in milliseconds using Callback
     * @tc.precon: SystemTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API using Callback (default milliseconds)
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealActiveTime callback returns valid positive millisecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeMs002', 0, async function (done) {
        console.log("testGetRealActiveTimeMs002 start");
        systemTime.getRealActiveTime((err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'number' && (data / MILLI_TO_BASE) > 0).assertTrue();
            done();
        })
        console.log('testGetRealActiveTimeMs002 end');
    })

    /**
     * @tc.number: TestGetRealActiveTimeMs003
     * @tc.name: TestGetRealActiveTimeMs003
     * @tc.desc: Test getRealActiveTime API returns active time in milliseconds with explicit isNano=false using Promise
     * @tc.precon: SystemTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=false using Promise
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealActiveTime returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeMs003', 0, async function (done) {
        console.log("testGetRealActiveTimeMs003 start");
        const milliTime = await systemTime.getRealActiveTime(false);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeMs003 end');
        done();
    })

    /**
     * @tc.number: TestGetRealActiveTimeMs004
     * @tc.name: TestGetRealActiveTimeMs004
     * @tc.desc: Test getRealActiveTime API returns active time in milliseconds with explicit isNano=false using Callback
     * @tc.precon: SystemTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=false using Callback
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealActiveTime callback returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeMs004', 0, async function (done) {
        console.log("testGetRealActiveTimeMs004 start");
        systemTime.getRealActiveTime(false, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'number' && (data / MILLI_TO_BASE) > 0).assertTrue();
            done();
        })
        console.log('testGetRealActiveTimeMs004 end');
    })

    /**
     * @tc.number: TestGetRealActiveTimeNs001
     * @tc.name: TestGetRealActiveTimeNs001
     * @tc.desc: Test getRealActiveTime API returns active time in nanoseconds with isNano=true using Promise
     * @tc.precon: SystemTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=true using Promise
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealActiveTime returns valid positive nanosecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeNs001', 0, async function (done) {
        console.log("testGetRealActiveTimeNs001 start");
        const nanoTime = await systemTime.getRealActiveTime(true);
        console.log('Get real active nano time is ' + nanoTime);
        expect(nanoTime / NANO_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeNs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealActiveTimeNs002
     * @tc.name: TestGetRealActiveTimeNs002
     * @tc.desc: Test getRealActiveTime API returns active time in nanoseconds with isNano=true using Callback
     * @tc.precon: SystemTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=true using Callback
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealActiveTime callback returns valid positive nanosecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeNs002', 0, async function (done) {
        console.log("testGetRealActiveTimeNs002 start");
        systemTime.getRealActiveTime(true, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect((data / MILLI_TO_BASE) > 0).assertTrue();
            done();
        })
        console.log('testGetRealActiveTimeNs002 end');
    })

    /**
     * @tc.number: TestGetRealTimeMs001
     * @tc.name: TestGetRealTimeMs001
     * @tc.desc: Test getRealTime API returns real time in milliseconds using Promise
     * @tc.precon: SystemTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API using Promise (default milliseconds)
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealTime returns valid positive millisecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeMs001', 0, async function (done) {
        console.log("testGetRealTimeMs001 start");
        const milliTime = await systemTime.getRealTime();
        console.log('Get real time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE >= 0).assertTrue();
        console.log('testGetRealTimeMs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealTimeMs002
     * @tc.name: TestGetRealTimeMs002
     * @tc.desc: Test getRealTime API returns real time in milliseconds using Callback
     * @tc.precon: SystemTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API using Callback (default milliseconds)
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealTime callback returns valid positive millisecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeMs002', 0, async function (done) {
        console.log("testGetRealTimeMs002 start");
        systemTime.getRealTime((err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'number' && (data / MILLI_TO_BASE) > 0).assertTrue();
            done();
        })
        console.log('testGetRealTimeMs002 end');
    })

    /**
     * @tc.number: TestGetRealTimeMs003
     * @tc.name: TestGetRealTimeMs003
     * @tc.desc: Test getRealTime API returns real time in milliseconds with explicit isNano=false using Promise
     * @tc.precon: SystemTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=false using Promise
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealTime returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeMs003', 0, async function (done) {
        console.log("testGetRealTimeMs003 start");
        const milliTime = await systemTime.getRealTime(false);
        console.log('Get real time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealTimeMs003 end');
        done();
    })

    /**
     * @tc.number: TestGetRealTimeMs004
     * @tc.name: TestGetRealTimeMs004
     * @tc.desc: Test getRealTime API returns real time in milliseconds with explicit isNano=false using Callback
     * @tc.precon: SystemTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=false using Callback
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealTime callback returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeMs004', 0, async function (done) {
        console.log("testGetRealTimeMs004 start");
        systemTime.getRealTime(false, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'number' && (data / MILLI_TO_BASE) > 0).assertTrue();
            done();
        })
        console.log('testGetRealTimeMs004 end');
    })

    /**
     * @tc.number: TestGetRealTimeNs001
     * @tc.name: TestGetRealTimeNs001
     * @tc.desc: Test getRealTime API returns real time in nanoseconds with isNano=true using Promise
     * @tc.precon: SystemTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=true using Promise
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealTime returns valid positive nanosecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeNs001', 0, async function (done) {
        console.log("testGetRealTimeNs001 start");
        const nanoTime = await systemTime.getRealTime(true);
        console.log('Get real nano time is ' + nanoTime);
        expect(nanoTime / NANO_TO_BASE > 0).assertTrue();
        console.log('testGetRealTimeNs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealTimeNs002
     * @tc.name: TestGetRealTimeNs002
     * @tc.desc: Test getRealTime API returns real time in nanoseconds with isNano=true using Callback
     * @tc.precon: SystemTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=true using Callback
     *           2. Verify returned time is positive number and correct type
     * @tc.expect: getRealTime callback returns valid positive nanosecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeNs002', 0, async function (done) {
        console.log("testGetRealTimeNs002 start");
        systemTime.getRealTime(true, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect((data / MILLI_TO_BASE) > 0).assertTrue();
            done();
        })
        console.log('testGetRealTimeNs002 end');
    })

    /**
     * @tc.number: TestGetDate001
     * @tc.name: TestGetDate001
     * @tc.desc: Test getDate API returns current date using Promise after setting specific date
     * @tc.precon: SystemTime service is available and date setting permission is granted
     * @tc.step: 1. Set specific date (2022-02-01) using setDate API
     *           2. Call getDate API using Promise to retrieve current date
     *           3. Verify returned date matches the set date
     * @tc.expect: getDate returns correct Date object matching the previously set date
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetDate001', 0, async function (done) {
        console.log("testGetDate001 start");
        let date = new Date(2022, 1, 1);
        await systemTime.setDate(date);
        const currentDate = await systemTime.getDate();
        expect(currentDate instanceof Date && currentDate.toDateString() === date.toDateString()).assertTrue();
        done();
        console.log('testGetDate001 end');
    })

    /**
     * @tc.number: TestGetDate002
     * @tc.name: TestGetDate002
     * @tc.desc: Test getDate API returns current date using Callback after setting specific date
     * @tc.precon: SystemTime service is available and date setting permission is granted
     * @tc.step: 1. Set specific date (2022-02-01) using setDate API
     *           2. Call getDate API using Callback to retrieve current date
     *           3. Verify returned date matches the set date
     * @tc.expect: getDate callback returns correct Date object matching the previously set date
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetDate002', 0, async function (done) {
        console.log("testGetDate002 start");
        let date = new Date(2022, 1, 1);
        await systemTime.setDate(date);
        systemTime.getDate((err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(data instanceof Date && data.toDateString() === date.toDateString()).assertTrue();
            done();
        })
        console.log('testGetDate002 end');
    })

    /**
     * @tc.number: TestGetCurrentTimeInvalidParam001
     * @tc.name: TestGetCurrentTimeInvalidParam001
     * @tc.desc: Test getCurrentTime API handles string parameter "true" correctly using Promise
     * @tc.precon: SystemTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getCurrentTime API with string parameter "true" using Promise
     *           2. Verify the API handles the string parameter without throwing exception
     * @tc.expect: getCurrentTime should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeInvalidParam001', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam001 start");
        try {
            systemTime.getCurrentTime("true").then((time) => {
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testGetCurrentTimeInvalidParam001 end');
    })

    /**
     * @tc.number: TestGetCurrentTimeInvalidParam002
     * @tc.name: TestGetCurrentTimeInvalidParam002
     * @tc.desc: Test getCurrentTime API handles string parameter "true" correctly using Callback
     * @tc.precon: SystemTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getCurrentTime API with string parameter "true" using Callback
     *           2. Verify the API handles the string parameter without returning error
     * @tc.expect: getCurrentTime callback should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeInvalidParam002', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam002 start");
        try {
            systemTime.getCurrentTime("true", function (err) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testGetCurrentTimeInvalidParam002 end');
    })

    /**
     * @tc.number: TestGetRealActiveTimeInvalidParam001
     * @tc.name: TestGetRealActiveTimeInvalidParam001
     * @tc.desc: Test getRealActiveTime API handles string parameter "true" correctly using Promise
     * @tc.precon: SystemTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealActiveTime API with string parameter "true" using Promise
     *           2. Verify the API handles the string parameter without throwing exception
     * @tc.expect: getRealActiveTime should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeInvalidParam001', 0, async function (done) {
        console.log("testGetRealActiveTimeInvalidParam001 start");
        try {
            systemTime.getRealActiveTime("true").then((time) => {
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testGetRealActiveTimeInvalidParam001 end');
    })

    /**
     * @tc.number: TestGetRealActiveTimeInvalidParam002
     * @tc.name: TestGetRealActiveTimeInvalidParam002
     * @tc.desc: Test getRealActiveTime API handles string parameter "true" correctly using Callback
     * @tc.precon: SystemTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealActiveTime API with string parameter "true" using Callback
     *           2. Verify the API handles the string parameter without returning error
     * @tc.expect: getRealActiveTime callback should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeInvalidParam002', 0, async function (done) {
        console.log("testGetRealActiveTimeInvalidParam002 start");
        try {
            systemTime.getRealActiveTime("true", function (err) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testGetRealActiveTimeInvalidParam002 end');
    })

    /**
     * @tc.number: TestGetRealTimeInvalidParam001
     * @tc.name: TestGetRealTimeInvalidParam001
     * @tc.desc: Test getRealTime API handles string parameter "true" correctly using Promise
     * @tc.precon: SystemTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealTime API with string parameter "true" using Promise
     *           2. Verify the API handles the string parameter without throwing exception
     * @tc.expect: getRealTime should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeInvalidParam001', 0, async function (done) {
        console.log("testGetRealTimeInvalidParam001 start");
        try {
            systemTime.getRealTime("true").then((time) => {
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testGetRealTimeInvalidParam001 end');
    })

    /**
     * @tc.number: TestGetRealTimeInvalidParam002
     * @tc.name: TestGetRealTimeInvalidParam002
     * @tc.desc: Test getRealTime API handles string parameter "true" correctly using Callback
     * @tc.precon: SystemTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealTime API with string parameter "true" using Callback
     *           2. Verify the API handles the string parameter without returning error
     * @tc.expect: getRealTime callback should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeInvalidParam002', 0, async function (done) {
        console.log("testGetRealTimeInvalidParam002 start");
        try {
            systemTime.getRealTime("true", function (err) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(true).assertTrue();
                done();
            });
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testGetRealTimeInvalidParam002 end');
    })

    /**
     * @tc.number: TestGetTimezone001
     * @tc.name: TestGetTimezone001
     * @tc.desc: Test getTimezone API returns current timezone using Promise after setting specific timezone
     * @tc.precon: SystemTime service is available and timezone setting permission is granted
     * @tc.step: 1. Set specific timezone to "Pacific/Majuro"
     *           2. Call getTimezone API using Promise to retrieve current timezone
     *           3. Verify returned timezone matches the set timezone
     *           4. Restore timezone to "Asia/Shanghai"
     * @tc.expect: getTimezone returns correct timezone string matching the previously set timezone
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTimezone001', 0, async function (done) {
        console.log("testGetTimezone001 start");
        let timezone = "Pacific/Majuro";
        await systemTime.setTimezone(timezone);
        const currentTimezone = await systemTime.getTimezone();
        expect(typeof (currentTimezone) == 'string' && timezone === currentTimezone).assertTrue();
        await systemTime.setTimezone('Asia/Shanghai');
        done();
        console.log('testGetTimezone001 end');
    })

    /**
     * @tc.number: TestGetTimezone002
     * @tc.name: TestGetTimezone002
     * @tc.desc: Test getTimezone API returns current timezone using Callback after setting specific timezone
     * @tc.precon: SystemTime service is available and timezone setting permission is granted
     * @tc.step: 1. Set specific timezone to "Pacific/Majuro"
     *           2. Call getTimezone API using Callback to retrieve current timezone
     *           3. Verify returned timezone matches the set timezone
     *           4. Restore timezone to "Asia/Shanghai"
     * @tc.expect: getTimezone callback returns correct timezone string matching the previously set timezone
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTimezone002', 0, async function (done) {
        console.log("testGetTimezone002 start");
        let timezone = "Pacific/Majuro";
        await systemTime.setTimezone(timezone);
        systemTime.getTimezone((err, data) => {
            if (err) {
                expect(false).assertTrue();
                done();
            }
            expect(typeof(data) == 'string' && data === timezone).assertTrue();
            done();
            systemTime.setTimezone('Asia/Shanghai');
        })
        console.log('testGetTimezone002 end');
    })
})