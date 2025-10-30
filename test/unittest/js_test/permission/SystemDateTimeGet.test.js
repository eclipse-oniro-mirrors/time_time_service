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
import systemDateTime from '@ohos.systemDateTime'

describe('SystemDateTimeGetTest', function () {
    const MILLI_TO_BASE = 1000;
    const NANO_TO_BASE = 1000000000;
    const NANO_TO_MILLI = NANO_TO_BASE / MILLI_TO_BASE;

    /**
     * @tc.number: TestGetCurrentTimeMs001
     * @tc.name: TestGetCurrentTimeMs001
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds using Promise
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
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
        const milliTime = await systemDateTime.getCurrentTime();
        console.log('Get current time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime >= nowTime).assertTrue();
        console.log('testGetCurrentTimeMs001 end');
        done();
    })

    /**
     * @tc.number: TestGetCurrentTimeMs002
     * @tc.name: TestGetCurrentTimeMs002
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds using Callback
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
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
        systemDateTime.getCurrentTime((err, data) => {
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
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
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
        const milliTime = await systemDateTime.getCurrentTime(false);
        console.log('Get current time is ' + milliTime);
        expect(milliTime >= nowTime && typeof (milliTime) === 'number').assertTrue();
        console.log('testGetCurrentTimeMs003 end');
        done();
    })

    /**
     * @tc.number: TestGetCurrentTimeMs004
     * @tc.name: TestGetCurrentTimeMs004
     * @tc.desc: Test getCurrentTime API returns current time in milliseconds with explicit isNano=false using Callback
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
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
        systemDateTime.getCurrentTime(false, (err, data) => {
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
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
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
        const nanoTime = await systemDateTime.getCurrentTime(true);
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
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
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
        systemDateTime.getCurrentTime(true, (err, data) => {
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
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
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
        const milliTime = await systemDateTime.getRealActiveTime();
        console.log('Get real active time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeMs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealActiveTimeMs002
     * @tc.name: TestGetRealActiveTimeMs002
     * @tc.desc: Test getRealActiveTime API returns active time in milliseconds using Callback
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API using Callback (default milliseconds)
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealActiveTime callback returns valid positive millisecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealActiveTimeMs002', 0, async function (done) {
        console.log("testGetRealActiveTimeMs002 start");
        systemDateTime.getRealActiveTime((err, data) => {
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
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=false using Promise
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealActiveTime returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealActiveTimeMs003', 0, async function (done) {
        console.log("testGetRealActiveTimeMs003 start");
        const milliTime = await systemDateTime.getRealActiveTime(false);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeMs003 end');
        done();
    })

    /**
     * @tc.number: TestGetRealActiveTimeMs004
     * @tc.name: TestGetRealActiveTimeMs004
     * @tc.desc: Test getRealActiveTime API returns active time in milliseconds with explicit isNano=false using Callback
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=false using Callback
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealActiveTime callback returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealActiveTimeMs004', 0, async function (done) {
        console.log("testGetRealActiveTimeMs004 start");
        systemDateTime.getRealActiveTime(false, (err, data) => {
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
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=true using Promise
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid nanosecond duration
     * @tc.expect: getRealActiveTime returns valid positive nanosecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealActiveTimeNs001', 0, async function (done) {
        console.log("testGetRealActiveTimeNs001 start");
        const nanoTime = await systemDateTime.getRealActiveTime(true);
        console.log('Get real active nano time is ' + nanoTime);
        expect(nanoTime / NANO_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeNs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealActiveTimeNs002
     * @tc.name: TestGetRealActiveTimeNs002
     * @tc.desc: Test getRealActiveTime API returns active time in nanoseconds with isNano=true using Callback
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getRealActiveTime API with isNano=true using Callback
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid nanosecond duration
     * @tc.expect: getRealActiveTime callback returns valid positive nanosecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealActiveTimeNs002', 0, async function (done) {
        console.log("testGetRealActiveTimeNs002 start");
        systemDateTime.getRealActiveTime(true, (err, data) => {
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
     * @tc.precon: SystemDateTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API using Promise (default milliseconds)
     *           2. Verify returned time is non-negative number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealTime returns valid non-negative millisecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealTimeMs001', 0, async function (done) {
        console.log("testGetRealTimeMs001 start");
        const milliTime = await systemDateTime.getRealTime();
        console.log('Get real time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE >= 0).assertTrue();
        console.log('testGetRealTimeMs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealTimeMs002
     * @tc.name: TestGetRealTimeMs002
     * @tc.desc: Test getRealTime API returns real time in milliseconds using Callback
     * @tc.precon: SystemDateTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API using Callback (default milliseconds)
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealTime callback returns valid positive millisecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealTimeMs002', 0, async function (done) {
        console.log("testGetRealTimeMs002 start");
        systemDateTime.getRealTime((err, data) => {
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
     * @tc.precon: SystemDateTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=false using Promise
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealTime returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealTimeMs003', 0, async function (done) {
        console.log("testGetRealTimeMs003 start");
        const milliTime = await systemDateTime.getRealTime(false);
        console.log('Get real time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealTimeMs003 end');
        done();
    })

    /**
     * @tc.number: TestGetRealTimeMs004
     * @tc.name: TestGetRealTimeMs004
     * @tc.desc: Test getRealTime API returns real time in milliseconds with explicit isNano=false using Callback
     * @tc.precon: SystemDateTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=false using Callback
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid millisecond duration
     * @tc.expect: getRealTime callback returns valid positive millisecond timestamp when isNano parameter is explicitly set to false
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealTimeMs004', 0, async function (done) {
        console.log("testGetRealTimeMs004 start");
        systemDateTime.getRealTime(false, (err, data) => {
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
     * @tc.precon: SystemDateTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=true using Promise
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid nanosecond duration
     * @tc.expect: getRealTime returns valid positive nanosecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealTimeNs001', 0, async function (done) {
        console.log("testGetRealTimeNs001 start");
        const nanoTime = await systemDateTime.getRealTime(true);
        console.log('Get real nano time is ' + nanoTime);
        expect(nanoTime / NANO_TO_BASE > 0).assertTrue();
        console.log('testGetRealTimeNs001 end');
        done();
    })

    /**
     * @tc.number: TestGetRealTimeNs002
     * @tc.name: TestGetRealTimeNs002
     * @tc.desc: Test getRealTime API returns real time in nanoseconds with isNano=true using Callback
     * @tc.precon: SystemDateTime service is available and real time functions are accessible
     * @tc.step: 1. Call getRealTime API with isNano=true using Callback
     *           2. Verify returned time is positive number and correct type
     *           3. Confirm time represents valid nanosecond duration
     * @tc.expect: getRealTime callback returns valid positive nanosecond timestamp for system real time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#842
     */
    it('testGetRealTimeNs002', 0, async function (done) {
        console.log("testGetRealTimeNs002 start");
        systemDateTime.getRealTime(true, (err, data) => {
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
     * @tc.precon: SystemDateTime service is available and date setting permission is granted
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
        await systemDateTime.setDate(date);
        const currentDate = await systemDateTime.getDate();
        expect(currentDate instanceof Date && currentDate.toDateString() === date.toDateString()).assertTrue();
        done();
        console.log('testGetDate001 end');
    })

    /**
     * @tc.number: TestGetDate002
     * @tc.name: TestGetDate002
     * @tc.desc: Test getDate API returns current date using Callback after setting specific date
     * @tc.precon: SystemDateTime service is available and date setting permission is granted
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
        await systemDateTime.setDate(date);
        systemDateTime.getDate((err, data) => {
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
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getCurrentTime API with string parameter "true" using Promise
     *           2. Verify the API handles the string parameter without throwing exception
     *           3. Check if the operation completes successfully
     * @tc.expect: getCurrentTime should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeInvalidParam001', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam001 start");
        try {
            systemDateTime.getCurrentTime("true").then((time) => {
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
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getCurrentTime API with string parameter "true" using Callback
     *           2. Verify the API handles the string parameter without returning error
     *           3. Check if the callback executes successfully
     * @tc.expect: getCurrentTime callback should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetCurrentTimeInvalidParam002', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam002 start");
        try {
            systemDateTime.getCurrentTime("true", function (err) {
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
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealActiveTime API with string parameter "true" using Promise
     *           2. Verify the API handles the string parameter without throwing exception
     *           3. Check if the operation completes successfully
     * @tc.expect: getRealActiveTime should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeInvalidParam001', 0, async function (done) {
        console.log("testGetRealActiveTimeInvalidParam001 start");
        try {
            systemDateTime.getRealActiveTime("true").then((time) => {
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
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealActiveTime API with string parameter "true" using Callback
     *           2. Verify the API handles the string parameter without returning error
     *           3. Check if the callback executes successfully
     * @tc.expect: getRealActiveTime callback should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealActiveTimeInvalidParam002', 0, async function (done) {
        console.log("testGetRealActiveTimeInvalidParam002 start");
        try {
            systemDateTime.getRealActiveTime("true", function (err) {
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
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealTime API with string parameter "true" using Promise
     *           2. Verify the API handles the string parameter without throwing exception
     *           3. Check if the operation completes successfully
     * @tc.expect: getRealTime should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeInvalidParam001', 0, async function (done) {
        console.log("testGetRealTimeInvalidParam001 start");
        try {
            systemDateTime.getRealTime("true").then((time) => {
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
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call getRealTime API with string parameter "true" using Callback
     *           2. Verify the API handles the string parameter without returning error
     *           3. Check if the callback executes successfully
     * @tc.expect: getRealTime callback should handle string parameter "true" gracefully without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetRealTimeInvalidParam002', 0, async function (done) {
        console.log("testGetRealTimeInvalidParam002 start");
        try {
            systemDateTime.getRealTime("true", function (err) {
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
     * @tc.precon: SystemDateTime service is available and timezone setting permission is granted
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
        await systemDateTime.setTimezone(timezone);
        const currentTimezone = await systemDateTime.getTimezone();
        expect(typeof (currentTimezone) == 'string' && timezone === currentTimezone).assertTrue();
        await systemDateTime.setTimezone('Asia/Shanghai');
        done();
        console.log('testGetTimezone001 end');
    })

    /**
     * @tc.number: TestGetTimezone002
     * @tc.name: TestGetTimezone002
     * @tc.desc: Test getTimezone API returns current timezone using Callback after setting specific timezone
     * @tc.precon: SystemDateTime service is available and timezone setting permission is granted
     * @tc.step: 1. Set specific timezone to "Pacific/Majuro"
     *           2. Call getTimezone API using Callback to retrieve current timezone
     *           3. Restore timezone to "Asia/Shanghai" after verification
     *           4. Verify returned timezone matches the set timezone
     * @tc.expect: getTimezone callback returns correct timezone string matching the previously set timezone
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTimezone002', 0, async function (done) {
        console.log("testGetTimezone002 start");
        let timezone = "Pacific/Majuro";
        await systemDateTime.setTimezone(timezone);
        systemDateTime.getTimezone((err, data) => {
            if (err) {
                expect(false).assertTrue();
                done();
            }
            systemDateTime.setTimezone('Asia/Shanghai');
            expect(typeof(data) == 'string' && data === timezone).assertTrue();
            done();
        })
        console.log('testGetTimezone002 end');
    })

    /**
     * @tc.number: TestGetTime001
     * @tc.name: TestGetTime001
     * @tc.desc: Test getTime API returns current time in nanoseconds when isNano parameter is true
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference in milliseconds
     *           2. Call getTime API with isNano=true parameter
     *           3. Verify returned time is number type and not less than reference time
     *           4. Verify nanosecond timestamp length is 6 digits longer than millisecond timestamp
     * @tc.expect: getTime returns valid nanosecond timestamp with correct length difference from millisecond timestamp
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTime001', 0, function (done) {
        console.log("testGetTime001 start");
        const nowTime = new Date().getTime();
        const time = systemDateTime.getTime(true);
        console.log('Get current time is ' + time);
        expect(typeof (time) === 'number' && time >= nowTime).assertTrue();
        expect(time.toString().length-6===nowTime.toString().length ).assertTrue();
        console.log('testGetTime001 end');
        done();
    })

    /**
     * @tc.number: TestGetTime002
     * @tc.name: TestGetTime002
     * @tc.desc: Test getTime API returns current time in milliseconds when isNano parameter is false
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference in milliseconds
     *           2. Call getTime API with isNano=false parameter
     *           3. Verify returned time is number type and not less than reference time
     *           4. Verify millisecond timestamp has same length as reference timestamp
     * @tc.expect: getTime returns valid millisecond timestamp with same length as reference timestamp
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTime002', 0, function (done) {
        console.log("testGetTime002 start");
        const nowTime = new Date().getTime();
        const time = systemDateTime.getTime(false);
        console.log('Get current time is ' + time);
        expect(typeof (time) === 'number' && time >= nowTime).assertTrue();
        expect(time.toString().length===nowTime.toString().length ).assertTrue();
        console.log('testGetTime002 end');
        done();
    })

    /**
     * @tc.number: TestGetTime003
     * @tc.name: TestGetTime003
     * @tc.desc: Test getTime API behavior with different parameter types including default, number and string
     * @tc.precon: SystemDateTime service is available and time functions are accessible
     * @tc.step: 1. Get current timestamp as reference
     *           2. Call getTime API with no parameters (default behavior)
     *           3. Call getTime API with number parameter (123)
     *           4. Call getTime API with string parameter ("true")
     *           5. Verify all calls return valid timestamps with correct properties
     * @tc.expect: getTime handles different parameter types correctly and returns valid millisecond timestamps
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTime003', 0, function (done) {
        console.log("testGetTime003 start");
        const nowTime = new Date().getTime();
        const time1 = systemDateTime.getTime();
        const time2 = systemDateTime.getTime(123);
        const time3 = systemDateTime.getTime("true");
        console.log('Get current time1 is:' + time1+'  time2 is:'+time2+'  time3 is:'+time3);
        expect(typeof (time1) === 'number' && time1 >= nowTime).assertTrue();
        expect(time1.toString().length===nowTime.toString().length ).assertTrue();
        expect(typeof (time2) === 'number' && time2 >= nowTime).assertTrue();
        expect(time2.toString().length===nowTime.toString().length ).assertTrue();
        expect(typeof (time3) === 'number' && time3 >= nowTime).assertTrue();
        expect(time3.toString().length===nowTime.toString().length ).assertTrue();
        console.log('testGetTime003 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime001
     * @tc.name: TestGetUptime001
     * @tc.desc: Test getUptime API returns system startup time in milliseconds with explicit isNano=false
     * @tc.precon: SystemDateTime service is available and uptime tracking is enabled
     * @tc.step: 1. Call getUptime API with STARTUP time type and isNano=false
     *           2. Verify returned time is positive number and correct type
     *           3. Verify time represents valid millisecond duration
     * @tc.expect: getUptime returns valid positive millisecond timestamp for system startup time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetUptime001', 0,  function (done) {
        console.log("testGetUptime001 start");
        const time = systemDateTime.getUptime(systemDateTime.TimeType.STARTUP, false);
        console.log('get uptime time is ' + time);
        expect(typeof (time) === 'number' && time / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetUptime001 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime002
     * @tc.name: TestGetUptime002
     * @tc.desc: Test getUptime API returns system startup time in milliseconds with default parameter
     * @tc.precon: SystemDateTime service is available and uptime tracking is enabled
     * @tc.step: 1. Call getUptime API with STARTUP time type and no isNano parameter (defaults to milliseconds)
     *           2. Verify returned time is positive number and correct type
     *           3. Verify time represents valid millisecond duration
     * @tc.expect: getUptime returns valid positive millisecond timestamp for system startup time with default parameter
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('TestGetUptime002', 0,  function (done) {
        console.log("testGetUptime002 start");
        const time = systemDateTime.getUptime(systemDateTime.TimeType.STARTUP);
        console.log('get uptime time is ' + time);
        expect(typeof (time) === 'number' && time / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetUptime002 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime003
     * @tc.name: TestGetUptime003
     * @tc.desc: Test getUptime API returns system startup time in nanoseconds with isNano=true
     * @tc.precon: SystemDateTime service is available and uptime tracking is enabled
     * @tc.step: 1. Call getUptime API with STARTUP time type and isNano=true
     *           2. Verify returned time is positive number and correct type
     *           3. Verify time represents valid nanosecond duration
     * @tc.expect: getUptime returns valid positive nanosecond timestamp for system startup time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetUptime003', 0,  function (done) {
        console.log("testGetUptime003 start");
        const time = systemDateTime.getUptime(systemDateTime.TimeType.STARTUP, true);
        console.log('get uptime time is ' + time);
        expect(typeof (time) === 'number' && time / NANO_TO_BASE > 0).assertTrue();
        console.log('testGetUptime003 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime004
     * @tc.name: TestGetUptime004
     * @tc.desc: Test getUptime API returns system active time in milliseconds with explicit isNano=false
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getUptime API with ACTIVE time type and isNano=false
     *           2. Verify returned time is positive number and correct type
     *           3. Verify time represents valid millisecond duration
     * @tc.expect: getUptime returns valid positive millisecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetUptime004', 0,  function (done) {
        console.log("testGetUptime004 start");
        const time = systemDateTime.getUptime(systemDateTime.TimeType.ACTIVE, false);
        console.log('get uptime time is ' + time);
        expect(typeof (time) === 'number' && time / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetUptime004 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime005
     * @tc.name: TestGetUptime005
     * @tc.desc: Test getUptime API returns system active time in milliseconds with default parameter
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getUptime API with ACTIVE time type and no isNano parameter (defaults to milliseconds)
     *           2. Verify returned time is positive number and correct type
     *           3. Verify time represents valid millisecond duration
     * @tc.expect: getUptime returns valid positive millisecond timestamp for system active time with default parameter
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('TestGetUptime005', 0,  function (done) {
        console.log("testGetUptime005 start");
        const time = systemDateTime.getUptime(systemDateTime.TimeType.ACTIVE);
        console.log('get uptime time is ' + time);
        expect(typeof (time) === 'number' && time / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetUptime005 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime006
     * @tc.name: TestGetUptime006
     * @tc.desc: Test getUptime API returns system active time in nanoseconds with isNano=true
     * @tc.precon: SystemDateTime service is available and active time tracking is enabled
     * @tc.step: 1. Call getUptime API with ACTIVE time type and isNano=true
     *           2. Verify returned time is positive number and correct type
     *           3. Verify time represents valid nanosecond duration
     * @tc.expect: getUptime returns valid positive nanosecond timestamp for system active time
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetUptime006', 0,  function (done) {
        console.log("testGetUptime006 start");
        const time = systemDateTime.getUptime(systemDateTime.TimeType.ACTIVE, true);
        console.log('get uptime time is ' + time);
        expect(typeof (time) === 'number' && time / NANO_TO_BASE > 0).assertTrue();
        console.log('testGetUptime006 end');
        done();
    })

    /**
     * @tc.number: TestGetUptime007
     * @tc.name: TestGetUptime007
     * @tc.desc: Test getUptime API handles invalid time type parameter correctly
     * @tc.precon: SystemDateTime service is available and error handling is properly implemented
     * @tc.step: 1. Call getUptime API with invalid time type parameter (2)
     *           2. Catch the expected exception
     *           3. Verify error code is 401 (invalid parameter)
     * @tc.expect: getUptime throws exception with error code 401 when invalid time type is provided
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetUptime007', 0,  function (done) {
        console.log("testGetUptime007 start");
        try {
            systemDateTime.getUptime(2);
        } catch (err) {
            expect(err.code).assertEqual(401)
            done();
        }
        console.log('testGetUptime007 end');
    })

    /**
     * @tc.number: TestGetTimezoneSync001
     * @tc.name: TestGetTimezoneSync001
     * @tc.desc: Test getTimezoneSync API returns current timezone synchronously after setting specific timezone
     * @tc.precon: SystemDateTime service is available and timezone setting permission is granted
     * @tc.step: 1. Set specific timezone to "Pacific/Majuro"
     *           2. Call getTimezoneSync API to synchronously retrieve current timezone
     *           3. Verify returned timezone matches the set timezone
     *           4. Restore timezone to "Asia/Shanghai"
     * @tc.expect: getTimezoneSync returns correct timezone string matching the previously set timezone
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetTimezoneSync001', 0, async function (done) {
        console.log("testGetTimezoneSync001 start");
        let timezone = "Pacific/Majuro";
        await systemDateTime.setTimezone(timezone);
        const currentTimezone = systemDateTime.getTimezoneSync();
        expect(typeof (currentTimezone) == 'string' && timezone === currentTimezone).assertTrue();
        await systemDateTime.setTimezone('Asia/Shanghai');
        done();
        console.log('testGetTimezoneSync001 end');
    })

    /**
     * @tc.number: TestUpdateAndGetNtpTime001
     * @tc.name: TestUpdateAndGetNtpTime001
     * @tc.desc: Test NTP time synchronization functionality with updateNtpTime and getNtpTime APIs
     * @tc.precon: SystemDateTime service is available and NTP server is accessible
     * @tc.step: 1. Attempt to get NTP time before update (should fail)
     *           2. Update NTP time using updateNtpTime API
     *           3. Get NTP time using getNtpTime API
     *           4. Verify NTP time is valid and current
     * @tc.expect: NTP time is successfully updated and retrieved as valid current timestamp
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testUpdateAndGetNtpTime001', 0, async function (done) {
        console.log("testUpdateAndGetNtpTime001 start");
        try {
            systemDateTime.getNtpTime();
        } catch (err) {
            expect(err.code).assertEqual(13000002);
            done();
        }
        const nowTime = new Date().getTime();
        await systemDateTime.updateNtpTime();
        const milliTime = systemDateTime.getNtpTime();
        console.log('Get ntp time is ' + milliTime);
        expect(typeof (milliTime) === 'number' && milliTime >= nowTime).assertTrue();
        console.log('testUpdateAndGetNtpTime001 end');
        done();
    })

    /**
     * @tc.number: testGetAutoTime001
     * @tc.name: testGetAutoTime001
     * @tc.desc: Test auto time status functionality by setting to false and verifying status
     * @tc.precon: SystemDateTime service is available and auto time configuration is accessible
     * @tc.step: 1. Set auto time status to false using setAutoTimeStatus API
     *           2. Get auto time status using getAutoTimeStatus API
     *           3. Verify status is correctly set to false
     * @tc.expect: Auto time status is successfully set to false and correctly retrieved
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetAutoTime001', 0, async function (done) {
        console.log("testGetAutoTime001 start");
        await systemDateTime.setAutoTimeStatus(false);
        const autoTimeStatus = systemDateTime.getAutoTimeStatus();
        expect(typeof (autoTimeStatus) == 'boolean' && autoTimeStatus === false).assertTrue();
        done();
        console.log('testGetAutoTime001 end');
    })

    /**
     * @tc.number: testGetAutoTime002
     * @tc.name: testGetAutoTime002
     * @tc.desc: Test auto time status functionality by setting to true and verifying status
     * @tc.precon: SystemDateTime service is available and auto time configuration is accessible
     * @tc.step: 1. Set auto time status to true using setAutoTimeStatus API
     *           2. Get auto time status using getAutoTimeStatus API
     *           3. Verify status is correctly set to true
     * @tc.expect: Auto time status is successfully set to true and correctly retrieved
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testGetAutoTime002', 0, async function (done) {
        console.log("testGetAutoTime002 start");
        await systemDateTime.setAutoTimeStatus(true);
        const autoTimeStatus = systemDateTime.getAutoTimeStatus();
        expect(typeof (autoTimeStatus) == 'boolean' && autoTimeStatus === true).assertTrue();
        done();
        console.log('testGetAutoTime002 end');
    })
})