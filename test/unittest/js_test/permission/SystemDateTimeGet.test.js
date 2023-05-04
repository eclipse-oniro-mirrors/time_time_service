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
     * @tc.name: TestGetCurrentTimeMs001
     * @tc.desc: test getCurrentTime ms for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeMs002
     * @tc.desc: test getCurrentTime ms for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeMs003
     * @tc.desc: test getCurrentTime ms for promise when isNano is false.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeMs004
     * @tc.desc: test getCurrentTime ms for callback when isNano is false.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeNs001
     * @tc.desc: test getCurrentTime ns for promise when inNano is true
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeNs002
     * @tc.desc: test getCurrentTime ns for promise when inNano is true
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeMs001
     * @tc.desc: test getRealActiveTime ms for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeMs002
     * @tc.desc: test getRealActiveTime ms for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeMs003
     * @tc.desc: test getRealActiveTime ms for promise when isNano is false.
     * @tc.type: Function
     * @tc.require:
     */
    it('testGetRealActiveTimeMs003', 0, async function (done) {
        console.log("testGetRealActiveTimeMs003 start");
        const milliTime = await systemDateTime.getRealActiveTime(false);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeMs003 end');
        done();
    })

    /**
     * @tc.name: TestGetRealActiveTimeMs004
     * @tc.desc: test getRealActiveTime ms for callback when isNano is false.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeNs001
     * @tc.desc: test getRealActiveTime ns for promise when isNano is true.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeNs002
     * @tc.desc: test getRealActiveTime ns for callback when isNano is true.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs001
     * @tc.desc: test getRealTime ms for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs002
     * @tc.desc: test getRealTime ms for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs003
     * @tc.desc: test getRealTime ms for promise when isNano is false.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs004
     * @tc.desc: test getRealTime ms for callback when isNano is false.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeNs001
     * @tc.desc: test getRealTime ns for promise when isNano is true.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeNs002
     * @tc.desc: test getRealTime ns for callback when isNano is true.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetDate001
     * @tc.desc: test getDate for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetDate002
     * @tc.desc: test getDate for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeInvalidParam001
     * @tc.desc: test getCurrentTime for promise with invalid param.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeInvalidParam002
     * @tc.desc: test getCurrentTime for callback with invalid param.
     * @tc.type: Function
     * @tc.require:
     */
    it('testGetCurrentTimeInvalidParam001', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam001 start");
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
        console.log('testGetCurrentTimeInvalidParam001 end');
    })

    /**
     * @tc.name: TestGetCurrentTimeInvalidParam002
     * @tc.desc: test getRealActiveTime for callback with invalid param.
     * @tc.type: Function
     * @tc.require:
     */
    it('testGetCurrentTimeInvalidParam002', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam002 start");
        try {
            systemDateTime.getRealActiveTime("true").then((time) => {
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
     * @tc.name: TestGetRealActiveTimeInvalidParam001
     * @tc.desc: test getRealActiveTime for promise with invalid param.
     * @tc.type: Function
     * @tc.require:
     */
    it('testGetRealActiveTimeInvalidParam001', 0, async function (done) {
        console.log("testGetRealActiveTimeInvalidParam001 start");
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
        console.log('testGetRealActiveTimeInvalidParam001 end');
    })

    /**
     * @tc.name: TestGetRealActiveTimeInvalidParam001
     * @tc.desc: test getRealTime for promise with invalid param.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetRealTimeInvalidParam002
     * @tc.desc: test getRealTime for callback with invalid param.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetTimezone001
     * @tc.desc: test getTimezone for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestGetTimezone002
     * @tc.desc: test getTimezone for callback.
     * @tc.type: Function
     * @tc.require:
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
})