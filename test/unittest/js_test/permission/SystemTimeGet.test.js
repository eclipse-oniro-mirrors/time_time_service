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
     * @tc.name: TestGetCurrentTimeMs001
     * @tc.desc: test getCurrentTime ms for promise.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeMs002
     * @tc.desc: test getCurrentTime ms for callback.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeMs003
     * @tc.desc: test getCurrentTime ms for promise when isNano is false.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeMs004
     * @tc.desc: test getCurrentTime ms for callback when isNano is false.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeNs001
     * @tc.desc: test getCurrentTime ns for promise when inNano is true
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeNs002
     * @tc.desc: test getCurrentTime ns for promise when inNano is true
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeMs001
     * @tc.desc: test getRealActiveTime ms for promise.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeMs002
     * @tc.desc: test getRealActiveTime ms for callback.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeMs003
     * @tc.desc: test getRealActiveTime ms for promise when isNano is false.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testGetRealActiveTimeMs003', 0, async function (done) {
        console.log("testGetRealActiveTimeMs003 start");
        const milliTime = await systemTime.getRealActiveTime(false);
        expect(typeof (milliTime) === 'number' && milliTime / MILLI_TO_BASE > 0).assertTrue();
        console.log('testGetRealActiveTimeMs003 end');
        done();
    })

    /**
     * @tc.name: TestGetRealActiveTimeMs004
     * @tc.desc: test getRealActiveTime ms for callback when isNano is false.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeNs001
     * @tc.desc: test getRealActiveTime ns for promise when isNano is true.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealActiveTimeNs002
     * @tc.desc: test getRealActiveTime ns for callback when isNano is true.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs001
     * @tc.desc: test getRealTime ms for promise.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs002
     * @tc.desc: test getRealTime ms for callback.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs003
     * @tc.desc: test getRealTime ms for promise when isNano is false.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeMs004
     * @tc.desc: test getRealTime ms for callback when isNano is false.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeNs001
     * @tc.desc: test getRealTime ns for promise when isNano is true.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeNs002
     * @tc.desc: test getRealTime ns for callback when isNano is true.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetDate001
     * @tc.desc: test getDate for promise.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetDate002
     * @tc.desc: test getDate for callback.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeInvalidParam001
     * @tc.desc: test getCurrentTime for promise with invalid param.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeInvalidParam002
     * @tc.desc: test getCurrentTime for callback with invalid param.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetCurrentTimeInvalidParam002
     * @tc.desc: test getRealActiveTime for callback with invalid param.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testGetCurrentTimeInvalidParam002', 0, async function (done) {
        console.log("testGetCurrentTimeInvalidParam002 start");
        try {
            systemTime.getRealActiveTime("true").then((time) => {
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
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testGetRealActiveTimeInvalidParam001', 0, async function (done) {
        console.log("testGetRealActiveTimeInvalidParam001 start");
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
        console.log('testGetRealActiveTimeInvalidParam001 end');
    })

    /**
     * @tc.name: TestGetRealActiveTimeInvalidParam001
     * @tc.desc: test getRealTime for promise with invalid param.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetRealTimeInvalidParam002
     * @tc.desc: test getRealTime for callback with invalid param.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetTimezone001
     * @tc.desc: test getTimezone for promise.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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
     * @tc.name: TestGetTimezone002
     * @tc.desc: test getTimezone for callback.
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
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