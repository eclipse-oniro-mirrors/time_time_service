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
import systemTimer from '@ohos.systemTimer'

describe('TimerTest', function() {

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0000
     * @tc.name SUB_time_systemTimer_createTimer_0000
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_REALTIME, repeat = false (Callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0000', 0, async function (done) {
        console.info("SUB_time_systemTimer_createTimer_0000 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false
        };
        try {
            console.info("SUB_time_systemTimer_createTimer_0000 create timer")
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.destroyTimer(timerID, function (e) {
                    console.info('SUB_time_systemTimer_createTimer_0000 destroyTimerID: ' + timerID);
                });
            });
        } catch (err) {
            console.info('SUB_time_systemTimer_createTimer_0000 has failed for ' + e);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0001
     * @tc.name SUB_time_systemTimer_createTimer_0001
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_REALTIME, repeat = true (callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0001', 0, async function (done) {
        console.info("SUB_time_systemTimer_createTimer_0001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: true
        }
        try {
            console.info("SUB_time_systemTimer_createTimer_0001 create timer")
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.destroyTimer(timerID, function (e) {
                    console.info('SUB_time_systemTimer_createTimer_0001 destroy timerID: ' + timerID);
                });
            });
        } catch (e) {
            console.info('SUB_time_systemTimer_createTimer_0001 has failed for ' + e);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0002
     * @tc.name SUB_time_systemTimer_createTimer_0002
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_WAKEUP, repeat = true, interval (Callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0002', 0, async function (done) {
        console.info("SUB_time_systemTimer_createTimer_0002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: true,
            interval: 5001
        }
        try {
            console.info("SUB_time_systemTimer_createTimer_0002 create timer")
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.destroyTimer(timerID, function (e) {
                    console.info('SUB_time_systemTimer_createTimer_0002 destroy timerID: ' + timerID);
                });
            });
        } catch (e) {
            console.info('SUB_time_systemTimer_createTimer_0002 has failed for ' + e);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0003
     * @tc.name SUB_time_systemTimer_createTimer_0003
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_EXACT, repeat = false (Callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0003', 0, async function (done) {
        console.info("SUB_time_systemTimer_createTimer_0003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false
        }
        try {
            console.info("SUB_time_systemTimer_createTimer_0003 create timer")
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.destroyTimer(timerID, function (e) {
                    console.info('SUB_time_systemTimer_createTimer_0003 destroy timerID: ' + timerID);
                });
            });
        } catch (e) {
            console.info('SUB_time_systemTimer_createTimer_0003 has failed for ' + e);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0004
     * @tc.name SUB_time_systemTimer_createTimer_0004
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_IDLE, repeat = false(callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0004', 0, async function (done) {
        console.info("SUB_time_systemTimer_createTimer_0004 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP | systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        try {
            console.info("SUB_time_systemTimer_createTimer_0004 create timer")
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.destroyTimer(timerID, function (e) {
                    console.info('SUB_time_systemTimer_createTimer_0004 destroy timerID: ' + timerID);
                });
            });
        } catch (e) {
            console.info('SUB_time_systemTimer_createTimer_0004 has failed for ' + e);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_startTimer_0005
     * @tc.name SUB_time_systemTimer_startTimer_0005
     * @tc.desc Test startTimer() interfaces, normal call(callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0005', 0, async function (done) {
        console.info("SUB_time_systemTimer_startTimer_0005 start")
        let options = {
            type: systemTimer.TIMER_TYPE_IDLE,
            repeat: false,
        }
        try {
            console.info("SUB_time_systemTimer_startTimer_0005 create timer")
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                let triggerTime = 5000;
                systemTimer.startTimer(timerID, triggerTime, function (err, data) {
                    systemTimer.stopTimer(timerID, function (err, data) {
                        systemTimer.destroyTimer(timerID, function (err, data) {
                            console.info('SUB_time_systemTimer_startTimer_0005 has SUCCESS');
                        });
                    });
                });
            });
        } catch (e) {
            console.info('SUB_time_systemTimer_startTimer_0005 has failed for ' + e);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0006
     * @tc.name SUB_time_systemTimer_createTimer_0006
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_REALTIME, repeat = false (Promise)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0006', 0, async function (done) {
        console.info("SUB_time_systemTimer_startTimer_0006 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false
        };
        try {
            systemTimer.createTimer(options).then((timerID) => {
                expect(Number.isInteger(timerID)).assertTrue();
                console.info("SUB_time_systemTimer_startTimer_0006 create timer")
            }, error => {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info('SUB_time_systemTimer_startTimer_0006 has failed for ' + err);
            expect(false).assertTrue();
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0007
     * @tc.name SUB_time_systemTimer_createTimer_0007
     * @tc.desc Test createTimer() interfaces, type = TIMER_TYPE_REALTIME | TIMER_TYPE_WAKEUP(Callback)
     * @tc.size MEDIUM
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_time_systemTimer_createTimer_0007', 0, async function (done) {
        console.info("SUB_time_systemTimer_startTimer_0007 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME | systemTimer.TIMER_TYPE_WAKEUP,
            repeat: true,
            interval: 5000
        };
        try {
            console.info("SUB_time_systemTimer_startTimer_0007 create timer")
            systemTimer.createTimer(options).then((timerID) => {
                expect(Number.isInteger(timerID)).assertTrue();
                console.info("SUB_time_systemTimer_startTimer_0007 create timer")
            }).catch(() => {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info('SUB_time_systemTimer_startTimer_0007 has failed for ' + err);
            expect(false).assertTrue();
        }
        done();
    });
})