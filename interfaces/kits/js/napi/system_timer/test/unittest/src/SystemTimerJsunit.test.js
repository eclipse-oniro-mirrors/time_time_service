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

// @ts-nocheck
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import systemTimer from '@ohos.systemTimer'

describe('TimerTest', function () {
    console.log('start################################start');

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0001
     * @tc.name   Test systemTimer.createTimer type = TIMER_TYPE_REALTIME
     * @tc.desc   Test systemTimer_Timer API functionality, repeat = true (Callback)
     * @tc.size   : MEDIUM
     * @tc.type   : Function
     * @tc.level  : Level 0
     */
    it('SUB_time_systemTimer_createTimer_0001', 0, async function (done) {
        console.log("SUB_time_systemTimer_createTimer_0001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: true,
            interval: 5001
        }
        try {
            systemTimer.createTimer(options, function (err, timerID) {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.startTimer("timerID", function (err, data) {
                    expect(false).assertTrue();
                });
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
        }
        console.log('SUB_time_systemTimer_createTimer_0001 end');
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0002
     * @tc.name   Test systemTimer.createTimer type = TIMER_TYPE_WAKEUP
     * @tc.desc   Test systemTimer_Timer API functionality, repeat = false (Callback)
     * @tc.size   : MEDIUM
     * @tc.type   : Function
     * @tc.level  : Level 0
     */
    it('SUB_time_systemTimer_createTimer_0002', 0, async function (done) {
        console.log("SUB_time_systemTimer_createTimer_0002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false
        }
        try {
            systemTimer.createTimer(options, function (err, timerID) {
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.startTimer(timerID, 6000, function (err, data) {
                    systemTimer.stopTimer("timerID", function (err, data) {
                        expect(false).assertTrue;
                    });
                });
            });
        } catch (e) {
            expect(err.code).assertEqual(401);
        }
        console.log('SUB_time_systemTimer_createTimer_0002 end');
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0003
     * @tc.name   Test systemTimer.createTimer type = TIMER_TYPE_EXACT
     * @tc.desc   Test systemTimer_Timer API functionality, repeat = false (Callback)
     * @tc.size   : MEDIUM
     * @tc.type   : Function
     * @tc.level  : Level 0
     */
    it('SUB_time_systemTimer_createTimer_0003', 0, async function (done) {
        console.log("SUB_time_systemTimer_createTimer_0003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false
        }
        try {
            systemTimer.createTimer(options, function (err, timerID) {
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.startTimer(timerID, 5000, function (e) {
                    systemTimer.stopTimer(timerID, function (e) {
                        systemTimer.destroyTimer("timerID", function (e) {
                            expect(false).assertTrue;
                        });
                    });
                });
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
        }
        console.log('SUB_time_systemTimer_createTimer_0003 end');
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0004
     * @tc.name   Test systemTimer.createTimer type = TIMER_TYPE_WAKEUP
     * @tc.desc   Test systemTimer_Timer API functionality, repeat = true (Promise)
     * @tc.size   : MEDIUM
     * @tc.type   : Function
     * @tc.level  : Level 0
     */
    it('SUB_time_systemTimer_createTimer_0004', 0, async function (done) {
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false
        };
        try {
            systemTimer.createTimer(options).then((timerID) => {
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.startTimer("timerID", 5000).then(() => {
                    expect(false).assertTrue();
                })
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0005
     * @tc.name   Test systemTimer.createTimer type = TIMER_TYPE_WAKEUP
     * @tc.desc   Test systemTimer_Timer API functionality, repeat = true (Promise)
     * @tc.size   : MEDIUM
     * @tc.type   : Function
     * @tc.level  : Level 0
     */
    it('SUB_time_systemTimer_createTimer_0005', 0, async function (done) {
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false
        };
        try {
            systemTimer.createTimer(options).then((timerID) => {
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.startTimer(timerID, 5000).then(() => {
                    systemTimer.stopTimer("timerID").then(() => {
                        expect(false).assertTrue();
                    })
                })
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
        }
        done();
    });

    /**
     * @tc.number SUB_time_systemTimer_createTimer_0006
     * @tc.name   Test systemTimer.createTimer type = TIMER_TYPE_WAKEUP
     * @tc.desc   Test systemTimer_Timer API functionality, repeat = true (Promise)
     * @tc.size   : MEDIUM
     * @tc.type   : Function
     * @tc.level  : Level 0
     */
    it('SUB_time_systemTimer_createTimer_0006', 0, async function (done) {
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false
        };
        try {
            systemTimer.createTimer(options).then((timerID) => {
                expect(Number.isInteger(timerID)).assertTrue();
                systemTimer.startTimer(timerID, 5000).then(() => {
                    systemTimer.stopTimer(timerID).then(() => {
                        systemTimer.destroyTimer("timerID").then(() => {
                            expect(false).assertTrue();
                        })
                    })
                })
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
        }
        done();
    });
})