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

describe('SystemTimerNormalTest', function () {
    console.log('start################################start');
    let timerCount = 0

    /**
     * @tc.name: TestCreateTimerType001
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_REALTIME.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType001', 0, async (done) => {
        console.log("testCreateTimerType001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        systemTimer.createTimer(options, async (err, timerId) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timerId)
            expect(timerId > 0).assertTrue();
            done();
        })
        console.log('testCreateTimerType001 end');
    });

    /**
     * @tc.name: TestCreateTimerType002
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_WAKEUP.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType002', 0, async (done) => {
        console.log("testCreateTimerType002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false,
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerType002 end');
    });

    /**
     * @tc.name: TestCreateTimerType003
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_EXACT.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType003', 0, async (done) => {
        console.log("testCreateTimerType003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerType003 end');
    });

    /**
     * @tc.name: TestCreateTimerType004
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_REALTIME | TIMER_TYPE_WAKEUP.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType004', 0, async (done) => {
        console.log("testCreateTimerType004 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME | systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false,
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerType004 end');
    });

    /**
     * @tc.name: TestCreateTimerType005
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_REALTIME | TIMER_TYPE_EXACT.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType005', 0, async (done) => {
        console.log("testCreateTimerType005 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME | systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerType005 end');
    });

    /**
     * @tc.name: TestCreateTimerType006
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_WAKEUP | TIMER_TYPE_EXACT.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType006', 0, async (done) => {
        console.log("testCreateTimerType006 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP | systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerType006 end');
    });

    /**
     * @tc.name: TestCreateTimerRepeat007
     * @tc.desc: Test createTimer for callback with repeat is true.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerRepeat007', 0, async (done) => {
        console.log("testCreateTimerRepeat007 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: true,
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerRepeat007 end');
    });

    /**
     * @tc.name: TestCreateTimerInterval008
     * @tc.desc: Test createTimer for callback with repeat is true, interval is 0.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerInterval008', 0, async (done) => {
        console.log("testCreateTimerInterval008 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: true,
            interval: 0
        }
        systemTimer.createTimer(options, async (err, timer) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timer)
            expect(timer > 0).assertEqual(true)
            done();
        })
        console.log('testCreateTimerInterval008 end');
    });

    /**
     * @tc.name: TestCreateTimerInterval009
     * @tc.desc: Test createTimer for callback with interval is 5000.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerInterval009', 0, async (done) => {
        console.log("testCreateTimerInterval009 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: true,
            interval: 5000
        }
        systemTimer.createTimer(options, async (err, timerId) => {
            if (err) {
                expect(false).assertTrue();
            }
            await systemTimer.destroyTimer(timerId);
            expect(typeof (timerId) === 'number' && timerId > 0).assertEqual(true);
            done();
        })
        console.log('testCreateTimerInterval009 end');
    });

    /**
     * @tc.name: TestCreateTimerType010
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_REALTIME.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType010', 0, async (done) => {
        console.log("testCreateTimerType010 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerType010 end');
    });

    /**
     * @tc.name: TestCreateTimerType011
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_WAKEUP.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType011', 0, async (done) => {
        console.log("testCreateTimerType011 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerType011 end');
    });

    /**
     * @tc.name: TestCreateTimerType012
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_EXACT.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType012', 0, async (done) => {
        console.log("testCreateTimerType012 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerType012 end');
    });

    /**
     * @tc.name: TestCreateTimerType013
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_REALTIME | TIMER_TYPE_WAKEUP.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType013', 0, async (done) => {
        console.log("testCreateTimerType013 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME | systemTimer.TIMER_TYPE_WAKEUP,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerType013 end');
    });

    /**
     * @tc.name: TestCreateTimerType014
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_REALTIME | TIMER_TYPE_EXACT.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType014', 0, async (done) => {
        console.log("testCreateTimerType014 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME | systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerType014 end');
    });

    /**
     * @tc.name: TestCreateTimerType015
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_WAKEUP | TIMER_TYPE_EXACT.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerType015', 0, async (done) => {
        console.log("testCreateTimerType015 start")
        let options = {
            type: systemTimer.TIMER_TYPE_WAKEUP | systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerType015 end');
    });

    /**
     * @tc.name: TestCreateTimerRepeat016
     * @tc.desc: Test createTimer for promise with repeat is true.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerRepeat016', 0, async (done) => {
        console.log("testCreateTimerRepeat016 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: true,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerRepeat016 end');
    });

    /**
     * @tc.name: TestCreateTimerInterval016
     * @tc.desc: Test createTimer for promise with repeat is true, interval is 0.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerInterval016', 0, async (done) => {
        console.log("testCreateTimerInterval016 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: true,
            interval: 0
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerInterval016 end');
    });

    /**
     * @tc.name: TestCreateTimerInterval018
     * @tc.desc: Test createTimer for promise with interval is 5000.
     * @tc.type: Function
     * @tc.require:
     */
    it('testCreateTimerInterval018', 0, async (done) => {
        console.log("testCreateTimerInterval018 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: true,
            interval: 5000
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testCreateTimerInterval018 end');
    });

    /**
     * @tc.name: TestCreateTimerType019
     * @tc.desc: Test createTimer for promise with type is TIMER_TYPE_IDLE.
     * @tc.type: Function
     * @tc.require:
     */
    it('TestCreateTimerType019', 0, async (done) => {
        console.log("TestCreateTimerType019 start")
        let options = {
            type: systemTimer.TIMER_TYPE_IDLE,
            repeat: false,
        }
        systemTimer.createTimer(options).then((timerId) => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('TestCreateTimerType019 end');
    });

    /**
     * @tc.name: TestCreateTimerType020
     * @tc.desc: Test createTimer for callback with type is TIMER_TYPE_IDLE.
     * @tc.type: Function
     * @tc.require:
     */
    it('TestCreateTimerType020', 0, async (done) => {
        console.log("TestCreateTimerType020 start")
        let options = {
            type: systemTimer.TIMER_TYPE_IDLE,
            repeat: false,
        }
        systemTimer.createTimer(options, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            systemTimer.destroyTimer(data)
            expect(true).assertTrue();
            done();
        })
        console.log('TestCreateTimerType020 end');
    });

    /**
     * @tc.name: TestStartTimer001
     * @tc.desc: Test startTimer for promise with triggerTime 0.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStartTimer001', 0, async (done) => {
        console.log("testStartTimer001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.startTimer(timerId, 0).then(() => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testStartTimer001 end');
    });

    /**
     * @tc.name: TestStartTimer002
     * @tc.desc: Test startTimer for promise with start timer twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStartTimer002', 0, async (done) => {
        console.log("testStartTimer002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.startTimer(timerId, new Date().getTime() + 1000).then(() => {
            expect(true).assertTrue();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        systemTimer.startTimer(timerId, new Date().getTime() + 1000).then(() => {
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        await systemTimer.stopTimer(timerId)
        await systemTimer.destroyTimer(timerId)
        console.log('testStartTimer002 end');
    });

    /**
     * @tc.name: TestStartTimer003
     * @tc.desc: Test startTimer for callback with triggerTime 0.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStartTimer003', 0, async (done) => {
        console.log("testStartTimer003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.startTimer(timerId, 0, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            systemTimer.destroyTimer(timerId)
            expect(typeof (data) === 'undefined').assertTrue();
            done();
        })
        console.log('testStartTimer003 end');
    });

    /**
     * @tc.name: TestStartTimer004
     * @tc.desc: Test startTimer for callback with start timer twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStartTimer004', 0, async (done) => {
        console.log("testStartTimer004 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.startTimer(timerId, new Date().getTime() + 1000, (err) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(true).assertTrue();
        })
        systemTimer.startTimer(timerId, new Date().getTime() + 2000, (err) => {
            if (err) {
                expect(false).assertTrue();
            }
            systemTimer.stopTimer(timerId)
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        })
        console.log('testStartTimer004 end');
    });

    /**
     * @tc.name: TestStopTimer001
     * @tc.desc: Test stopTimer for promise not start timer.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer001', 0, async (done) => {
        console.log("testStopTimer001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.stopTimer(timerId).then((data) => {
            systemTimer.destroyTimer(timerId);
            expect(typeof (data) === 'undefined').assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        });
        console.log('testStopTimer001 end');
    });

    /**
     * @tc.name: TestStopTimer002
     * @tc.desc: Test stopTimer for promise.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer002', 0, async (done) => {
        console.log("testStopTimer002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000);
        systemTimer.stopTimer(timerId).then(() => {
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testStopTimer002 end');
    });

    /**
     * @tc.name: TestStopTimer003
     * @tc.desc: Test stopTimer for promise stop timer twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer003', 0, async (done) => {
        console.log("testStopTimer003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        await systemTimer.stopTimer(timerId)
        systemTimer.stopTimer(timerId).then(() => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testStopTimer003 end');
    });

    /**
     * @tc.name: TestStopTimer004
     * @tc.desc: Test stopTimer for promise with start and stop timer twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('systemTimer_stopTimer_test4', 0, async (done) => {
        console.log("SUB_systemTimer_stopTimer_JS_API_004 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        await systemTimer.stopTimer(timerId)
        systemTimer.startTimer(timerId, new Date().getTime() + 1000).then(() => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('SUB_systemTimer_stopTimer_JS_API_004 end');
    });

    /**
     * @tc.name: TestStopTimer005
     * @tc.desc: Test stopTimer for callback not start timer.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer005', 0, async (done) => {
        console.log("testStopTimer005 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.stopTimer(timerId, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            systemTimer.destroyTimer(timerId);
            expect(typeof (data) === 'undefined').assertTrue();
            done();
        })
        console.log('testStopTimer005 end');
    });

    /**
     * @tc.name: TestStopTimer006
     * @tc.desc: Test stopTimer for callback.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer006', 0, async (done) => {
        console.log("testStopTimer006 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000);
        systemTimer.stopTimer(timerId, (err) => {
            if (err) {
                expect(false).assertTrue();
            }
            systemTimer.destroyTimer(timerId);
            expect(true).assertTrue();
            done();
        })
        console.log('testStopTimer006 end');
    });

    /**
     * @tc.name: TestStopTimer007
     * @tc.desc: Test stopTimer for callback stop timer twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer007', 0, async (done) => {
        console.log("testStopTimer007 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        await systemTimer.stopTimer(timerId)
        systemTimer.stopTimer(timerId, (err) => {
            if (err) {
                expect(false).assertTrue();
            }
            systemTimer.destroyTimer(timerId);
            expect(true).assertTrue();
            done();
        })
        console.log('testStopTimer007 end');
    });

    /**
     * @tc.name: TestStopTimer008
     * @tc.desc: Test stopTimer for callback with start and stop timer twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('testStopTimer008', 0, async (done) => {
        console.log("testStopTimer008 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        systemTimer.stopTimer(timerId, (err) => {
            if (err) {
                expect(false).assertTrue();
            }
        })
        systemTimer.startTimer(timerId, new Date().getTime() + 1000).then(() => {
            systemTimer.destroyTimer(timerId)
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testStopTimer008 end');
    });

    /**
     * @tc.name: TestDestroyTimer001
     * @tc.desc: Test destroyTimer for promise.
     * @tc.type: Function
     * @tc.require:
     */
    it('testDestroyTimer001', 0, async (done) => {
        console.log("testDestroyTimer001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        systemTimer.destroyTimer(timerId).then((data) => {
            expect(typeof (data) === 'undefined').assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log('testDestroyTimer001 end');
    });

    /**
     * @tc.name: TestDestroyTimer002
     * @tc.desc: Test destroyTimer for promise twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('testDestroyTimer002', 0, async (done) => {
        console.log("testDestroyTimer002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        await systemTimer.destroyTimer(timerId)
        systemTimer.destroyTimer(timerId).then((data) => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(true).assertTrue();
            done();
        })
        console.log('testDestroyTimer002 end');
    });

    /**
     * @tc.name: TestDestroyTimer003
     * @tc.desc: Test destroyTimer for promise before start timer.
     * @tc.type: Function
     * @tc.require:
     */
    it('testDestroyTimer003', 0, async (done) => {
        console.log("testDestroyTimer003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        await systemTimer.destroyTimer(timerId)
        systemTimer.startTimer(timerId, new Date().getTime() + 1000).then((data) => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(true).assertTrue();
            done();
        })
        console.log('testDestroyTimer003 end');
    });

    /**
     * @tc.name: TestDestroyTimer004
     * @tc.desc: Test destroyTimer for callback.
     * @tc.type: Function
     * @tc.require:
     */
    it('testDestroyTimer004', 0, async (done) => {
        console.log("testDestroyTimer004 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        systemTimer.destroyTimer(timerId, (err, data) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(typeof (data) === 'undefined').assertTrue();
            done();
        })
        console.log('testDestroyTimer004 end');
    });

    /**
     * @tc.name: TestDestroyTimer005
     * @tc.desc: Test destroyTimer for callback twice.
     * @tc.type: Function
     * @tc.require:
     */
    it('systemTimer_destroyTimer_test5', 0, async (done) => {
        console.log("SUB_systemTimer_destroyTimer_JS_API_005 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        await systemTimer.destroyTimer(timerId)
        systemTimer.destroyTimer(timerId, (err) => {
            if (err) {
                expect(true).assertTrue();
            } else {
                expect(false).assertTrue();
            }
            done();
        })
        console.log('SUB_systemTimer_destroyTimer_JS_API_005 end');
    });

    /**
     * @tc.name: TestDestroyTimer006
     * @tc.desc: Test destroyTimer for callback before start timer.
     * @tc.type: Function
     * @tc.require:
     */
    it('testDestroyTimer006', 0, async (done) => {
        console.log("testDestroyTimer006 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
        }
        let timerId = await systemTimer.createTimer(options)
        await systemTimer.startTimer(timerId, new Date().getTime() + 1000)
        systemTimer.destroyTimer(timerId, (err) => {
            if (err) {
                expect(false).assertTrue();
            } else {
                systemTimer.startTimer(timerId, new Date().getTime() + 1000).then(() => {
                    expect(false).assertTrue();
                    done();
                }).catch((err) => {
                    expect(true).assertTrue();
                    done();
                })
            }
            done();
        })
        console.log('testDestroyTimer006 end');
    });
})