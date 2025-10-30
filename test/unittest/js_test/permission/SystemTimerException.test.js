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
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import systemTimer from '@ohos.systemTimer'

describe('SystemTimerExceptionTest', function () {
    console.log('start################################start');

    async function testCreateTimerPromise(options, done) {
        try {
            systemTimer.createTimer(options).then(() => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    }

    async function testCreateTimerCallback(options, done) {
        try {
            systemTimer.createTimer(options, (err) => {
                if (err) {
                    expect(err.code).assertEqual(401);
                } else {
                    expect(false).assertTrue();
                }
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    }

    let timeErr = function (err, done) {
        if (err) {
            expect(true).assertTrue();
        } else {
            expect(false).assertTrue();
        }
        done();
    }

    /**
     * @tc.number: TestCreateTimerType001
     * @tc.name: TestCreateTimerType001
     * @tc.desc: Test createTimer API creates timer successfully with valid type 16 using Promise
     * @tc.precon: SystemTimer service is available and timer creation is supported
     * @tc.step: 1. Prepare timer options with type=16 and repeat=false
     *           2. Call createTimer API using Promise
     *           3. Verify timer ID is returned and not zero
     * @tc.expect: createTimer should successfully create timer and return valid timer ID
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerType001', 0, async function (done) {
        console.log("testCreateTimerType001 start")
        let options = {
            type: 16,
            repeat: false
        }
        let timerId = await systemTimer.createTimer(options)
        console.info(`timerId ${timerId}`)
        expect(timerId !== 0).assertTrue();
        done();
        console.log('testCreateTimerType001 end');
    });

    /**
     * @tc.number: TestCreateTimerType002
     * @tc.name: TestCreateTimerType002
     * @tc.desc: Test createTimer API handles string type parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with string type parameter
     *           2. Call createTimer API using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when type parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerType002', 0, async function (done) {
        console.log("testCreateTimerType002 start")
        let options = {
            type: "type",
            repeat: false
        }
        await testCreateTimerPromise(options, done);
        console.log('testCreateTimerType002 end');
    });

    /**
     * @tc.number: TestCreateTimerRepeat003
     * @tc.name: TestCreateTimerRepeat003
     * @tc.desc: Test createTimer API handles string repeat parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with string repeat parameter
     *           2. Call createTimer API using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when repeat parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerRepeat003', 0, async function (done) {
        console.log("testCreateTimerRepeat003 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: "true"
        }
        await testCreateTimerPromise(options, done);
        console.log('testCreateTimerRepeat003 end');
    });

    /**
     * @tc.number: TestCreateTimerWantAgent004
     * @tc.name: TestCreateTimerWantAgent004
     * @tc.desc: Test createTimer API handles number wantAgent parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with number wantAgent parameter
     *           2. Call createTimer API using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when wantAgent parameter is invalid number
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerWantAgent004', 0, async function (done) {
        console.log("testCreateTimerWantAgent004 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
            wantAgent: 123,
        }
        await testCreateTimerPromise(options, done);
        console.log('testCreateTimerWantAgent004 end');
    });

    /**
     * @tc.number: TestCreateTimerCallback005
     * @tc.name: TestCreateTimerCallback005
     * @tc.desc: Test createTimer API handles number callback parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with number callback parameter
     *           2. Call createTimer API using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when callback parameter is invalid number
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerCallback005', 0, async function (done) {
        console.log("testCreateTimerCallback005 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
            callback: 123,
        }
        await testCreateTimerPromise(options, done);
        console.log('testCreateTimerCallback005 end');
    });

    /**
     * @tc.number: TestCreateTimerNull006
     * @tc.name: TestCreateTimerNull006
     * @tc.desc: Test createTimer API handles null options parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call createTimer API with null options using Promise
     *           2. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when options parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerNull006', 0, async function (done) {
        console.log("testCreateTimerNull006 start")
        try {
            systemTimer.createTimer(null).then(() => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testCreateTimerNull006 end');
    });

    /**
     * @tc.number: TestCreateTimerRepeat007
     * @tc.name: TestCreateTimerRepeat007
     * @tc.desc: Test createTimer API handles missing repeat parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options without repeat parameter
     *           2. Call createTimer API using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when repeat parameter is missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerRepeat007', 0, async function (done) {
        console.log("testCreateTimerRepeat007 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT
        }
        await testCreateTimerPromise(options, done);
        console.log('testCreateTimerRepeat007 end');
    });

    /**
     * @tc.number: TestCreateTimerInterval008
     * @tc.name: TestCreateTimerInterval008
     * @tc.desc: Test createTimer API handles string interval parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with string interval parameter
     *           2. Call createTimer API using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer should reject with error code 401 when interval parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerInterval008', 0, async function (done) {
        console.log("testCreateTimerInterval008 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
            interval: "1000"
        }
        await testCreateTimerPromise(options, done);
        console.log('testCreateTimerInterval008 end');
    });

    /**
     * @tc.number: TestCreateTimerType009
     * @tc.name: TestCreateTimerType009
     * @tc.desc: Test createTimer API creates timer successfully with valid type 16 using Callback
     * @tc.precon: SystemTimer service is available and timer creation is supported
     * @tc.step: 1. Prepare timer options with type=16 and repeat=false
     *           2. Call createTimer API using Callback
     *           3. Verify timer creation succeeds without errors
     * @tc.expect: createTimer should successfully create timer using callback without errors
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerType009', 0, async function (done) {
        console.log("testCreateTimerType009 start")
        let options = {
            type: 16,
            repeat: false
        }
        try {
            systemTimer.createTimer(options, (err) => {
                if (err) {
                    expect(false).assertTrue();
                }
                expect(true).assertTrue();
                done();
            })
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        console.log('testCreateTimerType009 end');
    });

    /**
     * @tc.number: TestCreateTimerType010
     * @tc.name: TestCreateTimerType010
     * @tc.desc: Test createTimer API handles string type parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with string type parameter
     *           2. Call createTimer API using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when type parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerType010', 0, async function (done) {
        console.log("testCreateTimerType010 start")
        let options = {
            type: "type",
            repeat: false
        }
        await testCreateTimerCallback(options, done);
        console.log('testCreateTimerType010 end');
    });

    /**
     * @tc.number: TestCreateTimerRepeat011
     * @tc.name: TestCreateTimerRepeat011
     * @tc.desc: Test createTimer API handles string repeat parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with string repeat parameter
     *           2. Call createTimer API using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when repeat parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerRepeat011', 0, async function (done) {
        console.log("testCreateTimerRepeat011 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: "true"
        }
        await testCreateTimerCallback(options, done);
        console.log('testCreateTimerRepeat011 end');
    });

    /**
     * @tc.number: TestCreateTimerWantAgent012
     * @tc.name: TestCreateTimerWantAgent012
     * @tc.desc: Test createTimer API handles number wantAgent parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with number wantAgent parameter
     *           2. Call createTimer API using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when wantAgent parameter is invalid number
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerWantAgent012', 0, async function (done) {
        console.log("testCreateTimerWantAgent012 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
            wantAgent: 123,
        }
        await testCreateTimerCallback(options, done);
        console.log('testCreateTimerWantAgent012 end');
    });

    /**
     * @tc.number: TestCreateTimerCallback013
     * @tc.name: TestCreateTimerCallback013
     * @tc.desc: Test createTimer API handles number callback parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with number callback parameter
     *           2. Call createTimer API using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when callback parameter is invalid number
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerCallback013', 0, async function (done) {
        console.log("testCreateTimerCallback013 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
            callback: 123,
        }
        await testCreateTimerCallback(options, done);
        console.log('testCreateTimerCallback013 end');
    });

    /**
     * @tc.number: TestCreateTimerNull014
     * @tc.name: TestCreateTimerNull014
     * @tc.desc: Test createTimer API handles null options parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call createTimer API with null options using Callback
     *           2. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when options parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerNull014', 0, async function (done) {
        console.log("testCreateTimerNull014 start")
        try {
            systemTimer.createTimer(null, (err) => {
                if (err) {
                    expect(err.code).assertEqual(401);
                } else {
                    expect(false).assertTrue();
                }
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testCreateTimerNull014 end');
    });

    /**
     * @tc.number: TestCreateTimerRepeat015
     * @tc.name: TestCreateTimerRepeat015
     * @tc.desc: Test createTimer API handles missing repeat parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options without repeat parameter
     *           2. Call createTimer API using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when repeat parameter is missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerRepeat015', 0, async function (done) {
        console.log("testCreateTimerRepeat015 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT
        }
        await testCreateTimerCallback(options, done);
        console.log('testCreateTimerRepeat015 end');
    });

    /**
     * @tc.number: TestCreateTimerInterval016
     * @tc.name: TestCreateTimerInterval016
     * @tc.desc: Test createTimer API handles string interval parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Prepare timer options with string interval parameter
     *           2. Call createTimer API using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: createTimer callback should return error code 401 when interval parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerInterval016', 0, async function (done) {
        console.log("testCreateTimerInterval016 start")
        let options = {
            type: systemTimer.TIMER_TYPE_EXACT,
            repeat: false,
            interval: "1000"
        }
        try {
            systemTimer.createTimer(options, (err) => {
                if (err) {
                    expect(err.code).assertEqual(401);
                } else {
                    expect(false).assertTrue();
                }
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testCreateTimerInterval016 end');
    });

    /**
     * @tc.number: TestStartTimerLackParam001
     * @tc.name: TestStartTimerLackParam001
     * @tc.desc: Test startTimer API handles missing triggerTime parameter using Callback
     * @tc.precon: SystemTimer service is available and timer creation is supported
     * @tc.step: 1. Create valid timer with repeat mode
     *           2. Call startTimer API without triggerTime using Callback
     *           3. Verify operation fails with error code 401
     * @tc.expect: startTimer should return error code 401 when triggerTime parameter is missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerLackParam001', 0, async function (done) {
        console.log("testStartTimerLackParam001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: true,
            interval: 5001
        }
        try {
            let timerId = await systemTimer.createTimer(options);
            expect(Number.isInteger(timerId)).assertTrue();
            systemTimer.startTimer(timerId, function (err) {
                expect(false).assertTrue();
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testStartTimerLackParam001 end');
    });

    /**
     * @tc.number: TestStartTimerLackParam002
     * @tc.name: TestStartTimerLackParam002
     * @tc.desc: Test startTimer API handles missing triggerTime parameter using Promise
     * @tc.precon: SystemTimer service is available and timer creation is supported
     * @tc.step: 1. Create valid timer with repeat mode
     *           2. Call startTimer API without triggerTime using Promise
     *           3. Verify operation fails with error code 401
     * @tc.expect: startTimer should reject with error code 401 when triggerTime parameter is missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerLackParam002', 0, async function (done) {
        console.log("testStartTimerLackParam002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: true,
            interval: 5001
        }
        try {
            let timerId = await systemTimer.createTimer(options);
            expect(Number.isInteger(timerId)).assertTrue();
            systemTimer.startTimer(timerId).then(() => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testStartTimerLackParam002 end');
    });

    /**
     * @tc.number: TestStartTimerInvalidParam003
     * @tc.name: TestStartTimerInvalidParam003
     * @tc.desc: Test startTimer API handles string timerId parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call startTimer API with string timerId using Callback
     *           2. Verify operation fails with error code 401
     * @tc.expect: startTimer should return error code 401 when timerId parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerInvalidParam003', 0, async function (done) {
        console.log("testStartTimerInvalidParam003 start")
        try {
            systemTimer.startTimer("timerId", function (err) {
                expect(false).assertTrue();
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testStartTimerInvalidParam003 end');
    });

    /**
     * @tc.number: TestStartTimerInvalidParam004
     * @tc.name: TestStartTimerInvalidParam004
     * @tc.desc: Test startTimer API handles string timerId parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call startTimer API with string timerId using Promise
     *           2. Verify operation fails with error code 401
     * @tc.expect: startTimer should reject with error code 401 when timerId parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerInvalidParam004', 0, async function (done) {
        console.log("testStartTimerInvalidParam004 start")
        try {
            systemTimer.startTimer("timerId").then(() => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testStartTimerInvalidParam004 end');
    });

    /**
     * @tc.number: TestStartTimerInvalidValue005
     * @tc.name: TestStartTimerInvalidValue005
     * @tc.desc: Test startTimer API handles invalid timerId value using Callback
     * @tc.precon: SystemTimer service is available and timer validation is enabled
     * @tc.step: 1. Call startTimer API with invalid timerId (123456) using Callback
     *           2. Verify operation fails as expected
     * @tc.expect: startTimer should return error when timerId value is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerInvalidValue005', 0, async function (done) {
        console.log("testStartTimerInvalidValue005 start")
        let triggerTime = new Date().getTime();
        triggerTime += 3000;
        systemTimer.startTimer(123456, triggerTime, function (err) {
            if (err) {
                expect(true).assertTrue();
            } else {
                expect(false).assertTrue();
            }
            done();
        });
        console.log('testStartTimerInvalidValue005 end');
    });

    /**
     * @tc.number: TestStartTimerInvalidValue006
     * @tc.name: TestStartTimerInvalidValue006
     * @tc.desc: Test startTimer API handles invalid timerId value using Promise
     * @tc.precon: SystemTimer service is available and timer validation is enabled
     * @tc.step: 1. Call startTimer API with invalid timerId (123456) using Promise
     *           2. Verify operation fails as expected
     * @tc.expect: startTimer should reject when timerId value is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerInvalidValue006', 0, async function (done) {
        console.log("testStartTimerInvalidValue006 start")
        try {
            let triggerTime = new Date().getTime();
            triggerTime += 300
            systemTimer.startTimer(123456, triggerTime).then(() => {
                expect(false).assertTrue();
                done();
            }).catch((e) => {
                expect(true).assertTrue();
                done();
            })
        } catch (err) {
            expect(true).assertTrue();
            done()
        }
        console.log('testStartTimerInvalidValue006 end');
    });

    /**
     * @tc.number: TestStartTimerInvalidValue007
     * @tc.name: TestStartTimerInvalidValue007
     * @tc.desc: Test startTimer API handles negative triggerTime value using Callback
     * @tc.precon: SystemTimer service is available and timer creation is supported
     * @tc.step: 1. Create valid timer
     *           2. Call startTimer API with triggerTime=-1 using Callback
     *           3. Verify operation succeeds and timer is destroyed
     * @tc.expect: startTimer should handle negative triggerTime value gracefully using callback
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerInvalidValue007', 0, async function (done) {
        console.log("testStartTimerInvalidValue007 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false
        }
        let timerId = await systemTimer.createTimer(options);
        systemTimer.startTimer(timerId, -1, function (err) {
            if (err) {
                expect(false).assertTrue();
            }
            expect(true).assertTrue();
            systemTimer.destroyTimer(timerId);
            done();
        });
        console.log('testStartTimerInvalidValue007 end');
    });

    /**
     * @tc.number: TestStartTimerInvalidValue008
     * @tc.name: TestStartTimerInvalidValue008
     * @tc.desc: Test startTimer API handles negative triggerTime value using Promise
     * @tc.precon: SystemTimer service is available and timer creation is supported
     * @tc.step: 1. Create valid timer
     *           2. Call startTimer API with triggerTime=-1 using Promise
     *           3. Verify operation succeeds
     * @tc.expect: startTimer should handle negative triggerTime value gracefully using promise
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerInvalidValue008', 0, async function (done) {
        console.log("testStartTimerInvalidValue008 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false
        }
        try {
            let timerId = await systemTimer.createTimer(options);
            systemTimer.startTimer(timerId, -1).then(() => {
                expect(true).assertTrue();
                done();
            }).catch((e) => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(false).assertTrue();
            done()
        }
        console.log('testStartTimerInvalidValue008 end');
    });

    /**
     * @tc.number: TestDestroyTimerInvalidParam001
     * @tc.name: TestDestroyTimerInvalidParam001
     * @tc.desc: Test destroyTimer API handles string timerId parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call destroyTimer API with string timerId using Callback
     *           2. Verify operation fails with error code 401
     * @tc.expect: destroyTimer should return error code 401 when timerId parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testDestroyTimerInvalidParam001', 0, async function (done) {
        console.log("testDestroyTimerInvalidParam001 start");
        try {
            systemTimer.destroyTimer("timerID", function (e) {
                expect(false).assertTrue();
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testDestroyTimerInvalidParam001 end');
    });

    /**
     * @tc.number: TestDestroyTimerInvalidParam002
     * @tc.name: TestDestroyTimerInvalidParam002
     * @tc.desc: Test destroyTimer API handles string timerId parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call destroyTimer API with string timerId using Promise
     *           2. Verify operation fails with error code 401
     * @tc.expect: destroyTimer should reject with error code 401 when timerId parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testDestroyTimerInvalidParam002', 0, async function (done) {
        console.log("testDestroyTimerInvalidParam002 start");
        try {
            systemTimer.destroyTimer("timerID").then(() => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log("testDestroyTimerInvalidParam002 end");
    });

    /**
     * @tc.number: TestDestroyTimerInvalidValue003
     * @tc.name: TestDestroyTimerInvalidValue003
     * @tc.desc: Test destroyTimer API handles invalid timerId value using Callback
     * @tc.precon: SystemTimer service is available and timer validation is enabled
     * @tc.step: 1. Call destroyTimer API with invalid timerId (123456) using Callback
     *           2. Verify operation fails as expected
     * @tc.expect: destroyTimer should return error when timerId value is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testDestroyTimerInvalidValue003', 0, async function (done) {
        console.log("testDestroyTimerInvalidValue003 start");
        try {
            systemTimer.destroyTimer(123456, timeErr(err, done));
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
        console.log('testDestroyTimerInvalidValue003 end');
    });

    /**
     * @tc.number: TestDestroyTimerInvalidValue004
     * @tc.name: TestDestroyTimerInvalidValue004
     * @tc.desc: Test destroyTimer API handles invalid timerId value using Promise
     * @tc.precon: SystemTimer service is available and timer validation is enabled
     * @tc.step: 1. Call destroyTimer API with invalid timerId (123456) using Promise
     *           2. Verify operation fails as expected
     * @tc.expect: destroyTimer should reject when timerId value is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testDestroyTimerInvalidValue004', 0, async function (done) {
        console.log("testDestroyTimerInvalidValue004 start");
        try {
            systemTimer.destroyTimer(123456).then(() => {
                expect(false).assertTrue();
                done();
            }).catch((e) => {
                expect(true).assertTrue();
                done();
            })
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
        console.log("testDestroyTimerInvalidValue004 end");
    });

    /**
     * @tc.number: TestStopTimerInvalidParam001
     * @tc.name: TestStopTimerInvalidParam001
     * @tc.desc: Test stopTimer API handles string timerId parameter using Promise
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call stopTimer API with string timerId using Promise
     *           2. Verify operation fails with error code 401
     * @tc.expect: stopTimer should reject with error code 401 when timerId parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStopTimerInvalidParam001', 0, async function (done) {
        try {
            systemTimer.stopTimer("timerID").then(() => {
                expect(false).assertTrue();
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    });

    /**
     * @tc.number: TestStopTimerInvalidParam002
     * @tc.name: TestStopTimerInvalidParam002
     * @tc.desc: Test stopTimer API handles string timerId parameter using Callback
     * @tc.precon: SystemTimer service is available and parameter validation is enabled
     * @tc.step: 1. Call stopTimer API with string timerId using Callback
     *           2. Verify operation fails with error code 401
     * @tc.expect: stopTimer should return error code 401 when timerId parameter is invalid string
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStopTimerInvalidParam002', 0, async function (done) {
        try {
            systemTimer.stopTimer("timerID", function (err) {
                expect(false).assertTrue();
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    });

    /**
     * @tc.number: TestStopTimerInvalidValue003
     * @tc.name: TestStopTimerInvalidValue003
     * @tc.desc: Test stopTimer API handles invalid timerId value using Callback
     * @tc.precon: SystemTimer service is available and timer validation is enabled
     * @tc.step: 1. Call stopTimer API with invalid timerId (123456) using Callback
     *           2. Verify operation fails as expected
     * @tc.expect: stopTimer should return error when timerId value is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStopTimerInvalidValue003', 0, async function (done) {
        try {
            systemTimer.stopTimer(123456, timeErr(err ,done));
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
    });

    /**
     * @tc.number: TestStopTimerInvalidValue004
     * @tc.name: TestStopTimerInvalidValue004
     * @tc.desc: Test stopTimer API handles invalid timerId value using Promise
     * @tc.precon: SystemTimer service is available and timer validation is enabled
     * @tc.step: 1. Call stopTimer API with invalid timerId (123456) using Promise
     *           2. Verify operation fails as expected
     * @tc.expect: stopTimer should reject when timerId value is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStopTimerInvalidValue004', 0, async function (done) {
        try {
            systemTimer.stopTimer(123456).then(() => {
                expect(false).assertTrue();
                done();
            }).catch((err) => {
                expect(true).assertTrue();
                done();
            })
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
    });
})