/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

describe('SystemTimerTest', function () {

    /**
     * @tc.number: TestCreateTimerNoPermission001
     * @tc.name: TestCreateTimerNoPermission001
     * @tc.desc: Test createTimer API returns error when called without required permission using Promise
     * @tc.precon: SystemTimer service is available and timer creation permissions are properly configured
     * @tc.step: 1. Prepare timer options with realtime type and non-repeat mode
     *           2. Call createTimer API using Promise without required permissions
     *           3. Catch the rejection and verify operation fails
     * @tc.expect: createTimer Promise call should reject when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerNoPermission001', 0, async function (done) {
        console.log("testCreateTimerNoPermission001 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        systemTimer.createTimer(options).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(true).assertTrue();
            done();
        })
        console.log('testCreateTimerNoPermission001 end');
    });

    /**
     * @tc.number: TestCreateTimerNoPermission002
     * @tc.name: TestCreateTimerNoPermission002
     * @tc.desc: Test createTimer API returns error when called without required permission using Callback
     * @tc.precon: SystemTimer service is available and timer creation permissions are properly configured
     * @tc.step: 1. Prepare timer options with realtime type and non-repeat mode
     *           2. Call createTimer API using Callback without required permissions
     *           3. Check error object and verify operation fails
     * @tc.expect: createTimer Callback should return error when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testCreateTimerNoPermission002', 0, async function (done) {
        console.log("testCreateTimerNoPermission002 start")
        let options = {
            type: systemTimer.TIMER_TYPE_REALTIME,
            repeat: false,
        }
        systemTimer.createTimer(options, (err) => {
            if (err) {
                expect(true).assertTrue();
            } else {
                expect(false).assertTrue();
            }
            done();
        })
        console.log('testCreateTimerNoPermission002 end');
    });

    /**
     * @tc.number: TestStartTimerNoPermission001
     * @tc.name: TestStartTimerNoPermission001
     * @tc.desc: Test startTimer API returns permission error when called without required permission using Callback
     * @tc.precon: SystemTimer service is available and timer operation permissions are properly configured
     * @tc.step: 1. Call startTimer API with timer ID and trigger time using Callback
     *           2. Verify the operation fails with error code 202 due to missing permissions
     * @tc.expect: startTimer Callback should return error with code 202 when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerNoPermission001', 0, async function (done) {
        console.log("testStartTimerNoPermission001 start")
        systemTimer.startTimer(123456, 123456, (err) => {
            if (err) {
                expect(err.code).assertEqual(202);
            } else {
                expect(false).assertTrue();
            }
            done();
        });
        console.log('testStartTimerNoPermission001 end');
    });

    /**
     * @tc.number: TestStartTimerNoPermission002
     * @tc.name: TestStartTimerNoPermission002
     * @tc.desc: Test startTimer API returns permission error when called without required permission using Promise
     * @tc.precon: SystemTimer service is available and timer operation permissions are properly configured
     * @tc.step: 1. Call startTimer API with timer ID and trigger time using Promise
     *           2. Catch the rejection and verify error code equals 202
     * @tc.expect: startTimer Promise call should reject with error code 202 when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStartTimerNoPermission002', 0, async function (done) {
        console.log("testStartTimerNoPermission002 start")
        systemTimer.startTimer(123456, 123456).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(err.code).assertEqual(202);
            done();
        })
        console.log('testStartTimerNoPermission002 end');
    });

    /**
     * @tc.number: TestDestroyTimerNoPermission001
     * @tc.name: TestDestroyTimerNoPermission001
     * @tc.desc: Test destroyTimer API returns permission error when called without required permission using Callback
     * @tc.precon: SystemTimer service is available and timer management permissions are properly configured
     * @tc.step: 1. Call destroyTimer API with timer ID using Callback
     *           2. Verify the operation fails with error code 202 due to missing permissions
     * @tc.expect: destroyTimer Callback should return error with code 202 when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testDestroyTimerNoPermission001', 0, async function (done) {
        console.log("testDestroyTimerNoPermission001 start");
        systemTimer.destroyTimer(123456, (err) => {
            if (err) {
                expect(err.code).assertEqual(202);
            } else {
                expect(false).assertTrue();
            }
            done();
        });
        console.log('testDestroyTimerNoPermission001 end');
    });

    /**
     * @tc.number: TestDestroyTimerNoPermission002
     * @tc.name: TestDestroyTimerNoPermission002
     * @tc.desc: Test destroyTimer API returns permission error when called without required permission using Promise
     * @tc.precon: SystemTimer service is available and timer management permissions are properly configured
     * @tc.step: 1. Call destroyTimer API with timer ID using Promise
     *           2. Catch the rejection and verify error code equals 202
     * @tc.expect: destroyTimer Promise call should reject with error code 202 when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testDestroyTimerNoPermission002', 0, async function (done) {
        console.log("testDestroyTimerNoPermission002 start");
        systemTimer.destroyTimer(123456).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(err.code).assertEqual(202);
            done();
        })
        console.log("testDestroyTimerNoPermission002 end");
    });

    /**
     * @tc.number: TestStopTimerNoPermission001
     * @tc.name: TestStopTimerNoPermission001
     * @tc.desc: Test stopTimer API returns permission error when called without required permission using Promise
     * @tc.precon: SystemTimer service is available and timer control permissions are properly configured
     * @tc.step: 1. Call stopTimer API with timer ID using Promise
     *           2. Catch the rejection and verify error code equals 202
     * @tc.expect: stopTimer Promise call should reject with error code 202 when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStopTimerNoPermission001', 0, async function (done) {
        console.log("testStopTimerNoPermission001 start");
        systemTimer.stopTimer(123456).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(err.code).assertEqual(202);
            done();
        })
        console.log("testStopTimerNoPermission001 end");
    });

    /**
     * @tc.number: TestStopTimerNoPermission002
     * @tc.name: TestStopTimerNoPermission002
     * @tc.desc: Test stopTimer API returns permission error when called without required permission using Callback
     * @tc.precon: SystemTimer service is available and timer control permissions are properly configured
     * @tc.step: 1. Call stopTimer API with timer ID using Callback
     *           2. Verify the operation fails with error code 202 due to missing permissions
     * @tc.expect: stopTimer Callback should return error with code 202 when permissions are missing
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testStopTimerNoPermission002', 0, async function (done) {
        console.log("testStopTimerNoPermission002 start");
        systemTimer.stopTimer(123456, function (err) {
            if (err) {
                expect(err.code).assertEqual(202);
            } else {
                expect(false).assertTrue();
            }
            done();
        });
        console.log("testStopTimerNoPermission002 end");
    });
})