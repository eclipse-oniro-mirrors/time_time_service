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
import systemDateTime from '@ohos.systemDateTime'

describe('SystemDateTimeTest', function () {

    /**
     * @tc.number: TestSetTimeNoPermission001
     * @tc.name: TestSetTimeNoPermission001
     * @tc.desc: Test setTime no permission for promise
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testSetTimeNoPermission001', 0, async function (done) {
        console.log("testSetTimeNoPermission001 start");
        const nowTime = new Date().getTime();
        systemDateTime.setTime(nowTime).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(err.code).assertEqual(202);
            done();
        })
        console.log('testSetTimeNoPermission001 end');
    })

    /**
     * @tc.number: TestSetTimeNoPermission002
     * @tc.name: TestSetTimeNoPermission002
     * @tc.desc: Test setTime no permission for callback
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testSetTimeNoPermission002', 0, async function (done) {
        console.log("testSetTimeNoPermission002 start");
        const nowTime = new Date().getTime();
        systemDateTime.setTime(nowTime, (err) => {
            if (err) {
                expect(err.code).assertEqual(202);
            } else {
                expect(false).assertTrue();
            }
            done();
        })
        console.log('testSetTimeNoPermission002 end');
    })

    /**
     * @tc.number: TestSetTimezoneNoPermission001
     * @tc.name: TestSetTimezoneNoPermission001
     * @tc.desc: Test setTimezone no permission for promise
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testSetTimezoneNoPermission001', 0, async function (done) {
        console.log("testSetTimezoneNoPermission001 start");
        const timezone = "Antarctica/McMurdo";
        systemDateTime.setTimezone(timezone).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(err.code).assertEqual(202);
            done();
        })
        console.log('testSetTimezoneNoPermission001 end');
    })

    /**
     * @tc.number: TestSetTimezoneNoPermission002
     * @tc.name: TestSetTimezoneNoPermission002
     * @tc.desc: Test setTimezone no permission for callback
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level 1
     * @tc.require:
     */
    it('testSetTimezoneNoPermission002', 0, async function (done) {
        console.log("testSetTimezoneNoPermission002 start");
        const timezone = "Antarctica/McMurdo";
        systemDateTime.setTimezone(timezone, (err) => {
            if (err) {
                expect(err.code).assertEqual(202);
            } else {
                expect(false).assertTrue();
            }
            done();
        })
        console.log('testSetTimezoneNoPermission002 end');
    })
})