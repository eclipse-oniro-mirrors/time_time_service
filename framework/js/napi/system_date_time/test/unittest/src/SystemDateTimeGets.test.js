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

describe('TimeTest', function () {
    const MILLI_TO_BASE = 1000;
    const NANO_TO_BASE = 1000000000;
    const NANO_TO_MILLI = NANO_TO_BASE / MILLI_TO_BASE;

    beforeAll(async function () {
        console.info('beforeAll')
    })

    afterAll(async function () {
        console.info('afterAll')
    })

    /**
     * @tc.number    systemDateTime_getCurrentTime_test1
     * @tc.name      Test systemDateTime.getCurrentTime Invalid value
     * @tc.desc      Test systemDateTime_getCurrentTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getCurrentTime_test1', 0, async function (done) {
        console.log("systemDateTime_getCurrentTime_test1 start");

        const nowTime = new Date().getTime();

        const milliTime = await systemDateTime.getCurrentTime();
        console.log('Get current time is ' + milliTime);

        expect(milliTime > nowTime).assertTrue;
        expect((milliTime - nowTime) < 500).assertTrue;

        console.log('systemDateTime_getCurrentTime_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getCurrentTime_Nano_test1
     * @tc.name      Test systemDateTime.getCurrentTime Invalid value
     * @tc.desc      Test systemDateTime_getCurrentTime API functionality with nano.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getCurrentTime_Nano_test1', 0, async function (done) {
        console.log("systemDateTime_getCurrentTime_Nano_test1 start");

        const nowTime = new Date().getTime();

        const nanoTime = await systemDateTime.getCurrentTime(true);
        console.log('Get current nano time is ' + nanoTime);

        const milliTime = nanoTime / NANO_TO_MILLI;

        expect(milliTime > nowTime).assertTrue;
        expect((milliTime - nowTime) < 500).assertTrue;

        console.log('systemDateTime_getCurrentTime_Nano_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getCurrentTime_test1
     * @tc.name      Test systemDateTime.getCurrentTime Invalid value
     * @tc.desc      Test systemDateTime_getCurrentTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getRealActiveTime_test1', 0, async function (done) {
        console.log("systemDateTime_getRealActiveTime_test1 start");

        const milliTime = await systemDateTime.getRealActiveTime();
        console.log('Get real active time is ' + milliTime);

        expect(milliTime / MILLI_TO_BASE > 0).assertTrue;

        console.log('systemDateTime_getRealActiveTime_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getRealActiveTime_Nano_test1
     * @tc.name      Test systemDateTime.getRealActiveTime Invalid value
     * @tc.desc      Test systemDateTime_getRealActiveTime API functionality with nano.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getRealActiveTime_Nano_test1', 0, async function (done) {
        console.log("systemDateTime_getRealActiveTime_Nano_test1 start");

        const nanoTime = await systemDateTime.getRealActiveTime(true);
        console.log('Get real active nano time is ' + nanoTime);

        expect(nanoTime / NANO_TO_BASE > 0).assertTrue;

        console.log('systemDateTime_getRealActiveTime_Nano_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getRealTime_test1
     * @tc.name      Test systemDateTime.getRealTime Invalid value
     * @tc.desc      Test systemDateTime_getRealTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getRealTime_test1', 0, async function (done) {
        console.log("systemDateTime_getRealTime_test1 start");

        const milliTime = await systemDateTime.getRealTime();
        console.log('Get real time is ' + milliTime);

        expect(milliTime / MILLI_TO_BASE > 0).milliTime;

        console.log('systemDateTime_getRealTime_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getRealTime_test1
     * @tc.name      Test systemDateTime.getRealTime Invalid value
     * @tc.desc      Test systemDateTime_getRealTime API functionality with nano.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getRealTime_Nano_test1', 0, async function (done) {
        console.log("systemDateTime_getRealTime_Nano_test1 start");

        const nanoTime = await systemDateTime.getRealTime(true);
        console.log('Get real nano time is ' + nanoTime);

        expect(nanoTime / NANO_TO_BASE > 0).assertTrue;

        console.log('systemDateTime_getRealTime_Nano_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getDate_test1
     * @tc.name      Test systemDateTime.getDate Invalid value
     * @tc.desc      Test systemDateTime_getDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getDate_test1', 0, async function (done) {
        console.log("systemDateTime_getDate_test1 start");

        const nowTime = new Date().getTime();

        const date = await systemDateTime.getDate();
        const milliTime = date.getTime();
        expect(milliTime > nowTime).assertTrue;
        expect((milliTime - nowTime) < 500).assertTrue;

        console.log('systemDateTime_getDate_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getCurrentTime_401_test1
     * @tc.name      Test systemDateTime.getCurrentTime Invalid value
     * @tc.desc      Test systemDateTime_getCurrentTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getCurrentTime_401_test1', 0, async function (done) {
        console.log("systemDateTime_getCurrentTime_401_test1 start");

        try {
            systemDateTime.getCurrentTime("true", function (err) {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info(err.code);
            expect(err.code).assertEqual(401);
        }

        try {
            systemDateTime.getCurrentTime("true").then((time) => {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info(err.code);
            expect(err.code).assertEqual(401);
        }
        console.log('systemDateTime_getCurrentTime_401_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getCurrentTime_401_test1
     * @tc.name      Test systemDateTime.getCurrentTime Invalid value
     * @tc.desc      Test systemDateTime_getCurrentTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getRealActiveTime_401_test1', 0, async function (done) {
        console.log("systemDateTime_getRealActiveTime_401_test1 start");

        try {
            systemDateTime.getRealActiveTime("true", function (err) {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info(err.code);
            expect(err.code).assertEqual(401);
        }

        try {
            systemDateTime.getRealActiveTime("true").then((time) => {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info(err.code);
            expect(err.code).assertEqual(401);
        }
        console.log('systemDateTime_getRealActiveTime_401_test1 end');
        done();
    })

    /**
     * @tc.number    systemDateTime_getRealTime_401_test1
     * @tc.name      Test systemDateTime.getRealTime Invalid value
     * @tc.desc      Test systemDateTime_getRealTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it('systemDateTime_getRealTime_401_test1', 0, async function (done) {
        console.log("systemDateTime_getRealTime_401_test1 start");

        try {
            systemDateTime.getRealTime("true", function (err) {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info(err.code);
            expect(err.code).assertEqual(401);
        }

        try {
            systemDateTime.getRealTime("true").then((time) => {
                expect(false).assertTrue();
            });
        } catch (err) {
            console.info(err.code);
            expect(err.code).assertEqual(401);
        }
        console.log('systemDateTime_getRealTime_401_test1 end');
        done();
    })
})