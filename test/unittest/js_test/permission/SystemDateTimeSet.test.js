/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// @ts-nocheck
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import systemDateTime from '@ohos.systemDateTime'

let timezone = ["Antarctica/McMurdo", "America/Argentina/Buenos_Aires", "Australia/Sydney", "America/Noronha",
    "America/St_Johns", "Africa/Kinshasa", "America/Santiago", "Europe/Lisbon", "Asia/Nicosia", "Europe/Berlin",
    "America/Guayaquil", "Europe/Madrid", "Pacific/Pohnpei", "Asia/Jakarta", "Pacific/Tarawa", "Asia/Almaty",
    "Pacific/Majuro", "Asia/Ulaanbaatar", "America/Mexico_City", "Asia/Kuala_Lumpur", "Pacific/Auckland",
    "Pacific/Tahiti", "Pacific/Port_Moresby", "Asia/Gaza", "Europe/Moscow", "Europe/Kiev", "Pacific/Wake", "America/New_York",
    "Asia/Tashkent", "Asia/Shanghai"
]

describe("SystemDateTimeSetTest", function () {

    /**
     * @tc.number: TestSetTime001
     * @tc.name: TestSetTime001
     * @tc.desc: Test setTime API sets system time correctly using Promise with valid timestamp
     * @tc.precon: SystemDateTime service is available and time setting permission is granted
     * @tc.step: 1. Call setTime API with valid timestamp (123235423411) using Promise
     *           2. Verify the operation completes successfully without errors
     * @tc.expect: setTime should successfully set system time with valid timestamp using Promise
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTime001", 0,function (done) {
        console.log("testSetTime001 start");
        systemDateTime.setTime(123235423411).then(() => {
            expect(true).assertTrue();
            done();
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
        console.log("testSetTime001 end");
    });

    /**
     * @tc.number: TestSetTime002
     * @tc.name: TestSetTime002
     * @tc.desc: Test setTime API sets system time correctly using Callback with valid timestamp
     * @tc.precon: SystemDateTime service is available and time setting permission is granted
     * @tc.step: 1. Call setTime API with valid timestamp (123235423411) using Callback
     *           2. Verify the operation completes successfully without errors
     * @tc.expect: setTime should successfully set system time with valid timestamp using Callback
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTime002", 0, async function (done) {
        console.log("testSetTime002 start");
        let time = 123235423411;
        systemDateTime.setTime(time, (err) => {
            if (err) {
                expect(false).assertTrue();
            }
            expect(true).assertTrue();
            done();
        })
        console.log("testSetTime002 end");
    });

    /**
     * @tc.number: TestSetTimeInvalidValue003
     * @tc.name: TestSetTimeInvalidValue003
     * @tc.desc: Test setTime API handles excessively large timestamp using Promise
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTime API with excessively large timestamp (10451042204000) using Promise
     *           2. Verify the operation fails as expected
     * @tc.expect: setTime should reject Promise when timestamp value is excessively large
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimeInvalidValue003", 0, async function (done) {
        console.log("testSetTimeInvalidValue003 start");
        let time = 10451042204000;
        systemDateTime.setTime(time).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(true).assertTrue();
            done();
        })
        console.log("testSetTimeInvalidValue003 end");
    });

    /**
     * @tc.number: TestSetTimeInvalidValue004
     * @tc.name: TestSetTimeInvalidValue004
     * @tc.desc: Test setTime API handles excessively large timestamp using Callback
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTime API with excessively large timestamp (10451042204000) using Callback
     *           2. Verify the operation fails as expected
     * @tc.expect: setTime callback should return error when timestamp value is excessively large
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimeInvalidValue004", 0, async function (done) {
        console.log("testSetTimeInvalidValue004 start");
        let time = 10451042204000;
        systemDateTime.setTime(time, (err) => {
            if (err) {
                expect(true).assertTrue();
            } else {
                expect(false).assertTrue();
            }
            done();
        })
        console.log("testSetTimeInvalidValue004 end");
    });

    /**
     * @tc.number: TestSetTimeInvalidParam005
     * @tc.name: TestSetTimeInvalidParam005
     * @tc.desc: Test setTime API handles string parameter using Promise
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTime API with string parameter "time" using Promise
     *           2. Verify the operation fails with error code 401
     * @tc.expect: setTime should reject Promise with error code 401 when parameter type is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimeInvalidParam005", 0, async function (done) {
        console.log("testSetTimeInvalidParam005 start");
        try {
            systemDateTime.setTime("time").then(() => {
                expect(false).assertTrue();
                done();
            }).catch((err) => {
                expect(err.code).assertEqual(401);
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log("testSetTimeInvalidParam005 end");
    });

    /**
     * @tc.number: TestSetTimeInvalidParam006
     * @tc.name: TestSetTimeInvalidParam006
     * @tc.desc: Test setTime API handles string parameter using Callback
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTime API with string parameter "time" using Callback
     *           2. Verify the operation fails with error code 401
     * @tc.expect: setTime callback should return error code 401 when parameter type is invalid
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimeInvalidParam006", 0, async function (done) {
        console.log("testSetTimeInvalidParam006 start");
        try {
            systemDateTime.setTime("time", (err) => {
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
        console.log("testSetTimeInvalidParam006 end");
    });

    /**
     * @tc.number: TestSetTimeInvalidValue007
     * @tc.name: TestSetTimeInvalidValue007
     * @tc.desc: Test setTime API handles negative timestamp using Promise
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTime API with negative timestamp (-1) using Promise
     *           2. Verify the operation fails with undefined error code
     * @tc.expect: setTime should reject Promise when timestamp value is negative
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimeInvalidValue007", 0, async function (done) {
        console.log("testSetTimeInvalidValue007 start");
        systemDateTime.setTime(-1).then(() => {
            expect(false).assertTrue();
            done();
        }).catch((err) => {
            expect(err.code).assertEqual(undefined);
            done();
        })
        console.log("testSetTimeInvalidValue007 end");
    });

    /**
     * @tc.number: TestSetTimeInvalidValue008
     * @tc.name: TestSetTimeInvalidValue008
     * @tc.desc: Test setTime API handles negative timestamp using Callback
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTime API with negative timestamp (-1) using Callback
     *           2. Verify the operation fails with undefined error code
     * @tc.expect: setTime callback should return error when timestamp value is negative
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimeInvalidValue008", 0, async function (done) {
        console.log("testSetTimeInvalidValue008 start");
        systemDateTime.setTime(-1, (err) => {
            if (err) {
                expect(err.code).assertEqual(undefined);
            } else {
                expect(false).assertTrue();
            }
            done();
        })
        console.log("testSetTimeInvalidValue008 end");
    });

    /**
     * @tc.number: TestSetDate001
     * @tc.name: TestSetDate001
     * @tc.desc: Test setDate API sets system date correctly using Promise
     * @tc.precon: SystemDateTime service is available and date setting permission is granted
     * @tc.step: 1. Set current date using setDate API with Promise
     *           2. Retrieve current date using getDate API
     *           3. Verify the set date matches the retrieved date
     * @tc.expect: setDate should successfully set system date and getDate should return matching date
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetDate001", 0, async function (done) {
        let date = new Date();
        systemDateTime.setDate(date).then(() => {
            systemDateTime.getDate().then((data) => {
                expect(date.toDateString() === data.toDateString()).assertTrue();
                done();
            }).catch((err) => {
                expect(false).assertTrue();
                done();
            });
        }).catch((err) => {
            expect(false).assertTrue();
            done();
        })
    });

    /**
     * @tc.number: TestSetDate002
     * @tc.name: TestSetDate002
     * @tc.desc: Test setDate API sets system date correctly using Callback
     * @tc.precon: SystemDateTime service is available and date setting permission is granted
     * @tc.step: 1. Set current date using setDate API with Callback
     *           2. Retrieve current date using getDate API
     *           3. Verify the set date matches the retrieved date
     * @tc.expect: setDate should successfully set system date and getDate should return matching date using Callback
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetDate002", 0, async function (done) {
        let date = new Date();
        systemDateTime.setDate(date, (err) => {
            if (err) {
                expect(false).assertTrue();
                done();
            }
            systemDateTime.getDate().then((data) => {
                expect(date.toDateString() === data.toDateString()).assertTrue();
                done();
            }).catch((err) => {
                expect(false).assertTrue();
                done();
            });
        });
    });

    /**
     * @tc.number: TestSetDateNull001
     * @tc.name: TestSetDateNull001
     * @tc.desc: Test setDate API handles null parameter using Promise
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setDate API with null parameter using Promise
     *           2. Verify the operation fails with error code 401
     * @tc.expect: setDate should reject Promise with error code 401 when parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetDateNull001", 0, async function (done) {
        try {
            systemDateTime.setDate(null).then(() => {
                expect(false).assertTrue();
                done();
            }).catch((err) => {
                expect(err.code).assertEqual(401);
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    });

    /**
     * @tc.number: TestSetDateNull002
     * @tc.name: TestSetDateNull002
     * @tc.desc: Test setDate API handles null parameter using Callback
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setDate API with null parameter using Callback
     *           2. Verify the operation fails as expected
     * @tc.expect: setDate callback should return error when parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetDateNull002", 0, async function (done) {
        try {
            systemDateTime.setDate(null, (err) => {
                if (err) {
                    expect(true).assertTrue();
                } else {
                    expect(false).assertTrue();
                }
                done();
            })
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
    });

    /**
     * @tc.number: TestSetTimezone001
     * @tc.name: TestSetTimezone001
     * @tc.desc: Test setTimezone API sets multiple timezones correctly using Promise
     * @tc.precon: SystemDateTime service is available and timezone setting permission is granted
     * @tc.step: 1. Iterate through predefined timezone list
     *           2. Set each timezone using setTimezone API with Promise
     *           3. Verify all timezone settings complete successfully
     * @tc.expect: setTimezone should successfully set all valid timezones in the list using Promise
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimezone001", 0, async function (done) {
        function calLoop(index) {
            if (index >= timezone.length - 1) {
                expect(true).assertTrue();
                done();
            }
        }
        for (let i = 0; i < timezone.length; i++) {
            systemDateTime.setTimezone(timezone[i]).then(() => {
                calLoop(i)
            }).catch((err) => {
                expect(false).assertTrue();
                done();
            });
        }
    });

    /**
     * @tc.number: TestSetTimezone002
     * @tc.name: TestSetTimezone002
     * @tc.desc: Test setTimezone API sets multiple timezones correctly using Callback
     * @tc.precon: SystemDateTime service is available and timezone setting permission is granted
     * @tc.step: 1. Iterate through predefined timezone list
     *           2. Set each timezone using setTimezone API with Callback
     *           3. Verify all timezone settings complete successfully
     * @tc.expect: setTimezone should successfully set all valid timezones in the list using Callback
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimezone002", 0, async function (done) {
        for (let i = 0; i < timezone.length; i++) {
            systemDateTime.setTimezone(timezone[i], (err) => {
                if (err) {
                    expect(false).assertTrue();
                }
            })
        }
        expect(true).assertTrue();
        done();
    });

    /**
     * @tc.number: TestSetTimezoneNull003
     * @tc.name: TestSetTimezoneNull003
     * @tc.desc: Test setTimezone API handles null parameter using Promise
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTimezone API with null parameter using Promise
     *           2. Verify the operation fails with error code 401
     * @tc.expect: setTimezone should reject Promise with error code 401 when parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimezoneNull003", 0, async function (done) {
        try {
            systemDateTime.setTimezone(null).then(() => {
                expect(false).assertTrue();
                done();
            }).catch((err) => {
                expect(err.code).assertEqual(401);
                done();
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    });

    /**
     * @tc.number: TestSetTimezoneNull004
     * @tc.name: TestSetTimezoneNull004
     * @tc.desc: Test setTimezone API handles null parameter using Callback
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setTimezone API with null parameter using Callback
     *           2. Verify the operation fails with error code 401
     * @tc.expect: setTimezone callback should return error code 401 when parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetTimezoneNull004", 0, async function (done) {
        try {
            systemDateTime.setTimezone(null, (err) => {
                if (err) {
                    expect(err.code).assertEqual(401);
                } else {
                    expect(false).assertTrue();
                }
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
    });

    /**
     * @tc.number: TestSetTimezoneNonsupport005
     * @tc.name: TestSetTimezoneNonsupport005
     * @tc.desc: Test setTimezone API handles unsupported timezone using Promise
     * @tc.precon: SystemDateTime service is available and timezone validation is enabled
     * @tc.step: 1. Call setTimezone API with unsupported timezone 'Asia/Hangzhou' using Promise
     *           2. Verify the operation fails as expected
     * @tc.expect: setTimezone should reject Promise when timezone is not supported
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("TestSetTimezoneNonsupport005", 0, async function (done) {
        console.log("TestSetTimezoneNonsupport005 start");
        try {
            systemDateTime.setTimezone('Asia/Hangzhou').then(() => {
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
        console.log("TestSetTimezoneNonsupport005 end");
    });

    /**
     * @tc.number: TestSetTimezoneNonsupport006
     * @tc.name: TestSetTimezoneNonsupport006
     * @tc.desc: Test setTimezone API handles unsupported timezone using Callback
     * @tc.precon: SystemDateTime service is available and timezone validation is enabled
     * @tc.step: 1. Call setTimezone API with unsupported timezone 'Asia/Hangzhou' using Callback
     *           2. Verify the operation fails as expected
     * @tc.expect: setTimezone callback should return error when timezone is not supported
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("TestSetTimezoneNonsupport006", 0, async function (done) {
        console.log("TestSetTimezoneNonsupport006 start");
        try {
            systemDateTime.setTimezone('Asia/Hangzhou', (err) => {
                if (err) {
                    expect(true).assertTrue();
                    console.log(err.code);
                } else {
                    expect(false).assertTrue();
                }
                done();
            });
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
        console.log("TestSetTimezoneNonsupport006 end");
    });

    /**
     * @tc.number: TestSetAutoTime001
     * @tc.name: TestSetAutoTime001
     * @tc.desc: Test setAutoTimeStatus API disables auto time and verifies status using getAutoTimeStatus
     * @tc.precon: SystemDateTime service is available and auto time configuration is accessible
     * @tc.step: 1. Set auto time status to false using setAutoTimeStatus API
     *           2. Retrieve auto time status using getAutoTimeStatus API
     *           3. Verify status is correctly set to false
     * @tc.expect: Auto time status should be successfully set to false and correctly retrieved
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testSetAutoTime001', 0, async function (done) {
        console.log("testSetAutoTime001 start");
        await systemDateTime.setAutoTimeStatus(false);
        const autoTimeStatus = systemDateTime.getAutoTimeStatus();
        expect(!autoTimeStatus).assertTrue();
        done();
        console.log('testSetAutoTime001 end');
    })

    /**
     * @tc.number: TestSetAutoTime002
     * @tc.name: TestSetAutoTime002
     * @tc.desc: Test setAutoTimeStatus API enables auto time and verifies status using getAutoTimeStatus
     * @tc.precon: SystemDateTime service is available and auto time configuration is accessible
     * @tc.step: 1. Set auto time status to true using setAutoTimeStatus API
     *           2. Retrieve auto time status using getAutoTimeStatus API
     *           3. Verify status is correctly set to true
     * @tc.expect: Auto time status should be successfully set to true and correctly retrieved
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it('testSetAutoTime002', 0, async function (done) {
        console.log("testSetAutoTime002 start");
        await systemDateTime.setAutoTimeStatus(true);
        const autoTimeStatus = systemDateTime.getAutoTimeStatus();
        expect(autoTimeStatus).assertTrue();
        done();
        console.log('testSetAutoTime002 end');
    })

    /**
     * @tc.number: TestSetAutoTime003
     * @tc.name: TestSetAutoTime003
     * @tc.desc: Test setAutoTimeStatus API handles null parameter using Callback
     * @tc.precon: SystemDateTime service is available and parameter validation is enabled
     * @tc.step: 1. Call setAutoTimeStatus API with null parameter using Callback
     *           2. Verify the operation fails with error code 401
     * @tc.expect: setAutoTimeStatus should return error code 401 when parameter is null
     * @tc.size: MediumTest
     * @tc.type: Function
     * @tc.level: Level1
     * @tc.require: issue#844
     */
    it("testSetAutoTime003", 0, async function (done) {
        console.log("testSetAutoTime003 start");
        try {
            systemDateTime.setAutoTimeStatus(null, (err) => {
                if (err) {
                    expect(err.code).assertEqual(401);
                } else {
                    expect(false).assertTrue();
                }
                done();
            });
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log('testSetAutoTime003 end')
    })
})