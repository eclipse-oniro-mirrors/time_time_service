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
     * @tc.name: TestSetTime001
     * @tc.desc: Test setTime for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTime002
     * @tc.desc: Test setTime for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimeInvalidValue003
     * @tc.desc: Test setTime for promise with invalid value.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimeInvalidValue004
     * @tc.desc: Test setTime for callback with invalid value.
     * @tc.type: Function
     * @tc.require:
     */
    it("testSetTimeInvalidValue004", 0, async function (done) {
        console.log("testSetTimeInvalidValue004 start");
        let time = 10451042204000;
        systemDateTime.setTime(time, (err) => {
            if (err) {
                expect(true).assertTrue();
                done();
            } else {
                expect(false).assertTrue();
                done();
            }
        })
        console.log("testSetTimeInvalidValue004 end");
    });

    /**
     * @tc.name: TestSetTimeInvalidParam005
     * @tc.desc: Test setTime for promise with invalid param.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimeInvalidParam006
     * @tc.desc: Test setTime for callback with invalid param.
     * @tc.type: Function
     * @tc.require:
     */
    it("testSetTimeInvalidParam006", 0, async function (done) {
        console.log("testSetTimeInvalidParam006 start");
        try {
            systemDateTime.setTime("time", (err) => {
                if (err) {
                    expect(err.code).assertEqual(401);
                    done();
                } else {
                    expect(false).assertTrue();
                    done();
                }
            })
        } catch (err) {
            expect(err.code).assertEqual(401);
            done();
        }
        console.log("testSetTimeInvalidParam006 end");
    });

    /**
     * @tc.name: TestSetTimeInvalidValue007
     * @tc.desc: Test setTime for callback with invalid value.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimeInvalidValue008
     * @tc.desc: Test setTime for callback with invalid value.
     * @tc.type: Function
     * @tc.require:
     */
    it("testSetTimeInvalidValue008", 0, async function (done) {
        console.log("testSetTimeInvalidValue008 start");
        systemDateTime.setTime(-1, (err) => {
            if (err) {
                expect(err.code).assertEqual(undefined);
                done();
            } else {
                expect(false).assertTrue();
                done();
            }
        })
        console.log("testSetTimeInvalidValue008 end");
    });

    /**
     * @tc.name: TestSetDate001
     * @tc.desc: Test setDate for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetDate002
     * @tc.desc: Test setDate for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetDateNull001
     * @tc.desc: Test setDate for promise with null.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetDateNull002
     * @tc.desc: Test setDate for callback with null.
     * @tc.type: Function
     * @tc.require:
     */
    it("testSetDateNull002", 0, async function (done) {
        try {
            systemDateTime.setDate(null, (err) => {
                if (err) {
                    expect(true).assertTrue();
                    done()
                } else {
                    expect(false).assertTrue();
                    done();
                }
            })
        } catch (err) {
            expect(true).assertTrue();
            done();
        }
    });

    /**
     * @tc.name: TestSetTimezone001
     * @tc.desc: Test setDate for promise.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimezone002
     * @tc.desc: Test setDate for callback.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimezoneNull003
     * @tc.desc: Test setDate for promise with null.
     * @tc.type: Function
     * @tc.require:
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
     * @tc.name: TestSetTimezoneNull004
     * @tc.desc: Test setDate for callback with null.
     * @tc.type: Function
     * @tc.require:
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
})