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
// @ts-nocheck
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import systemTime from '@ohos.systemTime'

describe("TimeTest", function () {
    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0100
     * @tc.name      Test systemTime.setTimezone timezone = 'Antarctica/McMurdo'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test1", 0, async function (done) {
        var timezone = "Antarctica/McMurdo";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0200
     * @tc.name      Test systemTime.setTimezone timezone = 'America/Argentina/Buenos_Aires'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test2", 0, async function (done) {
        var timezone = "America/Argentina/Buenos_Aires";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0300
     * @tc.name      Test systemTime.setTimezone timezone = 'Australia/Sydney'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test3", 0, async function (done) {
        var timezone = "Australia/Sydney";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0400
     * @tc.name      Test systemTime.setTimezone timezone = 'America/Noronha'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test4", 0, async function (done) {
        var timezone = "America/Noronha";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0500
     * @tc.name      Test systemTime.setTimezone timezone = 'Beijing, China'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test5", 0, async function (done) {
        var timezone = "America/St_Johns";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0600
     * @tc.name      Test systemTime.setTimezone timezone = 'Africa/Kinshasa'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test6", 0, async function (done) {
        var timezone = "Africa/Kinshasa";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0700
     * @tc.name      Test systemTime.setTimezone timezone = 'America/Santiago'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test7", 0, async function (done) {
        var timezone = "America/Santiago";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0800
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Shanghai'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test8", 0, async function (done) {
        var timezone = "Asia/Shanghai";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_0900
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Nicosia'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test9", 0, async function (done) {
        var timezone = "Asia/Nicosia";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1000
     * @tc.name      Test systemTime.setTimezone timezone = 'Europe/Berlin'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test10", 0, async function (done) {
        var timezone = "Europe/Berlin";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1100
     * @tc.name      Test systemTime.setTimezone timezone = 'America/Guayaquil'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test11", 0, async function (done) {
        var timezone = "America/Guayaquil";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });
    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1200
     * @tc.name      Test systemTime.setTimezone timezone = 'Europe/Madrid'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test12", 0, async function (done) {
        var timezone = "Europe/Madrid";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1300
     * @tc.name      Test systemTime.setTimezone timezone = 'Pacific/Pohnpei'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test13", 0, async function (done) {
        var timezone = "Pacific/Pohnpei";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1400
     * @tc.name      Test systemTime.setTimezone timezone = 'America/Godthab'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test14", 0, async function (done) {
        var timezone = "America/Godthab";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1500
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Jakarta'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test15", 0, async function (done) {
        var timezone = "Asia/Jakarta";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1600
     * @tc.name      Test systemTime.setTimezone timezone = 'Pacific/Tarawa'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test16", 0, async function (done) {
        var timezone = "Pacific/Tarawa";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1700
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Almaty'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test17", 0, async function (done) {
        var timezone = "Asia/Almaty";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1800
     * @tc.name      Test systemTime.setTimezone timezone = 'Pacific/Majuro'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test18", 0, async function (done) {
        var timezone = "Pacific/Majuro";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_1900
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Ulaanbaatar'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test19", 0, async function (done) {
        var timezone = "Asia/Ulaanbaatar";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2000
     * @tc.name      Test systemTime.setTimezone timezone = 'America/Mexico_City'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test20", 0, async function (done) {
        var timezone = "America/Mexico_City";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2100
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Kuala_Lumpur'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test21", 0, async function (done) {
        var timezone = "Asia/Kuala_Lumpur";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2200
     * @tc.name      Test systemTime.setTimezone timezone = 'Pacific/Auckland'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test22", 0, async function (done) {
        var timezone = "Pacific/Auckland";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2300
     * @tc.name      Test systemTime.setTimezone timezone = 'Pacific/Tahiti'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test23", 0, async function (done) {
        var timezone = "Pacific/Tahiti";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2400
     * @tc.name      Test systemTime.setTimezone timezone = 'Pacific/Port_Moresby'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test24", 0, async function (done) {
        var timezone = "Pacific/Port_Moresby";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2500
     * @tc.name      Test systemTime.setTimezone timezone = 'Asia/Gaza'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test25", 0, async function (done) {
        var timezone = "Asia/Gaza";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });
    });

    /**
     * @tc.number    SUB_systemTime_setTimezone_JS_API_2600
     * @tc.name      Test systemTime.setTimezone timezone = 'Europe/Lisbon'
     * @tc.desc      Test systemTime_setTimezone API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTimezone_test26", 0, async function (done) {
        var timezone = "Asia/Shanghai";
        systemTime.setTimezone(timezone).then(() => {
            systemTime.getTimezone().then((data) => {
                expect(data).assertEqual(timezone);
                done();
            });
        });

    });

    /**
     * @tc.number    SUB_systemTime_setTime_JS_API_0100
     * @tc.name      Test systemTime.setTime time = 123235423411
     * @tc.desc      Test systemTime_setTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTime_test1", 0, async function (done) {
        let time = 123235423411;
        try {
            systemTime.setTime(time).then(() => {
                systemTime.getCurrentTime(false).then((data) => {
                    expect(data >= time).assertTrue();
                    done();
                }).catch((err) => {
                    expect(false).assertTrue();
                    done();
                });
            }).catch((err) => {
                expect(false).assertTrue();
                done();
            })
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setTime_JS_API_0200
     * @tc.name      Test systemTime.setTime time = 1
     * @tc.desc      Test systemTime_setTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setTime_test2", 0, async function (done) {
        let time = 1;
        try {
            systemTime.setTime(time).then(() => {
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
        console.log("SUB_systemTime_setTime_JS_API_0200 end");
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0100
     * @tc.name      Test systemTime.setDate date = new Date()
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test1", 0, async function (done) {
        let date = new Date();
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0200
     * @tc.name      Test systemTime.setDate date = new Date(2022,1,1)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test2", 0, async function (done) {
        let date = new Date(2022, 1, 1);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0300
     * @tc.name      Test systemTime.setDate date = new Date(2022,1,15)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test3", 0, async function (done) {
        let date = new Date(2022, 1, 15);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0400
     * @tc.name      Test systemTime.setDate date = new Date(2022,1,31)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test4", 0, async function (done) {
        let date = new Date(2022, 1, 31);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0500
     * @tc.name      Test systemTime.setDate date = new Date(2022,2,1)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test5", 0, async function (done) {
        let date = new Date(2022, 2, 1);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });
    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0600
     * @tc.name      Test systemTime.setDate date = new Date(2022,2,28)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test6", 0, async function (done) {
        let date = new Date(2022, 2, 28);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
        done();
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0700
     * @tc.name      Test systemTime.setDate date = new Date(2040,2,28)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test7", 0, async function (done) {
        let date = new Date(2040, 2, 28);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0800
     * @tc.name      Test systemTime.setDate date = new Date(2040,2,29)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test8", 0, async function (done) {
        let date = new Date(2040, 2, 29);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_0900
     * @tc.name      Test systemTime.setDate date = new Date(2022,6,30)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test9", 0, async function (done) {
        let date = new Date(2022, 6, 30);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_1000
     * @tc.name      Test systemTime.setDate date = new Date(2022,7,31)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test10", 0, async function (done) {
        let date = new Date(2022, 7, 31);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_1100
     * @tc.name      Test systemTime.setDate date = new Date(2022,12,31)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test11", 0, async function (done) {
        let date = new Date(2022, 12, 31);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_setDate_JS_API_1200
     * @tc.name      Test systemTime.setDate date = new Date(2022,13,1)
     * @tc.desc      Test systemTime_setDate API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_setDate_test12", 0, async function (done) {
        let date = new Date(2022, 13, 1);
        try {
            await systemTime.setDate(date).then(() => {
                systemTime.getDate().then((data) => {
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
        } catch (err) {
            expect(false).assertTrue();
            done();
        }
    });

    /**
     * @tc.number    SUB_systemTime_getRealActiveTime_JS_API_0100
     * @tc.name      Test systemTime.getRealActiveTime
     * @tc.desc      Test systemTime_getRealActiveTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_getRealActiveTime_test1", 0, async function (done) {
        systemTime.getRealActiveTime().then((data) => {
            console.log("getRealActiveTime data = " + data);
            expect(data).to.have.length.above(1);
        });
        done();
    });

    /**
     * @tc.number    SUB_systemTime_getRealTime_JS_API_0100
     * @tc.name      Test systemTime.getRealTime
     * @tc.desc      Test systemTime_getRealTime API functionality.
     * @tc.size      : MEDIUM
     * @tc.type      : Function
     * @tc.level     : Level 0
     */
    it("systemTime_getRealTime_test1", 0, async function (done) {
        systemTime.getRealTime().then((data) => {
            console.log("getRealTime data = " + data);
            expect(data).to.have.length.above(1);
        });
        done();
    });
});