## 项目概述

time_service 是 OpenHarmony 时间子系统的核心部件，提供系统时间、时区管理和定时器服务。

## 构建

OpenHarmony GN + Ninja 构建，设备 `rk3568`。（前提：在 `openharmony/` 根目录下，已执行 `source build/envsetup.sh`）

- 编译源码：`hb build --product-name=rk3568 --build-target time_service`
- 编译测试：`hb build --product-name=rk3568 --build-target time_service_test`
- 子系统名：`time`，部件名：`time_service`，SA ID：`3702`

## 架构

三层 JS API 框架，共享服务实现：

| 层 | 路径 | 用途 |
|---|---|---|
| NAPI | `framework/js/napi/` | C++ NAPI 封装（system_date_time / system_timer / system_time） |
| ANI | `framework/js/ani/` | ArkTS Native Interface 封装（@ohos.systemDateTime） |
| Taihe | `framework/js/taihe/` | IDL 驱动的接口生成（system_datetime / system_timer） |
| 公共 | `framework/js/common/` | 三层共享的工具函数（如 `GetMonotoneWallTimeNs`） |

核心服务：
- `TimeSystemAbility`（`services/time_system_ability.cpp`）— 主 SA 实现，继承 `SystemAbility` + `TimeServiceStub`，管理时间/时区/定时器
- `TimeServiceClient`（`interfaces/inner_api/`）— 单例客户端代理，其它模块通过它访问时间服务
- `TimeServiceNotify`（`services/time/src/time_service_notify.cpp`）— 通过 CommonEvent 发布时间变更/时区变更/时间滴答事件
- `TimerManager`（`services/timer/src/timer_manager.cpp`）— 定时器生命周期管理（创建/启动/停止/销毁）

其它：
- `interfaces/kits/c/` — C API
- `framework/cj/` — 仓颉语言绑定
- `tools/ohos-query-time-cli/` — 命令行时间查询工具
- `utils/native/` — 通用工具（hilog 日志封装、文件工具等）
- `services/dfx/` — 可观测性（hisysevent 打点、hidumper 命令解析）
