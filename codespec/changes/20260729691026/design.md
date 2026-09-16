# 设计文档

> 将 spec 落地为具体实现方案，明确代码/配置/构建改动。

## 变更总览

| 属性 | 内容 |
|------|------|
| 特性 | time_service CCM 默认 NTP 服务器增加国家授时中心 |
| 目标版本 | OpenHarmony-7.1-Release |
| 设计版本 | v1.0 |
| 基线日期 | 2026-09-02 |
| 关联文档 | `proposal.md`、`spec.md`、`execution-plan.md` |

### 设计原则

1. **零代码改动**：`time_service` 已原生支持逗号分隔的多 NTP 服务器列表，仅修改 CCM 参数默认值即可。
2. **最小侵入**：只改动 `time.para` 一个配置文件；测试部分仅新增/补充单元测试用例。
3. **可回退**：保留原有 `1.cn.pool.ntp.org` 作为 fallback，避免国家授时中心不可达时完全失能。

---

## 模块与文件改动清单

### 1. CCM 参数默认值

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `time_time_service/services/etc/time.para` | MODIFY | 将 `persist.time.ntpserver` 默认值改为 `"ntp.ntsc.ac.cn,1.cn.pool.ntp.org"` |

### 2. 构建系统

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `time_time_service/services/etc/BUILD.gn` | 无需修改 | 该文件已通过 `ohos_prebuilt_etc("time.para")` 将 `time.para` 安装到 `etc/param` |

### 3. 单元测试

| 文件 | 变更类型 | 说明 |
|------|----------|------|
| `time_time_service/test/unittest/service_test/src/time_service_time_test.cpp` | MODIFY | 新增 `NtpTime003` 用例，验证默认值拆分结果 |

---

## 详细设计

### CCM 参数文件修改

修改 `time_time_service/services/etc/time.para` 第 15 行：

```diff
- persist.time.ntpserver = "1.cn.pool.ntp.org"
+ persist.time.ntpserver = "ntp.ntsc.ac.cn,1.cn.pool.ntp.org"
```

**理由：**
- `time_service` 启动时通过 `system::GetParameter` 读取该参数。
- 代码中的 `SplitNtpAddrs` 函数已将字符串按逗号拆分，并限制最多 5 个地址。
- 将 NTSC 服务器放在列表最前面，可使其在自动对时时被优先尝试；保留原 pool 服务器作为 fallback。

### 参数读取与拆分流程

```text
系统启动
  │
  ▼
NtpUpdateTime::Init()
  │
  ├── system::GetParameter("persist.time.ntpserver", "")
  │       返回："ntp.ntsc.ac.cn,1.cn.pool.ntp.org"（未覆盖时）
  │
  ├── SplitNtpAddrs(ntpServer)
  │       返回：["ntp.ntsc.ac.cn", "1.cn.pool.ntp.org"]
  │
  └── 保存到 autoTimeInfo_.ntpServer
  │
  ▼
GetNtpTimeInner()
  │
  ├── 尝试 ntpserver_specific 列表（如存在）
  │
  └── 按顺序尝试 ntpserver 列表
          1. ntp.ntsc.ac.cn
          2. 1.cn.pool.ntp.org
```

### 单元测试设计

在 `time_service_time_test.cpp` 中新增用例：

```cpp
/**
* @tc.name: NtpTime003
* @tc.desc: Test default NTP server list contains NTSC server
* @tc.precon: NtpUpdateTime service is available
* @tc.step: 1. Use the default NTP server string
*           2. Call SplitNtpAddrs method
*           3. Verify returned list contains ntp.ntsc.ac.cn as first item
* @tc.expect: SplitNtpAddrs returns ["ntp.ntsc.ac.cn", "1.cn.pool.ntp.org"]
* @tc.type: FUNC
* @tc.require: issue#TBD
* @tc.level: level0
*/
HWTEST_F(TimeServiceTimeTest, NtpTime003, TestSize.Level0)
{
    const std::string ntpStr = "ntp.ntsc.ac.cn,1.cn.pool.ntp.org";
    auto res = NtpUpdateTime::GetInstance().SplitNtpAddrs(ntpStr);
    EXPECT_EQ(res.size(), 2);
    EXPECT_EQ(res[0], "ntp.ntsc.ac.cn");
    EXPECT_EQ(res[1], "1.cn.pool.ntp.org");
}
```

### 集成测试设计（可选）

在可联网的真机/模拟器上执行：

1. 确保 `persist.time.auto_time=ON`。
2. 清除已覆盖的 `persist.time.ntpserver`（若有）。
3. 触发网络时间同步（如开关飞行模式或重启设备）。
4. 抓取 `time_service` 日志，验证出现：
   - `ntpServer is:ntp.ntsc.ac.cn`
   - 随后成功对时或 fallback 到 `1.cn.pool.ntp.org`。

---

## 构建与安装影响

- `time.para` 通过 `ohos_prebuilt_etc` 安装到 `/etc/param/time.para`，构建流程无需调整。
- 新镜像烧录后，系统初始化阶段读取的参数默认值即包含 `ntp.ntsc.ac.cn`。
- 升级场景：已写入的参数值不会被覆盖；未写入的设备升级后读取新默认值。

---

## 数据流与存储

| 数据 | 来源 | 流向 | 说明 |
|------|------|------|------|
| 默认 NTP 列表 | `time.para` → `/etc/param/time.para` | `system::GetParameter` → `NtpUpdateTime::Init` → `autoTimeInfo_.ntpServer` | 未覆盖时生效 |
| 覆盖的 NTP 列表 | 用户/MDM/运营商配置 | 同左 | 优先级高于默认值 |

---

## 错误处理与降级

| 场景 | 处理策略 |
|------|----------|
| `ntp.ntsc.ac.cn` 域名解析失败 | 记录 warning，继续尝试下一个地址 `1.cn.pool.ntp.org` |
| `ntp.ntsc.ac.cn` NTP 请求无响应 | 记录 warning，进入 `RETRY_TIMES` 重试；随后尝试 `1.cn.pool.ntp.org` |
| 所有默认服务器均失败 | 返回 `REFRESH_FAILED`，按现有重试间隔策略定时重试 |
| 参数被覆盖为空字符串 | `Init` 判断 `ntpServer.empty() && ntpServerSpec.empty()` 后提前返回，与现有行为一致 |

---

## 依赖关系

```mermaid
graph TD
    A[time.para] -->|ohos_prebuilt_etc| B[/etc/param/time.para]
    B -->|system::GetParameter| C[NtpUpdateTime::Init]
    C --> D[SplitNtpAddrs]
    D --> E[autoTimeInfo_.ntpServer]
    E --> F[GetNtpTimeInner]
    F -->|优先| G[ntp.ntsc.ac.cn]
    F -->|fallback| H[1.cn.pool.ntp.org]
```

---

## 设计约束与假设

1. `time_service` 代码中 `NTP_MAX_SIZE` 保持 5；当前默认值仅 2 个地址，留有足够余量。
2. 国家授时中心域名 `ntp.ntsc.ac.cn` 在目标网络环境中可解析且可达；若不可达，`1.cn.pool.ntp.org` 兜底。
3. 本次变更不涉及 `persist.time.ntpserver_specific` 的默认值。

---

## 设计评审检查清单

- [x] 所有 spec AC 在本设计中可追踪
- [x] 文件改动清单完整
- [x] 构建/安装流程已说明
- [x] 错误处理与降级策略已定义
- [x] 依赖关系已明确
- [x] 目标仓 Agent 指南中的约束已遵守

**设计结论:** 通过，可进入执行计划阶段。
