# ohos-queryTime 测试文档

## 测试概述

本文档描述 `ohos-queryTime` CLI 工具的测试方法和测试用例。

## 测试环境

- **操作系统**: OpenHarmony 标准系统
- **架构**: arm64 或 x86_64
- **依赖**: time_service 系统能力正常运行

## 测试准备

### 1. 编译安装

```bash
# 在 OpenHarmony 源码根目录执行
hb build //base/time/time_service/tools/ohos-queryTime-cli:ohos-queryTime
```

### 2. 安装到设备

```bash
# 推送到设备
hdc file send out/xxx/base/time/time_service/tools/ohos-queryTime-cli/ohos-queryTime /system/bin/cli_tool/executable

# 设置权限
hdc shell chmod 755 /system/bin/cli_tool/executable/ohos-queryTime
```

## 测试用例

### TC-001: 显示帮助信息

**目的**: 验证 --help 命令能正确显示帮助信息

**步骤**:
```bash
ohos-queryTime --help
```

**预期输出**:
```
ohos-queryTime - Query system time information

Usage: ohos-queryTime <command>

Commands:
  get-wall-time          Get wall time (UTC time in milliseconds)
  get-boot-time          Get boot time (including sleep time)
  get-monotonic-time     Get monotonic time (excluding sleep time)
  get-time-zone          Get current time zone

Options:
  --help                 Show this help message
  --version              Show version information
```

**结果**: [ ] 通过 [ ] 失败

---

### TC-002: 显示版本信息

**目的**: 验证 --version 命令能正确显示版本信息

**步骤**:
```bash
ohos-queryTime --version
```

**预期输出**:
```
ohos-queryTime version 1.0.0
```

**结果**: [ ] 通过 [ ] 失败

---

### TC-003: 获取 UTC 时间

**目的**: 验证 get-wall-time 命令能正确返回 UTC 时间

**步骤**:
```bash
ohos-queryTime get-wall-time
```

**预期结果**:
- 返回一个正整数（毫秒级时间戳）
- 返回值应大于 1700000000000（2023-11-14 之后的时间）

**结果**: [ ] 通过 [ ] 失败

---

### TC-004: 获取开机时间

**目的**: 验证 get-boot-time 命令能正确返回开机时间

**步骤**:
```bash
ohos-queryTime get-boot-time
```

**预期结果**:
- 返回一个正整数（毫秒）
- 返回值应小于 get-wall-time 的返回值
- 重复执行，返回值应递增

**结果**: [ ] 通过 [ ] 失败

---

### TC-005: 获取单调时间

**目的**: 验证 get-monotonic-time 命令能正确返回单调时间

**步骤**:
```bash
ohos-queryTime get-monotonic-time
```

**预期结果**:
- 返回一个正整数（毫秒）
- 返回值应小于 get-boot-time 的返回值（因为不包括休眠时间）
- 重复执行，返回值应递增

**结果**: [ ] 通过 [ ] 失败

---

### TC-006: 获取时区

**目的**: 验证 get-time-zone 命令能正确返回时区 ID

**步骤**:
```bash
ohos-queryTime get-time-zone
```

**预期结果**:
- 返回一个非空字符串
- 格式应符合 IANA 时区数据库格式，如 "Asia/Shanghai"、"America/New_York" 等

**结果**: [ ] 通过 [ ] 失败

---

### TC-007: 未知命令处理

**目的**: 验证工具能正确处理未知的命令

**步骤**:
```bash
ohos-queryTime unknown-command
```

**预期输出**:
```
Error: Unknown command 'unknown-command'
Use '--help' for usage information.
```

**返回码**: 非零值

**结果**: [ ] 通过 [ ] 失败

---

### TC-008: 无参数处理

**目的**: 验证工具在无参数时能正确显示帮助信息

**步骤**:
```bash
ohos-queryTime
```

**预期输出**: 显示帮助信息（同 --help）

**返回码**: 非零值

**结果**: [ ] 通过 [ ] 失败

## 性能测试

### PT-001: 命令响应时间

**目的**: 测试命令的响应时间

**步骤**:
```bash
time ohos-queryTime get-wall-time
```

**预期结果**:
- 响应时间应小于 100ms

**结果**: [ ] 通过 [ ] 失败

---

### PT-002: 并发测试

**目的**: 测试并发执行命令的稳定性

**步骤**:
```bash
for i in {1..100}; do
    ohos-queryTime get-wall-time &
done
wait
```

**预期结果**:
- 所有命令都应成功执行，无崩溃或死锁

**结果**: [ ] 通过 [ ] 失败

## 测试报告模板

| 项目 | 内容 |
|------|------|
| 测试日期 | YYYY-MM-DD |
| 测试人员 | 姓名 |
| 测试环境 | OpenHarmony 版本 / 设备型号 |
| 通过用例数 | X |
| 失败用例数 | X |
| 通过率 | X% |
| 已知问题 | 问题描述 |

## 附录

### 错误码说明

| 错误码 | 说明 |
|--------|------|
| 0 | 成功 |
| 非零 | 失败，具体错误码含义参考 TimeServiceClient 文档 |

### 相关文档

- [OpenHarmony 时间服务开发指南](https://gitee.com/openharmony/docs)
- [IANA 时区数据库](https://www.iana.org/time-zones)
