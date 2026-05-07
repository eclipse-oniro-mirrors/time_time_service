# ohos-queryTime

OpenHarmony 时间查询 CLI 工具，用于查询系统时间信息。

## 功能

- 获取 UTC 时间（毫秒）
- 获取开机时间（毫秒，包含休眠时间）
- 获取单调时间（毫秒，不包含休眠时间）
- 获取当前时区

## 用法

```bash
ohos-queryTime <command>
```

## 命令

| 命令 | 说明 |
|------|------|
| `get-wall-time` | 获取 UTC 时间（从 1970-01-01 00:00:00 UTC 开始的毫秒数） |
| `get-boot-time` | 获取开机时间（毫秒，包含休眠时间） |
| `get-monotonic-time` | 获取单调时间（毫秒，不包含休眠时间） |
| `get-time-zone` | 获取当前时区 ID |
| `--help` | 显示帮助信息 |

## 输出格式

所有命令统一输出 JSON 格式：

**成功响应：**
```json
{
  "type": "result",
  "status": "success",
  "data": { ... }
}
```

**失败响应：**
```json
{
  "type": "result",
  "status": "failed",
  "errCode": "ERR_XXX",
  "errMsg": "Error description",
  "suggestion": "Suggested next operation"
}
```

## 示例

### 获取 UTC 时间

```bash
ohos-queryTime get-wall-time
```

**成功输出:**
```json
{"type":"result","status":"success","data":{"time":1714305600000,"unit":"ms"}}
```

### 获取开机时间

```bash
ohos-queryTime get-boot-time
```

**成功输出:**
```json
{"type":"result","status":"success","data":{"time":3600000,"unit":"ms"}}
```

### 获取单调时间

```bash
ohos-queryTime get-monotonic-time
```

**成功输出:**
```json
{"type":"result","status":"success","data":{"time":3500000,"unit":"ms"}}
```

### 获取时区

```bash
ohos-queryTime get-time-zone
```

**成功输出:**
```json
{"type":"result","status":"success","data":{"timezone":"Asia/Shanghai"}}
```

### 显示帮助

```bash
ohos-queryTime --help
```

**输出:**
```
ohos-queryTime - Query system time information

Usage:
  ohos-queryTime <command> [options]

Parameters:
  --help             Display this help message

SubCommands:
  get-wall-time      Get wall time (UTC time in milliseconds)
  get-boot-time      Get boot time (including sleep time)
  get-monotonic-time Get monotonic time (excluding sleep time)
  get-time-zone      Get current time zone

Examples:
  ohos-queryTime --help
  ohos-queryTime get-wall-time --help
```

## 错误码

| 错误码 | 说明 | 常见原因 |
|--------|------|----------|
| `E_NO_COMMAND` | 未指定命令 | 调用时缺少子命令参数 |
| `E_UNKNOWN_COMMAND` | 未知命令 | 使用了不存在的子命令 |
| `ERR_CLIENT_INIT` | 客户端初始化失败 | time_service 系统能力未启动 |
| `ERR_GET_WALL_TIME` | 获取 UTC 时间失败 | 系统时间服务异常 |
| `ERR_GET_BOOT_TIME` | 获取开机时间失败 | 系统时间服务异常 |
| `ERR_GET_MONOTONIC_TIME` | 获取单调时间失败 | 系统时间服务异常 |
| `ERR_GET_TIME_ZONE` | 获取时区失败 | 系统时间服务异常 |

## 权限

本工具为纯查询工具，无需任何权限。

## 编译

```bash
# 在 OpenHarmony 源码根目录执行
hb build //base/time/time_service/tools/ohos-queryTime-cli:ohos-queryTime
```

## 安装

编译完成后，可执行文件位于：`out/xxx/base/time/time_service/tools/ohos-queryTime-cli/ohos-queryTime`

随镜像安装后可直接使用：
```bash
ohos-queryTime get-wall-time
```
