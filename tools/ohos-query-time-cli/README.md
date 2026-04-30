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
| `--version` | 显示版本信息 |

## 示例

```bash
# 获取 UTC 时间
ohos-queryTime get-wall-time
# 输出: 1714305600000

# 获取开机时间
ohos-queryTime get-boot-time
# 输出: 3600000

# 获取单调时间
ohos-queryTime get-monotonic-time
# 输出: 3500000

# 获取时区
ohos-queryTime get-time-zone
# 输出: Asia/Shanghai

# 显示帮助
ohos-queryTime --help

# 显示版本
ohos-queryTime --version
```

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
