# SecSweep

本机安全体检工具。只读扫描账户、持久化点、服务、网络暴露面这些地方，出一份 HTML 报告。

给自己用的，不做商业化。跑完就退，不常驻。

## 为什么要这个

Windows 的入侵痕迹不是"有没有杀软在报警"能回答的。真正要看的是：多了一个不该在的账户、注册表某个 Run 键指向一个不存在的文件、某个服务从桌面目录加载 exe、3389 绑在 0.0.0.0 上。

这些用规则查比任何 AI 都准，而且不需要联网。

## 怎么跑

三种方式，任选：

```
build.cmd                     # 双击，或命令行跑
```

VS Code 里按 `Ctrl+Shift+B`，走默认任务（中文、全域）。

或者直接：

```powershell
pwsh -File src\SecSweep.ps1 -Lang zh-CN
```

常用参数：

| 参数 | 作用 |
| --- | --- |
| `-Lang zh-CN\|en-US\|auto` | 报告语言，默认跟系统 |
| `-Domains accounts,services` | 只跑指定域，省时间 |
| `-OutDir .\out` | 报告输出目录 |
| `-Fix` | 列出可逆处置动作（当前只列清单，不执行） |
| `-IncludeRaw` | 关闭脱敏，报告里保留真实用户名和 IP |
| `-SaveBaseline` | 把当前账户 / Run 键 / 服务 / 监听端口存成基线快照，写完就退 |

## 隐私这块是怎么做到的

- **不出网**：源码里没有任何 HTTP/TCP 出站调用。检查"对外连接"是读本地连接表，不是发包。
- **不读隐私数据**：不碰浏览器历史、聊天记录、文档内容。只看系统元数据：注册表、服务表、进程表、文件属性。
- **默认脱敏**：报告里的用户名、主机名、IP 会换成占位符。IP 只留前两段，够判断内外网。要原始值加 `-IncludeRaw`。
- **报告留在本地**：只写到 `out\`。没有上传、没有遥测、没有更新检查。
- **中间数据不落盘**：扫描结果全在内存，直接写报告。

## 加一门语言

1. 复制 `lang/zh-CN.json`，改名成 `lang/xx-XX.json`，翻译里面所有字符串。
2. `meta.code` 改成新语言码。
3. 报告里的规则标题来自 `rules/rules.json`，那份文件每条规则带 `zh` 和 `en` 两份文案。加第三语言时，给每条规则的 `title/why/fix` 各加一个字段，再在 `report.ps1` 的 `New-FindingRow` 里补一个 `data-xx` 属性。

界面上语言是按语言包来的，规则文案是按规则文件来的，两边要同步加。

## 白名单是这台机器专用的

`rules/whitelist.json` 里的账户名、服务名、计划任务路径，是我在这台天翼云电脑上实测确认过的正常噪音（天翼云的 clink_*、希沃 EasiUpdate、阿里 AlibabaProtect、cloudbase-init 这些）。

**换到别的机器必须先改这份文件**，否则会满屏误报。改法是先跑一遍看哪些是你要保留的，再往名单里加。

## 现在实现到哪一步

11 个域都在跑，一轮 16 秒左右（这台机器是 1 核）。

| 域 | 看什么 |
| --- | --- |
| accounts | 陌生账户、Guest、管理员组多成员、UAC |
| persistence | Run 键、计划任务、WMI 订阅、Winlogon、IFEO、AppInit、启动文件夹 |
| services | 服务 exe 缺失、指向可写目录、注册表里没声明的 svchost 组 |
| network | RDP 全网卡、SMBv1、NFS、非常规端口、防火墙档关闭 |
| processes | Temp / 桌面跑的进程、用户目录下未签名的进程 |
| hardening | 脚本块日志、登录失败审计、LLMNR |
| files | 临时目录近 30 天的 exe、桌面上的可执行文件 |
| credentials | 桌面 / 文档 / 下载里文件名像凭据的文件（只看名字，不读内容） |
| events | 安全日志被清空（1102）、外网来源的网络登录 |
| software | 装了但 Publisher 是空的程序 |
| baseline | 和快照比对账户、Run、服务、监听端口的新增与变化 |

基线要先自己存一份：

```
.\SecSweep.ps1 -SaveBaseline
```

不存的话 baseline 域什么都不报——没基线就没什么可比的，不猜。

## 已知限制

- **只能看用户态**。驱动层 rootkit 改了内核结构，这里的进程表和注册表读到的就是它想让你看到的。要彻底排除得离线取证。
- **文件名启发式判断不可靠**。服务"指向可写目录"是按路径前缀猜的，没查 ACL。真要看权限得用 `Get-Acl` 逐个查，那会很慢。
- **日志审计可能是关着的**。4625 是 0 条不代表没人试过，可能是没开失败审计。
- **1 核机器上会慢**。`Get-AuthenticodeSignature` 逐个查签名，几十个进程要几十秒。全盘扫描没有做，就是因为这个。

## 目录

```
src/SecSweep.ps1        入口
src/lib/i18n.ps1        语言包加载
src/lib/report.ps1      评分、脱敏、HTML 生成
src/checks/*.ps1        每个域一个文件，函数名 Invoke-Check<Domain>
rules/rules.json        规则定义（id、严重度、双语文案、是否可逆）
rules/whitelist.json    本机白名单
lang/*.json             语言包
out/                    报告输出（不进版本库）
```
