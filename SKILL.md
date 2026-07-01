---
name: ip-analysis
description: IP 地址综合分析：归属地查询（国家/省份/城市）、网络信息（ASN/ISP/组织）、风险评分（黑灰产/VPN/代理/Tor/僵尸网络检测）。通过 DNSBL 黑名单查询 + 关键词分级 + VPN/proxy 提供商库 + ASN 类型，四层递进判断 IP 安全性。当用户说「查一下这个 IP」「IP 分析」「这个 IP 是哪里的」「IP 归属地」「查 IP」「分析 IP 地址」「IP 风险」「这个 IP 可不可信」「查黑灰产 IP」「查 VPN IP」「查代理 IP」「IP 地址跟实际位置不一致」「注册 IP 验证」「IP 被 Spamhaus 拉黑」时激活。不唤醒：域名分析/DNS 记解析/WHOIS（非 IP）、网络拓扑设计、端口扫描/渗透测试、批量 IP 提取与统计、子网划分/CIDR 计算、路由排查与网络运维。
---

# IP 分析 Skill

对单个 IP 地址进行综合分析，聚合多个公开数据源，输出归属地、网络信息与风险评分。

## 安装后设置

Skill 安装后需执行数据文件下载脚本（ip2region 离线库 ~46MB）：

```bash
bash <skill_directory>/scripts/setup_data.sh
```

脚本会自动从 CDN 下载 `ip2region_v4.xdb`（~11MB）和 `ip2region_v6.xdb`（~35MB）到 `<skill_directory>/data/` 目录。已存在的文件会自动跳过。

> 如果跳过此步骤，脚本会在首次查询时尝试自动下载（但可能较慢）。

## 触发条件

用户提到一个 IP 地址并想要了解其属性时激活。典型触发词：

- 「查一下这个 IP」
- 「IP 分析」
- 「这个 IP 是哪里的」
- 「IP 归属地」
- 「查 IP」
- 「分析 IP 地址」
- 「IP 风险」
- 「这个 IP 可不可信」
- 「查黑灰产 IP」
- 「查 VPN IP」
- 「查代理 IP」
- 「IP 地址跟实际位置不一致」
- 「注册 IP 验证」
- 「IP 被 Spamhaus 拉黑」

不唤醒：域名分析/DNS 记解析/WHOIS、网络拓扑设计、端口扫描/渗透测试、批量 IP 提取与统计、子网划分/CIDR 计算、路由排查与网络运维。

## 执行步骤

### 1. 提取 IP 地址

从用户消息中提取目标 IP。支持 IPv4 和 IPv6。若用户提供多个 IP，逐个分析。

### 2. 运行分析脚本

```bash
uv run --with py-ip2region <skill_directory>/scripts/ip_analysis.py <ip_address>
```

ip2region 离线库（数据文件位于 `<skill_directory>/data/`）作为首选归属地数据源，无需网络即可返回中国 IP 的精确中文归属地 + ISP 标注。在线 API 作为补充提供坐标、hostname、ASN 等信息。

若需风险评分，提前设置环境变量：

```bash
export ABUSEIPDB_KEY=<your_key>
uv run --with py-ip2region <skill_directory>/scripts/ip_analysis.py <ip_address>
```

### 2b. 降级到 agent-browser（最多 2 次）

仅当以下情况发生时考虑降级：

- 脚本所有 API 源（ipinfo.io + ipapi.co + ip.sb + RDAP）均失败
- 确实无其他替代方案可获取 IP 信息

降级流程：使用 agent-browser skill 打开百度 IP 查询页面或其他 IP 查询网站，提取可见的归属地/机构信息。

每次降级后检查结果是否有效。超过 2 次降级后停止，输出明确失败信息并退出。

### 3. 整理输出

将 JSON 结果转化为人类可读的摘要。

#### 单个 IP：详细分析格式

按以下结构逐项输出：

- **归属地**：国家 / 省份 / 城市 / 坐标 / Google Maps 链接
- **基础信息**：hostname / 时区 / UTC 偏移 / 邮编 / 国家代码 / 电话区号 / 货币 / 语言 / IP 版本 / **IP 用途类型（机构/家庭/CDN）** / Google Maps 链接
- **网络信息**：ISP / 组织 / ASN / ASN 类型 / CIDR
- **风险评分**：风险等级 / 是否 hosting / 是否在黑名单 / 黑名单详情 / hosting 信号

#### 多个 IP：表格格式

若用户提供了 N 个 IP（N > 1），逐个运行脚本后整理成表格汇总，列包含：

| IP | 归属地 | ISP | 用途类型 | 风险等级 | 关键信号 |

- **行数 ≤ 5**：直接以 Markdown 表格输出
- **行数 > 5**：调用 mixcard-creator skill，生成 KIM mixCard 表格卡片，通过 message 工具发送（channel=kim），使表格可交互、可滚动

风险等级说明：
- `low`（0-24）：正常 IP，少量或无滥用报告
- `medium`（25-74）：有一定滥用记录，需关注
- `high`（75-100）：高度可疑，大量滥用报告

### 4. 补充解读

根据结果主动给出解读，比如：

- 高风险 IP → 提醒用户注意，建议不信任该来源
- 代理/托管 IP → 说明可能非真实用户位置
- 白名单 IP → 说明该 IP 已被标记为可信来源

## ⚠️ 自修复熔断规则

本 Skill 脚本执行失败后，AI 最多尝试自修复 **2** 次。超过 2 次后必须停止重试，输出明确失败信息并退出，不得继续循环。

## ⚠️ agent-browser 降级规则：仅当 API 直接调用失败且确实无替代方案时，才允许降级到 agent-browser，最多降级 **2** 次。超过 2 次后必须停止，不得继续尝试浏览器操作。

## 数据源说明

| 数据源 | 功能 | 限制 |
|--------|------|------|
| **ip2region** | 离线归属地 + ISP（中国全中文，微秒级查询） | xdb 数据文件不随 Skill 打包，首次运行自动从 CDN 下载（IPv4: ~11MB / IPv6: ~35MB） |
| ipinfo.io | 补充坐标 + hostname + ASN | 免费 50k/月 |
| ipapi.co | 补充归属地 + ASN/ISP | 免费 1000/天 |
| ip.sb | 补充 ASN + ISP | 免费 |
| RDAP | IP 注册信息 → hosting 判断 | 免费，无限制 |
| Spamhaus ZEN DNSBL | 黑名单/僵尸网络/Tor/代理检测 | 免费，DNS 查询 |
| SpamCop DNSBL | 垃圾邮件检测 | 免费，DNS 查询 |
| CBL DNSBL | 僵尸网络/恶意软件检测 | 免费，DNS 查询 |
| Tor exit DNS | Tor 出口节点检测 | 免费，DNS 查询 |
| abuseipdb.com | 滥用报告 + 风险评分 | 需 API Key（可选增强） |

脚本自动聚合所有数据源：归属地/API 三源互为补充；RDAP 提供注册信息；DNSBL 通过 DNS 查询检测黑灰产/僵尸网络/Tor；AbuseIPDB 需配置 `ABUSEIPDB_KEY` 才启用。

## 风险判断逻辑（四层递进）

### 第一层：DNSBL 黑名单（最高优先级）

通过 DNS 查询多个黑名单数据库，**无需 API Key**：

| 检测结果 | 风险等级 | 含义 |
|---------|---------|------|
| Tor exit node | 🔴 high | Tor 出口节点，匿名中转，黑灰产高频 |
| 僵尸网络/恶意软件（XBL） | 🔴 high | 被劫持或参与恶意活动 |
| 垃圾邮件来源（SBL） | 🔴 high | 已确认的垃圾邮件/黑灰产 IP |
| ISP 策略屏蔽（PBL） | 🟡 medium | 数据中心/托管 IP，不允许直接发邮件 |

### 第二层：VPN/代理提供商库

40+ 已知 VPN/proxy 提供商 org 名称精确匹配（NordVPN、ExpressVPN、Mullvad、Luminati/Bright Data 等）。命中 → 🔴 high。

### 第三层：关键词分级

| 级别 | 关键词示例 | 含义 | 风险等级 |
|------|-----------|------|---------|
| **high** | tor, proxy, vpn, relay, exit, anonymizer | 匿名中转 | 🔴 high |
| **medium** | hosting, datacenter, vps, dedicated, OVH, Hetzner | 数据中心 IP | 🟡 medium |
| **low** | cloud, cdn, Google, AWS, Cloudflare, Azure | 云服务/CDN/企业 | 🟢 low（非 residential） |

- ipinfo.io `asn_type` 优先级高于关键词：`hosting` → medium，`business` → low，`isp` → residential
- 最高级别胜出

### 第四层：AbuseIPDB 增强（需 API Key）

叠加滥用置信度分数（0-100）：abuse ≥ 75 → high；hosting + abuse ≥ 25 → 升级为 high

## IP 用途分类（机构 vs 家庭）

基于 ip2region ISP 标注 + org 名称关键词综合判断：

| 分类 | 判断依据 | 示例 |
|------|-----------|------|
| **机构（机房/云服务）** | org 含 IDC/云服务商关键词 → 优先；ip2region ISP = 阿里/腾讯/华为等 | `AS23724 IDC` → 机构（机房），即使 ip2region 标注「电信」 |
| **机构（CDN）** | org 含 CDN 关键词 | `AS13335 Cloudflare` → 机构（CDN） |
| **机构（VPN/代理）** | VPN 提供商库匹配 | NordVPN → 机构（VPN/代理） |
| **家庭（运营商宽带）** | ip2region ISP = 联通/电信/移动，且 org 无 IDC 关键词 | `ip2region:联通` + org 无 IDC → 家庭 |

**优先级**：org IDC 关键词 > ip2region 云服务商 ISP > ip2region 运营商 ISP > 其他关键词