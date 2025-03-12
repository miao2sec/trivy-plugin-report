# 1. 概述

## 1.1 制品信息

容器镜像 test:latest 基于 Linux 操作系统构建，适用于 arm64 架构，并在 2025 年 03 月 12 日 20:23:10 的安全扫描中发现了潜在的安全问题。

| 制品类型 | 容器镜像 |
|--- | --- |
| 制品名称 | test:latest |
| 创建时间 | 2025 年 03 月 12 日 20:21:55 |
| 架构 | arm64 |
| 操作系统 | Linux |
| 仓库标签 | test:latest |
| 镜像 ID | sha256:61f488f61d6b30d34ceeb1bbe63d206e6044641375f8817fe06bbadc33e83ec0 |
| 扫描时间 | 2025 年 03 月 12 日 20:23:10 |

## 1.2 镜像配置

镜像创建历史记录如下所示，请手动检查是否有可疑的执行命令，例如下载恶意文件等。

| 创建时间 | 历史记录 |
|--- | --- |
| 2025-03-12 12:21:55 | COPY report /report # buildkit |
| 2025-03-12 12:21:55 | ENTRYPOINT ["/report"] |

镜像配置信息如下所示，请手动检查是否有可疑的执行命令和暴露的 secret，例如执行恶意命令和应用程序密钥等。

| 配置类型 | 内容 |
|--- | --- |
| 环境变量 | PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |

## 1.3 漏洞概览

本次共扫描出 7 个漏洞，超危漏洞有 2 个，占比 28.57% ；高危漏洞有 2 个，占比 28.57% 。

|  | 超危 | 高危 | 中危 | 低危 | 未知 | 总计 |
|--- | --- | --- | --- | --- | --- | --- |
| 应用层组件漏洞：report | 2 | 2 | 3 | 0 | 0 | 7 |
| 漏洞总数 | 2 | 2 | 3 | 0 | 0 | 7 |

其中可修复的漏洞有 7 个，占比 100.00% 。

| 可修复漏洞 | 漏洞数量 |
|--- | --- |
| CVE-2025-22866 : crypto/internal/nistec: golang: Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec | 1 |
| CVE-2025-21613 : go-git: argument injection via the URL field | 1 |
| CVE-2025-21614 : go-git: go-git clients vulnerable to DoS via maliciously crafted Git server replies | 1 |
| CVE-2024-45337 : golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto | 1 |
| CVE-2024-45338 : golang.org/x/net/html: Non-linear parsing of case-insensitive content in golang.org/x/net/html | 1 |
| CVE-2024-45336 : golang: net/http: net/http: sensitive headers incorrectly sent after cross-domain redirect | 1 |
| CVE-2024-45341 : golang: crypto/x509: crypto/x509: usage of IPv6 zone IDs can bypass URI name constraints | 1 |

包含漏洞的软件包如下所示。

| 软件包名称 | 包含的漏洞数量 |
|--- | --- |
| stdlib | 3 |
| github.com/go-git/go-git/v5 | 2 |
| golang.org/x/crypto | 1 |
| golang.org/x/net | 1 |

全量漏洞如下所示，漏洞详情请看第二部分的扫描结果。

| 漏洞名称 | 漏洞数量 |
|--- | --- |
| CVE-2024-45337 : golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto | 1 |
| CVE-2024-45338 : golang.org/x/net/html: Non-linear parsing of case-insensitive content in golang.org/x/net/html | 1 |
| CVE-2024-45336 : golang: net/http: net/http: sensitive headers incorrectly sent after cross-domain redirect | 1 |
| CVE-2024-45341 : golang: crypto/x509: crypto/x509: usage of IPv6 zone IDs can bypass URI name constraints | 1 |
| CVE-2025-22866 : crypto/internal/nistec: golang: Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec | 1 |
| CVE-2025-21613 : go-git: argument injection via the URL field | 1 |
| CVE-2025-21614 : go-git: go-git clients vulnerable to DoS via maliciously crafted Git server replies | 1 |

# 2. 扫描结果

## 2.1 report

| 扫描目标 | report |
|--- | --- |
| 软件包类型 | 应用层软件包 |
| 目标类型 | gobinary |

### 2.1.1 CVE-2025-21613:go-git: argument injection via the URL field

#### 2.1.1.1 软件包信息

| 软件包 URL | pkg:golang/github.com/go-git/go-git/v5@v5.12.0 |
|--- | --- |
| 软件包名称 | github.com/go-git/go-git/v5 |
| 安装版本 | v5.12.0 |
| 软件包 ID | github.com/go-git/go-git/v5@v5.12.0 |
| 修复版本 | 5.13.0 |

#### 2.1.1.2 漏洞信息

| 漏洞编号 | CVE-2025-21613 |
|--- | --- |
| 漏洞标题 | go-git: argument injection via the URL field |
| 威胁等级 | 超危 |
| 威胁等级来源 | ghsa |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2025 年 01 月 07 日 01:15:47 |
| 上次修改时间 | 2025 年 01 月 07 日 01:15:47 |

### 2.1.2 CVE-2025-21614:go-git: go-git clients vulnerable to DoS via maliciously crafted Git server replies

#### 2.1.2.1 软件包信息

| 软件包 URL | pkg:golang/github.com/go-git/go-git/v5@v5.12.0 |
|--- | --- |
| 软件包名称 | github.com/go-git/go-git/v5 |
| 安装版本 | v5.12.0 |
| 软件包 ID | github.com/go-git/go-git/v5@v5.12.0 |
| 修复版本 | 5.13.0 |

#### 2.1.2.2 漏洞信息

| 漏洞编号 | CVE-2025-21614 |
|--- | --- |
| 漏洞标题 | go-git: go-git clients vulnerable to DoS via maliciously crafted Git server replies |
| 威胁等级 | 高危 |
| 威胁等级来源 | ghsa |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2025 年 01 月 07 日 01:15:47 |
| 上次修改时间 | 2025 年 01 月 07 日 01:15:47 |

### 2.1.3 CVE-2024-45337:golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto

#### 2.1.3.1 软件包信息

| 软件包 URL | pkg:golang/golang.org/x/crypto@v0.27.0 |
|--- | --- |
| 软件包名称 | golang.org/x/crypto |
| 安装版本 | v0.27.0 |
| 软件包 ID | golang.org/x/crypto@v0.27.0 |
| 修复版本 | 0.31.0 |

#### 2.1.3.2 漏洞信息

| 漏洞编号 | CVE-2024-45337 |
|--- | --- |
| 漏洞标题 | golang.org/x/crypto/ssh: Misuse of ServerConfig.PublicKeyCallback may cause authorization bypass in golang.org/x/crypto |
| 威胁等级 | 超危 |
| 威胁等级来源 | ghsa |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2024 年 12 月 12 日 10:02:07 |
| 上次修改时间 | 2025 年 02 月 19 日 05:15:22 |

### 2.1.4 CVE-2024-45338:golang.org/x/net/html: Non-linear parsing of case-insensitive content in golang.org/x/net/html

#### 2.1.4.1 软件包信息

| 软件包 URL | pkg:golang/golang.org/x/net@v0.29.0 |
|--- | --- |
| 软件包名称 | golang.org/x/net |
| 安装版本 | v0.29.0 |
| 软件包 ID | golang.org/x/net@v0.29.0 |
| 修复版本 | 0.33.0 |

#### 2.1.4.2 漏洞信息

| 漏洞编号 | CVE-2024-45338 |
|--- | --- |
| 漏洞标题 | golang.org/x/net/html: Non-linear parsing of case-insensitive content in golang.org/x/net/html |
| 威胁等级 | 高危 |
| 威胁等级来源 | ghsa |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2024 年 12 月 19 日 05:15:08 |
| 上次修改时间 | 2025 年 02 月 22 日 02:15:17 |

### 2.1.5 CVE-2024-45336:golang: net/http: net/http: sensitive headers incorrectly sent after cross-domain redirect

#### 2.1.5.1 软件包信息

| 软件包 URL | pkg:golang/stdlib@v1.23.3 |
|--- | --- |
| 软件包名称 | stdlib |
| 安装版本 | v1.23.3 |
| 软件包 ID | stdlib@v1.23.3 |
| 修复版本 | 1.22.11, 1.23.5, 1.24.0-rc.2 |

#### 2.1.5.2 漏洞信息

| 漏洞编号 | CVE-2024-45336 |
|--- | --- |
| 漏洞标题 | golang: net/http: net/http: sensitive headers incorrectly sent after cross-domain redirect |
| 威胁等级 | 中危 |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2025 年 01 月 28 日 10:15:28 |
| 上次修改时间 | 2025 年 02 月 22 日 02:15:17 |

### 2.1.6 CVE-2024-45341:golang: crypto/x509: crypto/x509: usage of IPv6 zone IDs can bypass URI name constraints

#### 2.1.6.1 软件包信息

| 软件包 URL | pkg:golang/stdlib@v1.23.3 |
|--- | --- |
| 软件包名称 | stdlib |
| 安装版本 | v1.23.3 |
| 软件包 ID | stdlib@v1.23.3 |
| 修复版本 | 1.22.11, 1.23.5, 1.24.0-rc.2 |

#### 2.1.6.2 漏洞信息

| 漏洞编号 | CVE-2024-45341 |
|--- | --- |
| 漏洞标题 | golang: crypto/x509: crypto/x509: usage of IPv6 zone IDs can bypass URI name constraints |
| 威胁等级 | 中危 |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2025 年 01 月 28 日 10:15:29 |
| 上次修改时间 | 2025 年 02 月 22 日 02:15:17 |

### 2.1.7 CVE-2025-22866:crypto/internal/nistec: golang: Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec

#### 2.1.7.1 软件包信息

| 软件包 URL | pkg:golang/stdlib@v1.23.3 |
|--- | --- |
| 软件包名称 | stdlib |
| 安装版本 | v1.23.3 |
| 软件包 ID | stdlib@v1.23.3 |
| 修复版本 | 1.22.12, 1.23.6, 1.24.0-rc.3 |

#### 2.1.7.2 漏洞信息

| 漏洞编号 | CVE-2025-22866 |
|--- | --- |
| 漏洞标题 | crypto/internal/nistec: golang: Timing sidechannel for P-256 on ppc64le in crypto/internal/nistec |
| 威胁等级 | 中危 |
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2025 年 02 月 07 日 01:15:21 |
| 上次修改时间 | 2025 年 02 月 22 日 02:15:32 |

