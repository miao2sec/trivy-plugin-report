# 1. 概述

## 1.1 制品信息

容器镜像 tomcat:9.0.97-jre8-temurin-jammy 基于 ubuntu 22.04 操作系统构建，适用于 amd64 架构，并在 2024 年 11 月 22 日 09:41:23 的安全扫描中发现了潜在的安全问题。

| 制品类型 | 容器镜像 |
|--- | --- |
| 制品名称 | tomcat:9.0.97-jre8-temurin-jammy |
| 创建时间 | 2024 年 11 月 09 日 23:03:40 |
| 架构 | amd64 |
| 操作系统 | ubuntu 22.04 |
| 仓库标签 | tomcat:9.0.97-jre8-temurin-jammy |
| 镜像 ID | sha256:6e6b14d057065b834f0e00319629864861c08492f84f3e9b870d0250c0a14d4b |
| 扫描时间 | 2024 年 11 月 22 日 09:41:23 |

## 1.2 镜像配置

镜像创建历史记录如下所示，请手动检查是否有可疑的执行命令，例如下载恶意文件等。

| 创建时间 | 历史记录 |
|--- | --- |
| 2024-09-11 16:25:16 | /bin/sh -c #(nop)  ARG RELEASE |
| 2024-09-11 16:25:16 | /bin/sh -c #(nop)  ARG LAUNCHPAD_BUILD_ARCH |
| 2024-09-11 16:25:16 | /bin/sh -c #(nop)  LABEL org.opencontainers.image.ref.name=ubuntu |
| 2024-09-11 16:25:16 | /bin/sh -c #(nop)  LABEL org.opencontainers.image.version=22.04 |
| 2024-09-11 16:25:17 | /bin/sh -c #(nop) ADD file:ebe009f86035c175ba244badd298a2582914415cf62783d510eab3a311a5d4e1 in /  |
| 2024-09-11 16:25:18 | /bin/sh -c #(nop)  CMD ["/bin/bash"] |
| 2024-10-23 15:41:32 | ENV JAVA_HOME=/opt/java/openjdk |
| 2024-10-23 15:41:32 | ENV PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |
| 2024-10-23 15:41:32 | ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8 |
| 2024-10-23 15:41:32 | RUN /bin/sh -c set -eux;     apt-get update;     DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends         curl         wget         gnupg         fontconfig         ca-certificates p11-kit         tzdata         locales     ;     echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen;     locale-gen en_US.UTF-8;     rm -rf /var/lib/apt/lists/* # buildkit |
| 2024-10-23 15:41:32 | ENV JAVA_VERSION=jdk8u432-b06 |
| 2024-10-23 15:41:32 | RUN /bin/sh -c set -eux;     ARCH="$(dpkg --print-architecture)";     case "${ARCH}" in        amd64)          ESUM='bb8c8cc575b69e68e12a213674ec2e3848baff4f1955d2973d98e67666ab94d7';          BINARY_URL='https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u432-b06/OpenJDK8U-jre_x64_linux_hotspot_8u432b06.tar.gz';          ;;        arm64)          ESUM='786522da4c761104dd8274c81edc90126a25acaafbbbc5da886b3fb51f33cba2';          BINARY_URL='https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u432-b06/OpenJDK8U-jre_aarch64_linux_hotspot_8u432b06.tar.gz';          ;;        armhf)          ESUM='49894dbe2f915dfad026cf7b4013118c0284e88359172499b1b25a4dac195ff1';          BINARY_URL='https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u432-b06/OpenJDK8U-jre_arm_linux_hotspot_8u432b06.tar.gz';          apt-get update;          DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libatomic1;          rm -rf /var/lib/apt/lists/*;          ;;        ppc64el)          ESUM='c573f33f9e5ba49a4838847d0d34efc9c1dc57a9ba71b926599530bbcda87f65';          BINARY_URL='https://github.com/adoptium/temurin8-binaries/releases/download/jdk8u432-b06/OpenJDK8U-jre_ppc64le_linux_hotspot_8u432b06.tar.gz';          ;;        *)          echo "Unsupported arch: ${ARCH}";          exit 1;          ;;     esac;     wget --progress=dot:giga -O /tmp/openjdk.tar.gz ${BINARY_URL};     wget --progress=dot:giga -O /tmp/openjdk.tar.gz.sig ${BINARY_URL}.sig;     export GNUPGHOME="$(mktemp -d)";     gpg --batch --keyserver keyserver.ubuntu.com --recv-keys 3B04D753C9050D9A5D343F39843C48A565F8F04B;     gpg --batch --verify /tmp/openjdk.tar.gz.sig /tmp/openjdk.tar.gz;     rm -r "${GNUPGHOME}" /tmp/openjdk.tar.gz.sig;     echo "${ESUM} */tmp/openjdk.tar.gz" | sha256sum -c -;     mkdir -p "$JAVA_HOME";     tar --extract         --file /tmp/openjdk.tar.gz         --directory "$JAVA_HOME"         --strip-components 1         --no-same-owner     ;     rm -f /tmp/openjdk.tar.gz ${JAVA_HOME}/lib/src.zip;     find "$JAVA_HOME/lib" -name '*.so' -exec dirname '{}' ';' | sort -u > /etc/ld.so.conf.d/docker-openjdk.conf;     ldconfig; # buildkit |
| 2024-10-23 15:41:32 | RUN /bin/sh -c set -eux;     echo "Verifying install ...";     echo "java -version"; java -version;     echo "Complete." # buildkit |
| 2024-10-23 15:41:32 | COPY --chmod=755 entrypoint.sh /__cacert_entrypoint.sh # buildkit |
| 2024-10-23 15:41:32 | ENTRYPOINT ["/__cacert_entrypoint.sh"] |
| 2024-11-09 15:03:40 | ENV CATALINA_HOME=/usr/local/tomcat |
| 2024-11-09 15:03:40 | ENV PATH=/usr/local/tomcat/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |
| 2024-11-09 15:03:40 | RUN /bin/sh -c mkdir -p "$CATALINA_HOME" # buildkit |
| 2024-11-09 15:03:40 | WORKDIR /usr/local/tomcat |
| 2024-11-09 15:03:40 | ENV TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib |
| 2024-11-09 15:03:40 | ENV LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib |
| 2024-11-09 15:03:40 | ENV GPG_KEYS=48F8E69F6390C9F25CFEDCD268248959359E722B A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 |
| 2024-11-09 15:03:40 | ENV TOMCAT_MAJOR=9 |
| 2024-11-09 15:03:40 | ENV TOMCAT_VERSION=9.0.97 |
| 2024-11-09 15:03:40 | ENV TOMCAT_SHA512=537dbbfc03b37312c2ec282c6906828298cb74e42aca6e3e6835d44bf6923fd8c5db77e98bf6ce9ef19e1922729de53b20546149176e07ac04087df786a62fd9 |
| 2024-11-09 15:03:40 | COPY /usr/local/tomcat /usr/local/tomcat # buildkit |
| 2024-11-09 15:03:40 | RUN /bin/sh -c set -eux; 	apt-get update; 	xargs -rt apt-get install -y --no-install-recommends < "$TOMCAT_NATIVE_LIBDIR/.dependencies.txt"; 	rm -rf /var/lib/apt/lists/* # buildkit |
| 2024-11-09 15:03:40 | RUN /bin/sh -c set -eux; 	nativeLines="$(catalina.sh configtest 2>&1)"; 	nativeLines="$(echo "$nativeLines" | grep 'Apache Tomcat Native')"; 	nativeLines="$(echo "$nativeLines" | sort -u)"; 	if ! echo "$nativeLines" | grep -E 'INFO: Loaded( APR based)? Apache Tomcat Native library' >&2; then 		echo >&2 "$nativeLines"; 		exit 1; 	fi # buildkit |
| 2024-11-09 15:03:40 | EXPOSE map[8080/tcp:{}] |
| 2024-11-09 15:03:40 | ENTRYPOINT [] |
| 2024-11-09 15:03:40 | CMD ["catalina.sh" "run"] |

镜像配置信息如下所示，请手动检查是否有可疑的执行命令和暴露的 secret，例如执行恶意命令和应用程序密钥等。

| 配置类型 | 内容 |
|--- | --- |
| 执行命令 | catalina.sh |
| 执行命令 | run |
| 环境变量 | PATH=/usr/local/tomcat/bin:/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin |
| 环境变量 | JAVA_HOME=/opt/java/openjdk |
| 环境变量 | LANG=en_US.UTF-8 |
| 环境变量 | LANGUAGE=en_US:en |
| 环境变量 | LC_ALL=en_US.UTF-8 |
| 环境变量 | JAVA_VERSION=jdk8u432-b06 |
| 环境变量 | CATALINA_HOME=/usr/local/tomcat |
| 环境变量 | TOMCAT_NATIVE_LIBDIR=/usr/local/tomcat/native-jni-lib |
| 环境变量 | LD_LIBRARY_PATH=/usr/local/tomcat/native-jni-lib |
| 环境变量 | GPG_KEYS=48F8E69F6390C9F25CFEDCD268248959359E722B A9C5DF4D22E99998D9875A5110C01C5A2F6059E7 DCFD35E0BF8CA7344752DE8B6FB21E8933C60243 |
| 环境变量 | TOMCAT_MAJOR=9 |
| 环境变量 | TOMCAT_VERSION=9.0.97 |
| 环境变量 | TOMCAT_SHA512=537dbbfc03b37312c2ec282c6906828298cb74e42aca6e3e6835d44bf6923fd8c5db77e98bf6ce9ef19e1922729de53b20546149176e07ac04087df786a62fd9 |

## 1.3 漏洞概览

本次共扫描出 64 个漏洞，超危漏洞有 0 个，占比 0.00% ；高危漏洞有 0 个，占比 0.00% 。

|  | 超危 | 高危 | 中危 | 低危 | 未知 | 总计 |
|--- | --- | --- | --- | --- | --- | --- |
| 系统层组件漏洞：tomcat:9.0.97-jre8-temurin-jammy (ubuntu 22.04) | 0 | 0 | 17 | 47 | 0 | 64 |
| 应用层组件漏洞：Java | 0 | 0 | 0 | 0 | 0 | 0 |
| 漏洞总数 | 0 | 0 | 17 | 47 | 0 | 64 |

其中可修复的漏洞有 2 个，占比 3.12% 。

| 可修复漏洞 | 漏洞数量 |
|--- | --- |
| CVE-2024-9681 : curl: HSTS subdomain overwrites parent cache entry | 2 |

包含漏洞的软件包如下所示。

| 软件包名称 | 包含的漏洞数量 |
|--- | --- |
| libk5crypto3 | 3 |
| libkrb5-3 | 3 |
| libkrb5support0 | 3 |
| libgssapi-krb5-2 | 3 |
| ncurses-base | 2 |
| libpam-modules | 2 |
| libpam-modules-bin | 2 |
| libgcc-s1 | 2 |
| libpam-runtime | 2 |
| libncursesw6 | 2 |
| libtinfo6 | 2 |
| gcc-12-base | 2 |
| libpam0g | 2 |
| ncurses-bin | 2 |
| libstdc++6 | 2 |
| libncurses6 | 2 |
| openssl | 1 |
| curl | 1 |
| libc6 | 1 |
| coreutils | 1 |
| wget | 1 |
| locales | 1 |
| gpg | 1 |
| gnupg-utils | 1 |
| gpg-agent | 1 |
| gpgconf | 1 |
| gnupg | 1 |
| gpgsm | 1 |
| dirmngr | 1 |
| libc-bin | 1 |
| libssl3 | 1 |
| libzstd1 | 1 |
| libgcrypt20 | 1 |
| libudev1 | 1 |
| login | 1 |
| gnupg-l10n | 1 |
| libcurl4 | 1 |
| gpgv | 1 |
| libpcre2-8-0 | 1 |
| libpcre3 | 1 |
| gpg-wks-server | 1 |
| libsystemd0 | 1 |
| passwd | 1 |
| gpg-wks-client | 1 |

全量漏洞如下所示，漏洞详情请看第二部分的扫描结果。

| 漏洞名称 | 漏洞数量 |
|--- | --- |
| CVE-2022-3219 : gnupg: denial of service issue (resource consumption) using compressed packets | 11 |
| CVE-2023-45918 : ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c | 5 |
| CVE-2023-50495 : ncurses: segmentation fault via _nc_wrap_entry() | 5 |
| CVE-2024-26462 : krb5: Memory leak at /krb5/src/kdc/ndr.c | 4 |
| CVE-2024-10041 : pam: libpam: Libpam vulnerable to read hashed password | 4 |
| CVE-2024-26458 : krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | 4 |
| CVE-2024-26461 : krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | 4 |
| CVE-2024-10963 : pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass | 4 |
| CVE-2016-20013 | 3 |
| CVE-2022-27943 : binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | 3 |
| CVE-2023-4039 : gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | 3 |
| CVE-2023-7008 : systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes | 2 |
| CVE-2023-29383 : shadow: Improper input validation in shadow-utils package utility chfn | 2 |
| CVE-2024-9681 : curl: HSTS subdomain overwrites parent cache entry | 2 |
| CVE-2024-41996 : openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations | 2 |
| CVE-2021-31879 : wget: authorization header disclosure on redirect | 1 |
| CVE-2017-11164 : pcre: OP_KETRMAX feature in the match function in pcre_exec.c | 1 |
| CVE-2022-4899 : zstd: mysql: buffer overrun in util.c | 1 |
| CVE-2016-2781 : coreutils: Non-privileged session can escape to the parent session in chroot | 1 |
| CVE-2022-41409 : pcre2: negative repeat value in a pcre2test subject line leads to inifinite loop | 1 |
| CVE-2024-2236 : libgcrypt: vulnerable to Marvin Attack | 1 |

# 2. 扫描结果

## 2.1 tomcat:9.0.97-jre8-temurin-jammy (ubuntu 22.04)

| 扫描目标 | tomcat:9.0.97-jre8-temurin-jammy (ubuntu 22.04) |
|--- | --- |
| 软件包类型 | 系统层软件包 |
| 目标类型 | ubuntu |

### 2.1.1 CVE-2016-2781:coreutils: Non-privileged session can escape to the parent session in chroot

#### 2.1.1.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/coreutils@8.32-4.1ubuntu1.2?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | coreutils |
| 安装版本 | 8.32-4.1ubuntu1.2 |
| 软件包 ID | coreutils@8.32-4.1ubuntu1.2 |

#### 2.1.1.2 漏洞信息

| 漏洞编号 | CVE-2016-2781 |
|--- | --- |
| 漏洞标题 | coreutils: Non-privileged session can escape to the parent session in chroot |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2017 年 02 月 07 日 23:59:00 |
| 上次修改时间 | 2023 年 11 月 07 日 10:32:03 |

#### 2.1.1.3 漏洞描述

chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.

#### 2.1.1.4 相关链接

- https://avd.aquasec.com/nvd/cve-2016-2781
- https://git.launchpad.net/ubuntu-cve-tracker
- http://seclists.org/oss-sec/2016/q1/452
- http://www.openwall.com/lists/oss-security/2016/02/28/2
- http://www.openwall.com/lists/oss-security/2016/02/28/3
- https://access.redhat.com/security/cve/CVE-2016-2781
- https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E
- https://lore.kernel.org/patchwork/patch/793178/
- https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.28/v2.28-ReleaseNotes
- https://nvd.nist.gov/vuln/detail/CVE-2016-2781
- https://www.cve.org/CVERecord?id=CVE-2016-2781

### 2.1.2 CVE-2024-9681:curl: HSTS subdomain overwrites parent cache entry

#### 2.1.2.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.18?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | curl |
| 安装版本 | 7.81.0-1ubuntu1.18 |
| 软件包 ID | curl@7.81.0-1ubuntu1.18 |
| 修复版本 | 7.81.0-1ubuntu1.19 |

#### 2.1.2.2 漏洞信息

| 漏洞编号 | CVE-2024-9681 |
|--- | --- |
| 漏洞标题 | curl: HSTS subdomain overwrites parent cache entry |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | fixed |
| 披露时间 | 2024 年 11 月 06 日 16:15:03 |
| 上次修改时间 | 2024 年 11 月 07 日 02:17:17 |

#### 2.1.2.3 漏洞描述

When curl is asked to use HSTS, the expiry time for a subdomain might

overwrite a parent domain's cache entry, making it end sooner or later than

otherwise intended.



This affects curl using applications that enable HSTS and use URLs with the

insecure `HTTP://` scheme and perform transfers with hosts like

`x.example.com` as well as `example.com` where the first host is a subdomain

of the second host.



(The HSTS cache either needs to have been populated manually or there needs to

have been previous HTTPS accesses done as the cache needs to have entries for

the domains involved to trigger this problem.)



When `x.example.com` responds with `Strict-Transport-Security:` headers, this

bug can make the subdomain's expiry timeout *bleed over* and get set for the

parent domain `example.com` in curl's HSTS cache.



The result of a triggered bug is that HTTP accesses to `example.com` get

converted to HTTPS for a different period of time than what was asked for by

the origin server. If `example.com` for example stops supporting HTTPS at its

expiry time, curl might then fail to access `http://example.com` until the

(wrongly set) timeout expires. This bug can also expire the parent's entry

*earlier*, thus making curl inadvertently switch back to insecure HTTP earlier

than otherwise intended.

#### 2.1.2.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-9681
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-9681
- https://curl.se/docs/CVE-2024-9681.html
- https://curl.se/docs/CVE-2024-9681.json
- https://hackerone.com/reports/2764830
- https://nvd.nist.gov/vuln/detail/CVE-2024-9681
- https://ubuntu.com/security/notices/USN-7104-1
- https://www.cve.org/CVERecord?id=CVE-2024-9681

### 2.1.3 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.3.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/dirmngr@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | dirmngr |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | dirmngr@2.2.27-3ubuntu2.1 |

#### 2.1.3.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.3.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.3.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.4 CVE-2023-4039:gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64

#### 2.1.4.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gcc-12-base@12.3.0-1ubuntu1~22.04?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gcc-12-base |
| 安装版本 | 12.3.0-1ubuntu1~22.04 |
| 软件包 ID | gcc-12-base@12.3.0-1ubuntu1~22.04 |

#### 2.1.4.2 漏洞信息

| 漏洞编号 | CVE-2023-4039 |
|--- | --- |
| 漏洞标题 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 09 月 13 日 17:15:15 |
| 上次修改时间 | 2024 年 08 月 02 日 16:15:14 |

#### 2.1.4.3 漏洞描述





**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains 

that target AArch64 allows an attacker to exploit an existing buffer 

overflow in dynamically-sized local variables in your application 

without this being detected. This stack-protector failure only applies 

to C99-style dynamically-sized local variables or those created using 

alloca(). The stack-protector operates as intended for statically-sized 

local variables.



The default behavior when the stack-protector 

detects an overflow is to terminate your application, resulting in 

controlled loss of availability. An attacker who can exploit a buffer 

overflow without triggering the stack-protector might be able to change 

program flow control to cause an uncontrolled loss of availability or to

 go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.













#### 2.1.4.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-4039
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-4039
- https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64
- https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=SECURITY.txt
- https://gcc.gnu.org/pipermail/gcc-patches/2023-October/634066.html
- https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf
- https://inbox.sourceware.org/gcc-patches/46cfa37b-56eb-344d-0745-e0d35393392d@gotplt.org
- https://linux.oracle.com/cve/CVE-2023-4039.html
- https://linux.oracle.com/errata/ELSA-2023-28766.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-4039
- https://rtx.meta.security/mitigation/2023/09/12/CVE-2023-4039.html
- https://www.cve.org/CVERecord?id=CVE-2023-4039

### 2.1.5 CVE-2022-27943:binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const

#### 2.1.5.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gcc-12-base@12.3.0-1ubuntu1~22.04?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gcc-12-base |
| 安装版本 | 12.3.0-1ubuntu1~22.04 |
| 软件包 ID | gcc-12-base@12.3.0-1ubuntu1~22.04 |

#### 2.1.5.2 漏洞信息

| 漏洞编号 | CVE-2022-27943 |
|--- | --- |
| 漏洞标题 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2022 年 03 月 26 日 21:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:45:32 |

#### 2.1.5.3 漏洞描述

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

#### 2.1.5.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-27943
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-27943
- https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105039
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=1a770b01ef415e114164b6151d1e55acdee09371
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=9234cdca6ee88badfc00297e72f13dac4e540c79
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=fc968115a742d9e4674d9725ce9c2106b91b6ead
- https://gcc.gnu.org/pipermail/gcc-patches/2022-March/592244.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H424YXGW7OKXS2NCAP35OP6Y4P4AW6VG/
- https://nvd.nist.gov/vuln/detail/CVE-2022-27943
- https://sourceware.org/bugzilla/show_bug.cgi?id=28995
- https://www.cve.org/CVERecord?id=CVE-2022-27943

### 2.1.6 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.6.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gnupg@2.2.27-3ubuntu2.1?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gnupg |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gnupg@2.2.27-3ubuntu2.1 |

#### 2.1.6.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.6.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.6.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.7 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.7.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gnupg-l10n@2.2.27-3ubuntu2.1?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gnupg-l10n |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gnupg-l10n@2.2.27-3ubuntu2.1 |

#### 2.1.7.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.7.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.7.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.8 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.8.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gnupg-utils@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gnupg-utils |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gnupg-utils@2.2.27-3ubuntu2.1 |

#### 2.1.8.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.8.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.8.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.9 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.9.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpg@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpg |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpg@2.2.27-3ubuntu2.1 |

#### 2.1.9.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.9.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.9.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.10 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.10.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpg-agent@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpg-agent |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpg-agent@2.2.27-3ubuntu2.1 |

#### 2.1.10.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.10.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.10.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.11 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.11.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpg-wks-client@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpg-wks-client |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpg-wks-client@2.2.27-3ubuntu2.1 |

#### 2.1.11.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.11.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.11.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.12 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.12.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpg-wks-server@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpg-wks-server |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpg-wks-server@2.2.27-3ubuntu2.1 |

#### 2.1.12.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.12.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.12.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.13 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.13.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpgconf@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpgconf |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpgconf@2.2.27-3ubuntu2.1 |

#### 2.1.13.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.13.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.13.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.14 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.14.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpgsm@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpgsm |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpgsm@2.2.27-3ubuntu2.1 |

#### 2.1.14.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.14.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.14.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.15 CVE-2022-3219:gnupg: denial of service issue (resource consumption) using compressed packets

#### 2.1.15.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/gpgv@2.2.27-3ubuntu2.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | gpgv |
| 安装版本 | 2.2.27-3ubuntu2.1 |
| 软件包 ID | gpgv@2.2.27-3ubuntu2.1 |

#### 2.1.15.2 漏洞信息

| 漏洞编号 | CVE-2022-3219 |
|--- | --- |
| 漏洞标题 | gnupg: denial of service issue (resource consumption) using compressed packets |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

#### 2.1.15.3 漏洞描述

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

#### 2.1.15.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-3219
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-3219
- https://bugzilla.redhat.com/show_bug.cgi?id=2127010
- https://dev.gnupg.org/D556
- https://dev.gnupg.org/T5993
- https://marc.info/?l=oss-security&m=165696590211434&w=4
- https://nvd.nist.gov/vuln/detail/CVE-2022-3219
- https://security.netapp.com/advisory/ntap-20230324-0001/
- https://www.cve.org/CVERecord?id=CVE-2022-3219

### 2.1.16 CVE-2016-20013

#### 2.1.16.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libc-bin@2.35-0ubuntu3.8?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libc-bin |
| 安装版本 | 2.35-0ubuntu3.8 |
| 软件包 ID | libc-bin@2.35-0ubuntu3.8 |

#### 2.1.16.2 漏洞信息

| 漏洞编号 | CVE-2016-20013 |
|--- | --- |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2022 年 02 月 19 日 13:15:09 |
| 上次修改时间 | 2022 年 03 月 04 日 00:43:19 |

#### 2.1.16.3 漏洞描述

sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.

#### 2.1.16.4 相关链接

- https://avd.aquasec.com/nvd/cve-2016-20013
- https://git.launchpad.net/ubuntu-cve-tracker
- https://akkadia.org/drepper/SHA-crypt.txt
- https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/
- https://twitter.com/solardiz/status/795601240151457793
- https://www.cve.org/CVERecord?id=CVE-2016-20013

### 2.1.17 CVE-2016-20013

#### 2.1.17.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libc6@2.35-0ubuntu3.8?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libc6 |
| 安装版本 | 2.35-0ubuntu3.8 |
| 软件包 ID | libc6@2.35-0ubuntu3.8 |

#### 2.1.17.2 漏洞信息

| 漏洞编号 | CVE-2016-20013 |
|--- | --- |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2022 年 02 月 19 日 13:15:09 |
| 上次修改时间 | 2022 年 03 月 04 日 00:43:19 |

#### 2.1.17.3 漏洞描述

sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.

#### 2.1.17.4 相关链接

- https://avd.aquasec.com/nvd/cve-2016-20013
- https://git.launchpad.net/ubuntu-cve-tracker
- https://akkadia.org/drepper/SHA-crypt.txt
- https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/
- https://twitter.com/solardiz/status/795601240151457793
- https://www.cve.org/CVERecord?id=CVE-2016-20013

### 2.1.18 CVE-2024-9681:curl: HSTS subdomain overwrites parent cache entry

#### 2.1.18.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libcurl4@7.81.0-1ubuntu1.18?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libcurl4 |
| 安装版本 | 7.81.0-1ubuntu1.18 |
| 软件包 ID | libcurl4@7.81.0-1ubuntu1.18 |
| 修复版本 | 7.81.0-1ubuntu1.19 |

#### 2.1.18.2 漏洞信息

| 漏洞编号 | CVE-2024-9681 |
|--- | --- |
| 漏洞标题 | curl: HSTS subdomain overwrites parent cache entry |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | fixed |
| 披露时间 | 2024 年 11 月 06 日 16:15:03 |
| 上次修改时间 | 2024 年 11 月 07 日 02:17:17 |

#### 2.1.18.3 漏洞描述

When curl is asked to use HSTS, the expiry time for a subdomain might

overwrite a parent domain's cache entry, making it end sooner or later than

otherwise intended.



This affects curl using applications that enable HSTS and use URLs with the

insecure `HTTP://` scheme and perform transfers with hosts like

`x.example.com` as well as `example.com` where the first host is a subdomain

of the second host.



(The HSTS cache either needs to have been populated manually or there needs to

have been previous HTTPS accesses done as the cache needs to have entries for

the domains involved to trigger this problem.)



When `x.example.com` responds with `Strict-Transport-Security:` headers, this

bug can make the subdomain's expiry timeout *bleed over* and get set for the

parent domain `example.com` in curl's HSTS cache.



The result of a triggered bug is that HTTP accesses to `example.com` get

converted to HTTPS for a different period of time than what was asked for by

the origin server. If `example.com` for example stops supporting HTTPS at its

expiry time, curl might then fail to access `http://example.com` until the

(wrongly set) timeout expires. This bug can also expire the parent's entry

*earlier*, thus making curl inadvertently switch back to insecure HTTP earlier

than otherwise intended.

#### 2.1.18.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-9681
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-9681
- https://curl.se/docs/CVE-2024-9681.html
- https://curl.se/docs/CVE-2024-9681.json
- https://hackerone.com/reports/2764830
- https://nvd.nist.gov/vuln/detail/CVE-2024-9681
- https://ubuntu.com/security/notices/USN-7104-1
- https://www.cve.org/CVERecord?id=CVE-2024-9681

### 2.1.19 CVE-2023-4039:gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64

#### 2.1.19.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libgcc-s1@12.3.0-1ubuntu1~22.04?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libgcc-s1 |
| 安装版本 | 12.3.0-1ubuntu1~22.04 |
| 软件包 ID | libgcc-s1@12.3.0-1ubuntu1~22.04 |

#### 2.1.19.2 漏洞信息

| 漏洞编号 | CVE-2023-4039 |
|--- | --- |
| 漏洞标题 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 09 月 13 日 17:15:15 |
| 上次修改时间 | 2024 年 08 月 02 日 16:15:14 |

#### 2.1.19.3 漏洞描述





**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains 

that target AArch64 allows an attacker to exploit an existing buffer 

overflow in dynamically-sized local variables in your application 

without this being detected. This stack-protector failure only applies 

to C99-style dynamically-sized local variables or those created using 

alloca(). The stack-protector operates as intended for statically-sized 

local variables.



The default behavior when the stack-protector 

detects an overflow is to terminate your application, resulting in 

controlled loss of availability. An attacker who can exploit a buffer 

overflow without triggering the stack-protector might be able to change 

program flow control to cause an uncontrolled loss of availability or to

 go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.













#### 2.1.19.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-4039
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-4039
- https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64
- https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=SECURITY.txt
- https://gcc.gnu.org/pipermail/gcc-patches/2023-October/634066.html
- https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf
- https://inbox.sourceware.org/gcc-patches/46cfa37b-56eb-344d-0745-e0d35393392d@gotplt.org
- https://linux.oracle.com/cve/CVE-2023-4039.html
- https://linux.oracle.com/errata/ELSA-2023-28766.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-4039
- https://rtx.meta.security/mitigation/2023/09/12/CVE-2023-4039.html
- https://www.cve.org/CVERecord?id=CVE-2023-4039

### 2.1.20 CVE-2022-27943:binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const

#### 2.1.20.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libgcc-s1@12.3.0-1ubuntu1~22.04?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libgcc-s1 |
| 安装版本 | 12.3.0-1ubuntu1~22.04 |
| 软件包 ID | libgcc-s1@12.3.0-1ubuntu1~22.04 |

#### 2.1.20.2 漏洞信息

| 漏洞编号 | CVE-2022-27943 |
|--- | --- |
| 漏洞标题 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2022 年 03 月 26 日 21:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:45:32 |

#### 2.1.20.3 漏洞描述

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

#### 2.1.20.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-27943
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-27943
- https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105039
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=1a770b01ef415e114164b6151d1e55acdee09371
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=9234cdca6ee88badfc00297e72f13dac4e540c79
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=fc968115a742d9e4674d9725ce9c2106b91b6ead
- https://gcc.gnu.org/pipermail/gcc-patches/2022-March/592244.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H424YXGW7OKXS2NCAP35OP6Y4P4AW6VG/
- https://nvd.nist.gov/vuln/detail/CVE-2022-27943
- https://sourceware.org/bugzilla/show_bug.cgi?id=28995
- https://www.cve.org/CVERecord?id=CVE-2022-27943

### 2.1.21 CVE-2024-2236:libgcrypt: vulnerable to Marvin Attack

#### 2.1.21.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libgcrypt20@1.9.4-3ubuntu3?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libgcrypt20 |
| 安装版本 | 1.9.4-3ubuntu3 |
| 软件包 ID | libgcrypt20@1.9.4-3ubuntu3 |

#### 2.1.21.2 漏洞信息

| 漏洞编号 | CVE-2024-2236 |
|--- | --- |
| 漏洞标题 | libgcrypt: vulnerable to Marvin Attack |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 03 月 07 日 06:15:57 |
| 上次修改时间 | 2024 年 11 月 13 日 02:15:20 |

#### 2.1.21.3 漏洞描述

A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA ciphertexts.

#### 2.1.21.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-2236
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9404
- https://access.redhat.com/security/cve/CVE-2024-2236
- https://bugzilla.redhat.com/2245218
- https://bugzilla.redhat.com/show_bug.cgi?id=2245218
- https://dev.gnupg.org/T7136
- https://errata.almalinux.org/9/ALSA-2024-9404.html
- https://github.com/tomato42/marvin-toolkit/tree/master/example/libgcrypt
- https://gitlab.com/redhat-crypto/libgcrypt/libgcrypt-mirror/-/merge_requests/17
- https://linux.oracle.com/cve/CVE-2024-2236.html
- https://linux.oracle.com/errata/ELSA-2024-9404.html
- https://lists.gnupg.org/pipermail/gcrypt-devel/2024-March/005607.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-2236
- https://www.cve.org/CVERecord?id=CVE-2024-2236

### 2.1.22 CVE-2024-26462:krb5: Memory leak at /krb5/src/kdc/ndr.c

#### 2.1.22.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libgssapi-krb5-2@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libgssapi-krb5-2 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libgssapi-krb5-2@1.19.2-2ubuntu0.4 |

#### 2.1.22.2 漏洞信息

| 漏洞编号 | CVE-2024-26462 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

#### 2.1.22.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.

#### 2.1.22.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26462
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26462
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md
- https://linux.oracle.com/cve/CVE-2024-26462.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26462
- https://security.netapp.com/advisory/ntap-20240415-0012/
- https://www.cve.org/CVERecord?id=CVE-2024-26462

### 2.1.23 CVE-2024-26458:krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c

#### 2.1.23.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libgssapi-krb5-2@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libgssapi-krb5-2 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libgssapi-krb5-2@1.19.2-2ubuntu0.4 |

#### 2.1.23.2 漏洞信息

| 漏洞编号 | CVE-2024-26458 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

#### 2.1.23.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

#### 2.1.23.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26458
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26458
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md
- https://linux.oracle.com/cve/CVE-2024-26458.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26458
- https://security.netapp.com/advisory/ntap-20240415-0010/
- https://www.cve.org/CVERecord?id=CVE-2024-26458

### 2.1.24 CVE-2024-26461:krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c

#### 2.1.24.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libgssapi-krb5-2@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libgssapi-krb5-2 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libgssapi-krb5-2@1.19.2-2ubuntu0.4 |

#### 2.1.24.2 漏洞信息

| 漏洞编号 | CVE-2024-26461 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

#### 2.1.24.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

#### 2.1.24.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26461
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26461
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md
- https://linux.oracle.com/cve/CVE-2024-26461.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26461
- https://security.netapp.com/advisory/ntap-20240415-0011/
- https://www.cve.org/CVERecord?id=CVE-2024-26461

### 2.1.25 CVE-2024-26462:krb5: Memory leak at /krb5/src/kdc/ndr.c

#### 2.1.25.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libk5crypto3@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libk5crypto3 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libk5crypto3@1.19.2-2ubuntu0.4 |

#### 2.1.25.2 漏洞信息

| 漏洞编号 | CVE-2024-26462 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

#### 2.1.25.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.

#### 2.1.25.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26462
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26462
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md
- https://linux.oracle.com/cve/CVE-2024-26462.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26462
- https://security.netapp.com/advisory/ntap-20240415-0012/
- https://www.cve.org/CVERecord?id=CVE-2024-26462

### 2.1.26 CVE-2024-26458:krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c

#### 2.1.26.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libk5crypto3@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libk5crypto3 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libk5crypto3@1.19.2-2ubuntu0.4 |

#### 2.1.26.2 漏洞信息

| 漏洞编号 | CVE-2024-26458 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

#### 2.1.26.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

#### 2.1.26.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26458
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26458
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md
- https://linux.oracle.com/cve/CVE-2024-26458.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26458
- https://security.netapp.com/advisory/ntap-20240415-0010/
- https://www.cve.org/CVERecord?id=CVE-2024-26458

### 2.1.27 CVE-2024-26461:krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c

#### 2.1.27.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libk5crypto3@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libk5crypto3 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libk5crypto3@1.19.2-2ubuntu0.4 |

#### 2.1.27.2 漏洞信息

| 漏洞编号 | CVE-2024-26461 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

#### 2.1.27.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

#### 2.1.27.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26461
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26461
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md
- https://linux.oracle.com/cve/CVE-2024-26461.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26461
- https://security.netapp.com/advisory/ntap-20240415-0011/
- https://www.cve.org/CVERecord?id=CVE-2024-26461

### 2.1.28 CVE-2024-26462:krb5: Memory leak at /krb5/src/kdc/ndr.c

#### 2.1.28.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libkrb5-3@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libkrb5-3 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libkrb5-3@1.19.2-2ubuntu0.4 |

#### 2.1.28.2 漏洞信息

| 漏洞编号 | CVE-2024-26462 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

#### 2.1.28.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.

#### 2.1.28.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26462
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26462
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md
- https://linux.oracle.com/cve/CVE-2024-26462.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26462
- https://security.netapp.com/advisory/ntap-20240415-0012/
- https://www.cve.org/CVERecord?id=CVE-2024-26462

### 2.1.29 CVE-2024-26458:krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c

#### 2.1.29.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libkrb5-3@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libkrb5-3 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libkrb5-3@1.19.2-2ubuntu0.4 |

#### 2.1.29.2 漏洞信息

| 漏洞编号 | CVE-2024-26458 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

#### 2.1.29.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

#### 2.1.29.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26458
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26458
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md
- https://linux.oracle.com/cve/CVE-2024-26458.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26458
- https://security.netapp.com/advisory/ntap-20240415-0010/
- https://www.cve.org/CVERecord?id=CVE-2024-26458

### 2.1.30 CVE-2024-26461:krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c

#### 2.1.30.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libkrb5-3@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libkrb5-3 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libkrb5-3@1.19.2-2ubuntu0.4 |

#### 2.1.30.2 漏洞信息

| 漏洞编号 | CVE-2024-26461 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

#### 2.1.30.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

#### 2.1.30.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26461
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26461
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md
- https://linux.oracle.com/cve/CVE-2024-26461.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26461
- https://security.netapp.com/advisory/ntap-20240415-0011/
- https://www.cve.org/CVERecord?id=CVE-2024-26461

### 2.1.31 CVE-2024-26462:krb5: Memory leak at /krb5/src/kdc/ndr.c

#### 2.1.31.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libkrb5support0@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libkrb5support0 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libkrb5support0@1.19.2-2ubuntu0.4 |

#### 2.1.31.2 漏洞信息

| 漏洞编号 | CVE-2024-26462 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/kdc/ndr.c |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

#### 2.1.31.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.

#### 2.1.31.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26462
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26462
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md
- https://linux.oracle.com/cve/CVE-2024-26462.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26462
- https://security.netapp.com/advisory/ntap-20240415-0012/
- https://www.cve.org/CVERecord?id=CVE-2024-26462

### 2.1.32 CVE-2024-26458:krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c

#### 2.1.32.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libkrb5support0@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libkrb5support0 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libkrb5support0@1.19.2-2ubuntu0.4 |

#### 2.1.32.2 漏洞信息

| 漏洞编号 | CVE-2024-26458 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

#### 2.1.32.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

#### 2.1.32.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26458
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26458
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md
- https://linux.oracle.com/cve/CVE-2024-26458.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26458
- https://security.netapp.com/advisory/ntap-20240415-0010/
- https://www.cve.org/CVERecord?id=CVE-2024-26458

### 2.1.33 CVE-2024-26461:krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c

#### 2.1.33.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libkrb5support0@1.19.2-2ubuntu0.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libkrb5support0 |
| 安装版本 | 1.19.2-2ubuntu0.4 |
| 软件包 ID | libkrb5support0@1.19.2-2ubuntu0.4 |

#### 2.1.33.2 漏洞信息

| 漏洞编号 | CVE-2024-26461 |
|--- | --- |
| 漏洞标题 | krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

#### 2.1.33.3 漏洞描述

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

#### 2.1.33.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-26461
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:9331
- https://access.redhat.com/security/cve/CVE-2024-26461
- https://bugzilla.redhat.com/2266731
- https://bugzilla.redhat.com/2266740
- https://bugzilla.redhat.com/2266742
- https://bugzilla.redhat.com/show_bug.cgi?id=2266731
- https://bugzilla.redhat.com/show_bug.cgi?id=2266740
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26458
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-26461
- https://errata.almalinux.org/9/ALSA-2024-9331.html
- https://errata.rockylinux.org/RLSA-2024:3268
- https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md
- https://linux.oracle.com/cve/CVE-2024-26461.html
- https://linux.oracle.com/errata/ELSA-2024-9331.html
- https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html
- https://nvd.nist.gov/vuln/detail/CVE-2024-26461
- https://security.netapp.com/advisory/ntap-20240415-0011/
- https://www.cve.org/CVERecord?id=CVE-2024-26461

### 2.1.34 CVE-2023-45918:ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c

#### 2.1.34.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libncurses6@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libncurses6 |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | libncurses6@6.3-2ubuntu0.1 |

#### 2.1.34.2 漏洞信息

| 漏洞编号 | CVE-2023-45918 |
|--- | --- |
| 漏洞标题 | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

#### 2.1.34.3 漏洞描述

ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c. NOTE: Multiple third parties have disputed this indicating upstream does not regard it as a security issue.

#### 2.1.34.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-45918
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-45918
- https://bugzilla.redhat.com/show_bug.cgi?id=2300290#c1
- https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-45918
- https://security.netapp.com/advisory/ntap-20240315-0006/
- https://www.cve.org/CVERecord?id=CVE-2023-45918

### 2.1.35 CVE-2023-50495:ncurses: segmentation fault via _nc_wrap_entry()

#### 2.1.35.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libncurses6@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libncurses6 |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | libncurses6@6.3-2ubuntu0.1 |

#### 2.1.35.2 漏洞信息

| 漏洞编号 | CVE-2023-50495 |
|--- | --- |
| 漏洞标题 | ncurses: segmentation fault via _nc_wrap_entry() |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

#### 2.1.35.3 漏洞描述

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

#### 2.1.35.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-50495
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-50495
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-50495
- https://security.netapp.com/advisory/ntap-20240119-0008/
- https://ubuntu.com/security/notices/USN-6684-1
- https://www.cve.org/CVERecord?id=CVE-2023-50495

### 2.1.36 CVE-2023-45918:ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c

#### 2.1.36.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libncursesw6@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libncursesw6 |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | libncursesw6@6.3-2ubuntu0.1 |

#### 2.1.36.2 漏洞信息

| 漏洞编号 | CVE-2023-45918 |
|--- | --- |
| 漏洞标题 | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

#### 2.1.36.3 漏洞描述

ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c. NOTE: Multiple third parties have disputed this indicating upstream does not regard it as a security issue.

#### 2.1.36.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-45918
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-45918
- https://bugzilla.redhat.com/show_bug.cgi?id=2300290#c1
- https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-45918
- https://security.netapp.com/advisory/ntap-20240315-0006/
- https://www.cve.org/CVERecord?id=CVE-2023-45918

### 2.1.37 CVE-2023-50495:ncurses: segmentation fault via _nc_wrap_entry()

#### 2.1.37.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libncursesw6@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libncursesw6 |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | libncursesw6@6.3-2ubuntu0.1 |

#### 2.1.37.2 漏洞信息

| 漏洞编号 | CVE-2023-50495 |
|--- | --- |
| 漏洞标题 | ncurses: segmentation fault via _nc_wrap_entry() |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

#### 2.1.37.3 漏洞描述

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

#### 2.1.37.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-50495
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-50495
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-50495
- https://security.netapp.com/advisory/ntap-20240119-0008/
- https://ubuntu.com/security/notices/USN-6684-1
- https://www.cve.org/CVERecord?id=CVE-2023-50495

### 2.1.38 CVE-2024-10041:pam: libpam: Libpam vulnerable to read hashed password

#### 2.1.38.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam-modules@1.4.0-11ubuntu2.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam-modules |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam-modules@1.4.0-11ubuntu2.4 |

#### 2.1.38.2 漏洞信息

| 漏洞编号 | CVE-2024-10041 |
|--- | --- |
| 漏洞标题 | pam: libpam: Libpam vulnerable to read hashed password |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

#### 2.1.38.3 漏洞描述

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

#### 2.1.38.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10041
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10041
- https://bugzilla.redhat.com/show_bug.cgi?id=2319212
- https://nvd.nist.gov/vuln/detail/CVE-2024-10041
- https://www.cve.org/CVERecord?id=CVE-2024-10041

### 2.1.39 CVE-2024-10963:pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass

#### 2.1.39.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam-modules@1.4.0-11ubuntu2.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam-modules |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam-modules@1.4.0-11ubuntu2.4 |

#### 2.1.39.2 漏洞信息

| 漏洞编号 | CVE-2024-10963 |
|--- | --- |
| 漏洞标题 | pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

#### 2.1.39.3 漏洞描述

A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.

#### 2.1.39.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10963
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10963
- https://bugzilla.redhat.com/show_bug.cgi?id=2324291
- https://nvd.nist.gov/vuln/detail/CVE-2024-10963
- https://www.cve.org/CVERecord?id=CVE-2024-10963

### 2.1.40 CVE-2024-10041:pam: libpam: Libpam vulnerable to read hashed password

#### 2.1.40.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam-modules-bin@1.4.0-11ubuntu2.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam-modules-bin |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam-modules-bin@1.4.0-11ubuntu2.4 |

#### 2.1.40.2 漏洞信息

| 漏洞编号 | CVE-2024-10041 |
|--- | --- |
| 漏洞标题 | pam: libpam: Libpam vulnerable to read hashed password |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

#### 2.1.40.3 漏洞描述

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

#### 2.1.40.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10041
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10041
- https://bugzilla.redhat.com/show_bug.cgi?id=2319212
- https://nvd.nist.gov/vuln/detail/CVE-2024-10041
- https://www.cve.org/CVERecord?id=CVE-2024-10041

### 2.1.41 CVE-2024-10963:pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass

#### 2.1.41.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam-modules-bin@1.4.0-11ubuntu2.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam-modules-bin |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam-modules-bin@1.4.0-11ubuntu2.4 |

#### 2.1.41.2 漏洞信息

| 漏洞编号 | CVE-2024-10963 |
|--- | --- |
| 漏洞标题 | pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

#### 2.1.41.3 漏洞描述

A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.

#### 2.1.41.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10963
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10963
- https://bugzilla.redhat.com/show_bug.cgi?id=2324291
- https://nvd.nist.gov/vuln/detail/CVE-2024-10963
- https://www.cve.org/CVERecord?id=CVE-2024-10963

### 2.1.42 CVE-2024-10041:pam: libpam: Libpam vulnerable to read hashed password

#### 2.1.42.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam-runtime@1.4.0-11ubuntu2.4?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam-runtime |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam-runtime@1.4.0-11ubuntu2.4 |

#### 2.1.42.2 漏洞信息

| 漏洞编号 | CVE-2024-10041 |
|--- | --- |
| 漏洞标题 | pam: libpam: Libpam vulnerable to read hashed password |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

#### 2.1.42.3 漏洞描述

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

#### 2.1.42.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10041
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10041
- https://bugzilla.redhat.com/show_bug.cgi?id=2319212
- https://nvd.nist.gov/vuln/detail/CVE-2024-10041
- https://www.cve.org/CVERecord?id=CVE-2024-10041

### 2.1.43 CVE-2024-10963:pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass

#### 2.1.43.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam-runtime@1.4.0-11ubuntu2.4?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam-runtime |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam-runtime@1.4.0-11ubuntu2.4 |

#### 2.1.43.2 漏洞信息

| 漏洞编号 | CVE-2024-10963 |
|--- | --- |
| 漏洞标题 | pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

#### 2.1.43.3 漏洞描述

A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.

#### 2.1.43.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10963
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10963
- https://bugzilla.redhat.com/show_bug.cgi?id=2324291
- https://nvd.nist.gov/vuln/detail/CVE-2024-10963
- https://www.cve.org/CVERecord?id=CVE-2024-10963

### 2.1.44 CVE-2024-10041:pam: libpam: Libpam vulnerable to read hashed password

#### 2.1.44.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam0g@1.4.0-11ubuntu2.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam0g |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam0g@1.4.0-11ubuntu2.4 |

#### 2.1.44.2 漏洞信息

| 漏洞编号 | CVE-2024-10041 |
|--- | --- |
| 漏洞标题 | pam: libpam: Libpam vulnerable to read hashed password |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

#### 2.1.44.3 漏洞描述

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

#### 2.1.44.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10041
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10041
- https://bugzilla.redhat.com/show_bug.cgi?id=2319212
- https://nvd.nist.gov/vuln/detail/CVE-2024-10041
- https://www.cve.org/CVERecord?id=CVE-2024-10041

### 2.1.45 CVE-2024-10963:pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass

#### 2.1.45.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpam0g@1.4.0-11ubuntu2.4?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpam0g |
| 安装版本 | 1.4.0-11ubuntu2.4 |
| 软件包 ID | libpam0g@1.4.0-11ubuntu2.4 |

#### 2.1.45.2 漏洞信息

| 漏洞编号 | CVE-2024-10963 |
|--- | --- |
| 漏洞标题 | pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

#### 2.1.45.3 漏洞描述

A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.

#### 2.1.45.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-10963
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-10963
- https://bugzilla.redhat.com/show_bug.cgi?id=2324291
- https://nvd.nist.gov/vuln/detail/CVE-2024-10963
- https://www.cve.org/CVERecord?id=CVE-2024-10963

### 2.1.46 CVE-2022-41409:pcre2: negative repeat value in a pcre2test subject line leads to inifinite loop

#### 2.1.46.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpcre2-8-0@10.39-3ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libpcre2-8-0 |
| 安装版本 | 10.39-3ubuntu0.1 |
| 软件包 ID | libpcre2-8-0@10.39-3ubuntu0.1 |

#### 2.1.46.2 漏洞信息

| 漏洞编号 | CVE-2022-41409 |
|--- | --- |
| 漏洞标题 | pcre2: negative repeat value in a pcre2test subject line leads to inifinite loop |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 07 月 18 日 22:15:12 |
| 上次修改时间 | 2023 年 07 月 27 日 11:46:09 |

#### 2.1.46.3 漏洞描述

Integer overflow vulnerability in pcre2test before 10.41 allows attackers to cause a denial of service or other unspecified impacts via negative input.

#### 2.1.46.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-41409
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-41409
- https://github.com/PCRE2Project/pcre2/commit/94e1c001761373b7d9450768aa15d04c25547a35
- https://github.com/PCRE2Project/pcre2/issues/141
- https://github.com/advisories/GHSA-4qfx-v7wh-3q4j
- https://nvd.nist.gov/vuln/detail/CVE-2022-41409
- https://www.cve.org/CVERecord?id=CVE-2022-41409

### 2.1.47 CVE-2017-11164:pcre: OP_KETRMAX feature in the match function in pcre_exec.c

#### 2.1.47.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libpcre3@8.39-13ubuntu0.22.04.1?arch=amd64&distro=ubuntu-22.04&epoch=2 |
|--- | --- |
| 软件包名称 | libpcre3 |
| 安装版本 | 2:8.39-13ubuntu0.22.04.1 |
| 软件包 ID | libpcre3@2:8.39-13ubuntu0.22.04.1 |

#### 2.1.47.2 漏洞信息

| 漏洞编号 | CVE-2017-11164 |
|--- | --- |
| 漏洞标题 | pcre: OP_KETRMAX feature in the match function in pcre_exec.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2017 年 07 月 11 日 11:29:00 |
| 上次修改时间 | 2023 年 11 月 07 日 10:38:10 |

#### 2.1.47.3 漏洞描述

In PCRE 8.41, the OP_KETRMAX feature in the match function in pcre_exec.c allows stack exhaustion (uncontrolled recursion) when processing a crafted regular expression.

#### 2.1.47.4 相关链接

- https://avd.aquasec.com/nvd/cve-2017-11164
- https://git.launchpad.net/ubuntu-cve-tracker
- http://openwall.com/lists/oss-security/2017/07/11/3
- http://www.openwall.com/lists/oss-security/2023/04/11/1
- http://www.openwall.com/lists/oss-security/2023/04/12/1
- http://www.securityfocus.com/bid/99575
- https://access.redhat.com/security/cve/CVE-2017-11164
- https://lists.apache.org/thread.html/rf9fa47ab66495c78bb4120b0754dd9531ca2ff0430f6685ac9b07772%40%3Cdev.mina.apache.org%3E
- https://nvd.nist.gov/vuln/detail/CVE-2017-11164
- https://www.cve.org/CVERecord?id=CVE-2017-11164

### 2.1.48 CVE-2024-41996:openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations

#### 2.1.48.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libssl3 |
| 安装版本 | 3.0.2-0ubuntu1.18 |
| 软件包 ID | libssl3@3.0.2-0ubuntu1.18 |

#### 2.1.48.2 漏洞信息

| 漏洞编号 | CVE-2024-41996 |
|--- | --- |
| 漏洞标题 | openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 08 月 26 日 14:15:04 |
| 上次修改时间 | 2024 年 08 月 27 日 00:35:11 |

#### 2.1.48.3 漏洞描述

Validating the order of the public keys in the Diffie-Hellman Key Agreement Protocol, when an approved safe prime is used, allows remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations. The client may cause asymmetric resource consumption. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE and validate the order of the public key.

#### 2.1.48.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-41996
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-41996
- https://dheatattack.gitlab.io/details/
- https://dheatattack.gitlab.io/faq/
- https://gist.github.com/c0r0n3r/abccc14d4d96c0442f3a77fa5ca255d1
- https://github.com/openssl/openssl/issues/17374
- https://github.com/openssl/openssl/pull/25088
- https://nvd.nist.gov/vuln/detail/CVE-2024-41996
- https://openssl-library.org/post/2022-10-21-tls-groups-configuration/
- https://www.cve.org/CVERecord?id=CVE-2024-41996

### 2.1.49 CVE-2023-4039:gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64

#### 2.1.49.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libstdc%2B%2B6@12.3.0-1ubuntu1~22.04?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libstdc++6 |
| 安装版本 | 12.3.0-1ubuntu1~22.04 |
| 软件包 ID | libstdc++6@12.3.0-1ubuntu1~22.04 |

#### 2.1.49.2 漏洞信息

| 漏洞编号 | CVE-2023-4039 |
|--- | --- |
| 漏洞标题 | gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 09 月 13 日 17:15:15 |
| 上次修改时间 | 2024 年 08 月 02 日 16:15:14 |

#### 2.1.49.3 漏洞描述





**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains 

that target AArch64 allows an attacker to exploit an existing buffer 

overflow in dynamically-sized local variables in your application 

without this being detected. This stack-protector failure only applies 

to C99-style dynamically-sized local variables or those created using 

alloca(). The stack-protector operates as intended for statically-sized 

local variables.



The default behavior when the stack-protector 

detects an overflow is to terminate your application, resulting in 

controlled loss of availability. An attacker who can exploit a buffer 

overflow without triggering the stack-protector might be able to change 

program flow control to cause an uncontrolled loss of availability or to

 go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.













#### 2.1.49.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-4039
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-4039
- https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64
- https://gcc.gnu.org/git/?p=gcc.git;a=blob_plain;f=SECURITY.txt
- https://gcc.gnu.org/pipermail/gcc-patches/2023-October/634066.html
- https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf
- https://inbox.sourceware.org/gcc-patches/46cfa37b-56eb-344d-0745-e0d35393392d@gotplt.org
- https://linux.oracle.com/cve/CVE-2023-4039.html
- https://linux.oracle.com/errata/ELSA-2023-28766.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-4039
- https://rtx.meta.security/mitigation/2023/09/12/CVE-2023-4039.html
- https://www.cve.org/CVERecord?id=CVE-2023-4039

### 2.1.50 CVE-2022-27943:binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const

#### 2.1.50.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libstdc%2B%2B6@12.3.0-1ubuntu1~22.04?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libstdc++6 |
| 安装版本 | 12.3.0-1ubuntu1~22.04 |
| 软件包 ID | libstdc++6@12.3.0-1ubuntu1~22.04 |

#### 2.1.50.2 漏洞信息

| 漏洞编号 | CVE-2022-27943 |
|--- | --- |
| 漏洞标题 | binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2022 年 03 月 26 日 21:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:45:32 |

#### 2.1.50.3 漏洞描述

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

#### 2.1.50.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-27943
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2022-27943
- https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105039
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=1a770b01ef415e114164b6151d1e55acdee09371
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=9234cdca6ee88badfc00297e72f13dac4e540c79
- https://gcc.gnu.org/git/gitweb.cgi?p=gcc.git;h=fc968115a742d9e4674d9725ce9c2106b91b6ead
- https://gcc.gnu.org/pipermail/gcc-patches/2022-March/592244.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/H424YXGW7OKXS2NCAP35OP6Y4P4AW6VG/
- https://nvd.nist.gov/vuln/detail/CVE-2022-27943
- https://sourceware.org/bugzilla/show_bug.cgi?id=28995
- https://www.cve.org/CVERecord?id=CVE-2022-27943

### 2.1.51 CVE-2023-7008:systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes

#### 2.1.51.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libsystemd0@249.11-0ubuntu3.12?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libsystemd0 |
| 安装版本 | 249.11-0ubuntu3.12 |
| 软件包 ID | libsystemd0@249.11-0ubuntu3.12 |

#### 2.1.51.2 漏洞信息

| 漏洞编号 | CVE-2023-7008 |
|--- | --- |
| 漏洞标题 | systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 23 日 21:15:07 |
| 上次修改时间 | 2024 年 09 月 17 日 01:16:02 |

#### 2.1.51.3 漏洞描述

A vulnerability was found in systemd-resolved. This issue may allow systemd-resolved to accept records of DNSSEC-signed domains even when they have no signature, allowing man-in-the-middles (or the upstream DNS resolver) to manipulate records.

#### 2.1.51.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-7008
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:2463
- https://access.redhat.com/errata/RHSA-2024:3203
- https://access.redhat.com/security/cve/CVE-2023-7008
- https://bugzilla.redhat.com/2222672
- https://bugzilla.redhat.com/show_bug.cgi?id=2222261
- https://bugzilla.redhat.com/show_bug.cgi?id=2222672
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7008
- https://errata.almalinux.org/9/ALSA-2024-2463.html
- https://errata.rockylinux.org/RLSA-2024:2463
- https://github.com/systemd/systemd/issues/25676
- https://linux.oracle.com/cve/CVE-2023-7008.html
- https://linux.oracle.com/errata/ELSA-2024-3203.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-7008
- https://www.cve.org/CVERecord?id=CVE-2023-7008

### 2.1.52 CVE-2023-45918:ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c

#### 2.1.52.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libtinfo6@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libtinfo6 |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | libtinfo6@6.3-2ubuntu0.1 |

#### 2.1.52.2 漏洞信息

| 漏洞编号 | CVE-2023-45918 |
|--- | --- |
| 漏洞标题 | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

#### 2.1.52.3 漏洞描述

ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c. NOTE: Multiple third parties have disputed this indicating upstream does not regard it as a security issue.

#### 2.1.52.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-45918
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-45918
- https://bugzilla.redhat.com/show_bug.cgi?id=2300290#c1
- https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-45918
- https://security.netapp.com/advisory/ntap-20240315-0006/
- https://www.cve.org/CVERecord?id=CVE-2023-45918

### 2.1.53 CVE-2023-50495:ncurses: segmentation fault via _nc_wrap_entry()

#### 2.1.53.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libtinfo6@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libtinfo6 |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | libtinfo6@6.3-2ubuntu0.1 |

#### 2.1.53.2 漏洞信息

| 漏洞编号 | CVE-2023-50495 |
|--- | --- |
| 漏洞标题 | ncurses: segmentation fault via _nc_wrap_entry() |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

#### 2.1.53.3 漏洞描述

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

#### 2.1.53.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-50495
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-50495
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-50495
- https://security.netapp.com/advisory/ntap-20240119-0008/
- https://ubuntu.com/security/notices/USN-6684-1
- https://www.cve.org/CVERecord?id=CVE-2023-50495

### 2.1.54 CVE-2023-7008:systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes

#### 2.1.54.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libudev1@249.11-0ubuntu3.12?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libudev1 |
| 安装版本 | 249.11-0ubuntu3.12 |
| 软件包 ID | libudev1@249.11-0ubuntu3.12 |

#### 2.1.54.2 漏洞信息

| 漏洞编号 | CVE-2023-7008 |
|--- | --- |
| 漏洞标题 | systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 23 日 21:15:07 |
| 上次修改时间 | 2024 年 09 月 17 日 01:16:02 |

#### 2.1.54.3 漏洞描述

A vulnerability was found in systemd-resolved. This issue may allow systemd-resolved to accept records of DNSSEC-signed domains even when they have no signature, allowing man-in-the-middles (or the upstream DNS resolver) to manipulate records.

#### 2.1.54.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-7008
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:2463
- https://access.redhat.com/errata/RHSA-2024:3203
- https://access.redhat.com/security/cve/CVE-2023-7008
- https://bugzilla.redhat.com/2222672
- https://bugzilla.redhat.com/show_bug.cgi?id=2222261
- https://bugzilla.redhat.com/show_bug.cgi?id=2222672
- https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-7008
- https://errata.almalinux.org/9/ALSA-2024-2463.html
- https://errata.rockylinux.org/RLSA-2024:2463
- https://github.com/systemd/systemd/issues/25676
- https://linux.oracle.com/cve/CVE-2023-7008.html
- https://linux.oracle.com/errata/ELSA-2024-3203.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-7008
- https://www.cve.org/CVERecord?id=CVE-2023-7008

### 2.1.55 CVE-2022-4899:zstd: mysql: buffer overrun in util.c

#### 2.1.55.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/libzstd1@1.4.8%2Bdfsg-3build1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | libzstd1 |
| 安装版本 | 1.4.8+dfsg-3build1 |
| 软件包 ID | libzstd1@1.4.8+dfsg-3build1 |

#### 2.1.55.2 漏洞信息

| 漏洞编号 | CVE-2022-4899 |
|--- | --- |
| 漏洞标题 | zstd: mysql: buffer overrun in util.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 04 月 01 日 04:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:59:16 |

#### 2.1.55.3 漏洞描述

A vulnerability was found in zstd v1.4.10, where an attacker can supply empty string as an argument to the command line tool to cause buffer overrun.

#### 2.1.55.4 相关链接

- https://avd.aquasec.com/nvd/cve-2022-4899
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/errata/RHSA-2024:1141
- https://access.redhat.com/security/cve/CVE-2022-4899
- https://bugzilla.redhat.com/2179864
- https://bugzilla.redhat.com/2188109
- https://bugzilla.redhat.com/2188113
- https://bugzilla.redhat.com/2188115
- https://bugzilla.redhat.com/2188116
- https://bugzilla.redhat.com/2188117
- https://bugzilla.redhat.com/2188118
- https://bugzilla.redhat.com/2188119
- https://bugzilla.redhat.com/2188120
- https://bugzilla.redhat.com/2188121
- https://bugzilla.redhat.com/2188122
- https://bugzilla.redhat.com/2188123
- https://bugzilla.redhat.com/2188124
- https://bugzilla.redhat.com/2188125
- https://bugzilla.redhat.com/2188127
- https://bugzilla.redhat.com/2188128
- https://bugzilla.redhat.com/2188129
- https://bugzilla.redhat.com/2188130
- https://bugzilla.redhat.com/2188131
- https://bugzilla.redhat.com/2188132
- https://bugzilla.redhat.com/2224211
- https://bugzilla.redhat.com/2224212
- https://bugzilla.redhat.com/2224213
- https://bugzilla.redhat.com/2224214
- https://bugzilla.redhat.com/2224215
- https://bugzilla.redhat.com/2224216
- https://bugzilla.redhat.com/2224217
- https://bugzilla.redhat.com/2224218
- https://bugzilla.redhat.com/2224219
- https://bugzilla.redhat.com/2224220
- https://bugzilla.redhat.com/2224221
- https://bugzilla.redhat.com/2224222
- https://bugzilla.redhat.com/2245014
- https://bugzilla.redhat.com/2245015
- https://bugzilla.redhat.com/2245016
- https://bugzilla.redhat.com/2245017
- https://bugzilla.redhat.com/2245018
- https://bugzilla.redhat.com/2245019
- https://bugzilla.redhat.com/2245020
- https://bugzilla.redhat.com/2245021
- https://bugzilla.redhat.com/2245022
- https://bugzilla.redhat.com/2245023
- https://bugzilla.redhat.com/2245024
- https://bugzilla.redhat.com/2245026
- https://bugzilla.redhat.com/2245027
- https://bugzilla.redhat.com/2245028
- https://bugzilla.redhat.com/2245029
- https://bugzilla.redhat.com/2245030
- https://bugzilla.redhat.com/2245031
- https://bugzilla.redhat.com/2245032
- https://bugzilla.redhat.com/2245033
- https://bugzilla.redhat.com/2245034
- https://bugzilla.redhat.com/2258771
- https://bugzilla.redhat.com/2258772
- https://bugzilla.redhat.com/2258773
- https://bugzilla.redhat.com/2258774
- https://bugzilla.redhat.com/2258775
- https://bugzilla.redhat.com/2258776
- https://bugzilla.redhat.com/2258777
- https://bugzilla.redhat.com/2258778
- https://bugzilla.redhat.com/2258779
- https://bugzilla.redhat.com/2258780
- https://bugzilla.redhat.com/2258781
- https://bugzilla.redhat.com/2258782
- https://bugzilla.redhat.com/2258783
- https://bugzilla.redhat.com/2258784
- https://bugzilla.redhat.com/2258785
- https://bugzilla.redhat.com/2258787
- https://bugzilla.redhat.com/2258788
- https://bugzilla.redhat.com/2258789
- https://bugzilla.redhat.com/2258790
- https://bugzilla.redhat.com/2258791
- https://bugzilla.redhat.com/2258792
- https://bugzilla.redhat.com/2258793
- https://bugzilla.redhat.com/2258794
- https://errata.almalinux.org/9/ALSA-2024-1141.html
- https://github.com/facebook/zstd
- https://github.com/facebook/zstd/issues/3200
- https://github.com/facebook/zstd/pull/3220
- https://github.com/pypa/advisory-database/tree/main/vulns/zstd/PYSEC-2023-121.yaml
- https://github.com/sergey-dryabzhinsky/python-zstd/commit/c8a619aebdbd6b838fbfef6e19325a70f631a4c6
- https://linux.oracle.com/cve/CVE-2022-4899.html
- https://linux.oracle.com/errata/ELSA-2024-1141.html
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/C63HAGVLQA6FJNDCHR7CNZZL6VSLILB2/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JEHRBBYYTPA4DETOM5XAKGCP37NUTLOA/
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QYLDK6ODVC4LJSDULLX6Q2YHTFOWABCN/
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/C63HAGVLQA6FJNDCHR7CNZZL6VSLILB2
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/JEHRBBYYTPA4DETOM5XAKGCP37NUTLOA
- https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/QYLDK6ODVC4LJSDULLX6Q2YHTFOWABCN
- https://nvd.nist.gov/vuln/detail/CVE-2022-4899
- https://security.netapp.com/advisory/ntap-20230725-0005
- https://security.netapp.com/advisory/ntap-20230725-0005/
- https://www.cve.org/CVERecord?id=CVE-2022-4899

### 2.1.56 CVE-2016-20013

#### 2.1.56.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/locales@2.35-0ubuntu3.8?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | locales |
| 安装版本 | 2.35-0ubuntu3.8 |
| 软件包 ID | locales@2.35-0ubuntu3.8 |

#### 2.1.56.2 漏洞信息

| 漏洞编号 | CVE-2016-20013 |
|--- | --- |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2022 年 02 月 19 日 13:15:09 |
| 上次修改时间 | 2022 年 03 月 04 日 00:43:19 |

#### 2.1.56.3 漏洞描述

sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.

#### 2.1.56.4 相关链接

- https://avd.aquasec.com/nvd/cve-2016-20013
- https://git.launchpad.net/ubuntu-cve-tracker
- https://akkadia.org/drepper/SHA-crypt.txt
- https://pthree.org/2018/05/23/do-not-use-sha256crypt-sha512crypt-theyre-dangerous/
- https://twitter.com/solardiz/status/795601240151457793
- https://www.cve.org/CVERecord?id=CVE-2016-20013

### 2.1.57 CVE-2023-29383:shadow: Improper input validation in shadow-utils package utility chfn

#### 2.1.57.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/login@4.8.1-2ubuntu2.2?arch=amd64&distro=ubuntu-22.04&epoch=1 |
|--- | --- |
| 软件包名称 | login |
| 安装版本 | 1:4.8.1-2ubuntu2.2 |
| 软件包 ID | login@1:4.8.1-2ubuntu2.2 |

#### 2.1.57.2 漏洞信息

| 漏洞编号 | CVE-2023-29383 |
|--- | --- |
| 漏洞标题 | shadow: Improper input validation in shadow-utils package utility chfn |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 04 月 15 日 06:15:07 |
| 上次修改时间 | 2023 年 04 月 25 日 02:05:30 |

#### 2.1.57.3 漏洞描述

In Shadow 4.13, it is possible to inject control characters into fields provided to the SUID program chfn (change finger). Although it is not possible to exploit this directly (e.g., adding a new user fails because \n is in the block list), it is possible to misrepresent the /etc/passwd file when viewed. Use of \r manipulations and Unicode characters to work around blocking of the : character make it possible to give the impression that a new user has been added. In other words, an adversary may be able to convince a system administrator to take the system offline (an indirect, social-engineered denial of service) by demonstrating that "cat /etc/passwd" shows a rogue user account.

#### 2.1.57.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-29383
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-29383
- https://github.com/shadow-maint/shadow/commit/e5905c4b84d4fb90aefcd96ee618411ebfac663d
- https://github.com/shadow-maint/shadow/pull/687
- https://nvd.nist.gov/vuln/detail/CVE-2023-29383
- https://www.cve.org/CVERecord?id=CVE-2023-29383
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2023-29383-abusing-linux-chfn-to-misrepresent-etc-passwd/
- https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=31797

### 2.1.58 CVE-2023-45918:ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c

#### 2.1.58.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/ncurses-base@6.3-2ubuntu0.1?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | ncurses-base |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | ncurses-base@6.3-2ubuntu0.1 |

#### 2.1.58.2 漏洞信息

| 漏洞编号 | CVE-2023-45918 |
|--- | --- |
| 漏洞标题 | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

#### 2.1.58.3 漏洞描述

ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c. NOTE: Multiple third parties have disputed this indicating upstream does not regard it as a security issue.

#### 2.1.58.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-45918
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-45918
- https://bugzilla.redhat.com/show_bug.cgi?id=2300290#c1
- https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-45918
- https://security.netapp.com/advisory/ntap-20240315-0006/
- https://www.cve.org/CVERecord?id=CVE-2023-45918

### 2.1.59 CVE-2023-50495:ncurses: segmentation fault via _nc_wrap_entry()

#### 2.1.59.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/ncurses-base@6.3-2ubuntu0.1?arch=all&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | ncurses-base |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | ncurses-base@6.3-2ubuntu0.1 |

#### 2.1.59.2 漏洞信息

| 漏洞编号 | CVE-2023-50495 |
|--- | --- |
| 漏洞标题 | ncurses: segmentation fault via _nc_wrap_entry() |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

#### 2.1.59.3 漏洞描述

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

#### 2.1.59.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-50495
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-50495
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-50495
- https://security.netapp.com/advisory/ntap-20240119-0008/
- https://ubuntu.com/security/notices/USN-6684-1
- https://www.cve.org/CVERecord?id=CVE-2023-50495

### 2.1.60 CVE-2023-45918:ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c

#### 2.1.60.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/ncurses-bin@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | ncurses-bin |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | ncurses-bin@6.3-2ubuntu0.1 |

#### 2.1.60.2 漏洞信息

| 漏洞编号 | CVE-2023-45918 |
|--- | --- |
| 漏洞标题 | ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

#### 2.1.60.3 漏洞描述

ncurses 6.4-20230610 has a NULL pointer dereference in tgetstr in tinfo/lib_termcap.c. NOTE: Multiple third parties have disputed this indicating upstream does not regard it as a security issue.

#### 2.1.60.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-45918
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-45918
- https://bugzilla.redhat.com/show_bug.cgi?id=2300290#c1
- https://lists.gnu.org/archive/html/bug-ncurses/2023-06/msg00005.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-45918
- https://security.netapp.com/advisory/ntap-20240315-0006/
- https://www.cve.org/CVERecord?id=CVE-2023-45918

### 2.1.61 CVE-2023-50495:ncurses: segmentation fault via _nc_wrap_entry()

#### 2.1.61.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/ncurses-bin@6.3-2ubuntu0.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | ncurses-bin |
| 安装版本 | 6.3-2ubuntu0.1 |
| 软件包 ID | ncurses-bin@6.3-2ubuntu0.1 |

#### 2.1.61.2 漏洞信息

| 漏洞编号 | CVE-2023-50495 |
|--- | --- |
| 漏洞标题 | ncurses: segmentation fault via _nc_wrap_entry() |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

#### 2.1.61.3 漏洞描述

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

#### 2.1.61.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-50495
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-50495
- https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LU4MYMKFEZQ5VSCVLRIZGDQOUW3T44GT/
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00020.html
- https://lists.gnu.org/archive/html/bug-ncurses/2023-04/msg00029.html
- https://nvd.nist.gov/vuln/detail/CVE-2023-50495
- https://security.netapp.com/advisory/ntap-20240119-0008/
- https://ubuntu.com/security/notices/USN-6684-1
- https://www.cve.org/CVERecord?id=CVE-2023-50495

### 2.1.62 CVE-2024-41996:openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations

#### 2.1.62.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | openssl |
| 安装版本 | 3.0.2-0ubuntu1.18 |
| 软件包 ID | openssl@3.0.2-0ubuntu1.18 |

#### 2.1.62.2 漏洞信息

| 漏洞编号 | CVE-2024-41996 |
|--- | --- |
| 漏洞标题 | openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2024 年 08 月 26 日 14:15:04 |
| 上次修改时间 | 2024 年 08 月 27 日 00:35:11 |

#### 2.1.62.3 漏洞描述

Validating the order of the public keys in the Diffie-Hellman Key Agreement Protocol, when an approved safe prime is used, allows remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations. The client may cause asymmetric resource consumption. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE and validate the order of the public key.

#### 2.1.62.4 相关链接

- https://avd.aquasec.com/nvd/cve-2024-41996
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2024-41996
- https://dheatattack.gitlab.io/details/
- https://dheatattack.gitlab.io/faq/
- https://gist.github.com/c0r0n3r/abccc14d4d96c0442f3a77fa5ca255d1
- https://github.com/openssl/openssl/issues/17374
- https://github.com/openssl/openssl/pull/25088
- https://nvd.nist.gov/vuln/detail/CVE-2024-41996
- https://openssl-library.org/post/2022-10-21-tls-groups-configuration/
- https://www.cve.org/CVERecord?id=CVE-2024-41996

### 2.1.63 CVE-2023-29383:shadow: Improper input validation in shadow-utils package utility chfn

#### 2.1.63.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/passwd@4.8.1-2ubuntu2.2?arch=amd64&distro=ubuntu-22.04&epoch=1 |
|--- | --- |
| 软件包名称 | passwd |
| 安装版本 | 1:4.8.1-2ubuntu2.2 |
| 软件包 ID | passwd@1:4.8.1-2ubuntu2.2 |

#### 2.1.63.2 漏洞信息

| 漏洞编号 | CVE-2023-29383 |
|--- | --- |
| 漏洞标题 | shadow: Improper input validation in shadow-utils package utility chfn |
| 威胁等级 | 低危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2023 年 04 月 15 日 06:15:07 |
| 上次修改时间 | 2023 年 04 月 25 日 02:05:30 |

#### 2.1.63.3 漏洞描述

In Shadow 4.13, it is possible to inject control characters into fields provided to the SUID program chfn (change finger). Although it is not possible to exploit this directly (e.g., adding a new user fails because \n is in the block list), it is possible to misrepresent the /etc/passwd file when viewed. Use of \r manipulations and Unicode characters to work around blocking of the : character make it possible to give the impression that a new user has been added. In other words, an adversary may be able to convince a system administrator to take the system offline (an indirect, social-engineered denial of service) by demonstrating that "cat /etc/passwd" shows a rogue user account.

#### 2.1.63.4 相关链接

- https://avd.aquasec.com/nvd/cve-2023-29383
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2023-29383
- https://github.com/shadow-maint/shadow/commit/e5905c4b84d4fb90aefcd96ee618411ebfac663d
- https://github.com/shadow-maint/shadow/pull/687
- https://nvd.nist.gov/vuln/detail/CVE-2023-29383
- https://www.cve.org/CVERecord?id=CVE-2023-29383
- https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2023-29383-abusing-linux-chfn-to-misrepresent-etc-passwd/
- https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=31797

### 2.1.64 CVE-2021-31879:wget: authorization header disclosure on redirect

#### 2.1.64.1 软件包信息

| 软件包 URL | pkg:deb/ubuntu/wget@1.21.2-2ubuntu1.1?arch=amd64&distro=ubuntu-22.04 |
|--- | --- |
| 软件包名称 | wget |
| 安装版本 | 1.21.2-2ubuntu1.1 |
| 软件包 ID | wget@1.21.2-2ubuntu1.1 |

#### 2.1.64.2 漏洞信息

| 漏洞编号 | CVE-2021-31879 |
|--- | --- |
| 漏洞标题 | wget: authorization header disclosure on redirect |
| 威胁等级 | 中危 |
| 威胁等级来源 | ubuntu |
| 状态 | affected |
| 披露时间 | 2021 年 04 月 29 日 13:15:08 |
| 上次修改时间 | 2022 年 05 月 14 日 04:52:24 |

#### 2.1.64.3 漏洞描述

GNU Wget through 1.21.1 does not omit the Authorization header upon a redirect to a different origin, a related issue to CVE-2018-1000007.

#### 2.1.64.4 相关链接

- https://avd.aquasec.com/nvd/cve-2021-31879
- https://git.launchpad.net/ubuntu-cve-tracker
- https://access.redhat.com/security/cve/CVE-2021-31879
- https://mail.gnu.org/archive/html/bug-wget/2021-02/msg00002.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-31879
- https://savannah.gnu.org/bugs/?56909
- https://security.netapp.com/advisory/ntap-20210618-0002/
- https://www.cve.org/CVERecord?id=CVE-2021-31879

