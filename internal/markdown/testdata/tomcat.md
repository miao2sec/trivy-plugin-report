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
| libkrb5-3 | 3 |
| libkrb5support0 | 3 |
| libk5crypto3 | 3 |
| libgssapi-krb5-2 | 3 |
| libpam-modules-bin | 2 |
| libncursesw6 | 2 |
| libncurses6 | 2 |
| libtinfo6 | 2 |
| libpam0g | 2 |
| libgcc-s1 | 2 |
| libpam-modules | 2 |
| ncurses-base | 2 |
| gcc-12-base | 2 |
| libstdc++6 | 2 |
| libpam-runtime | 2 |
| ncurses-bin | 2 |
| openssl | 1 |
| login | 1 |
| libsystemd0 | 1 |
| libc6 | 1 |
| gpg-wks-server | 1 |
| libpcre3 | 1 |
| gnupg-l10n | 1 |
| gpgsm | 1 |
| libcurl4 | 1 |
| wget | 1 |
| libpcre2-8-0 | 1 |
| gpg | 1 |
| gnupg-utils | 1 |
| libc-bin | 1 |
| gnupg | 1 |
| coreutils | 1 |
| gpg-agent | 1 |
| libssl3 | 1 |
| libudev1 | 1 |
| gpg-wks-client | 1 |
| passwd | 1 |
| curl | 1 |
| libgcrypt20 | 1 |
| gpgconf | 1 |
| locales | 1 |
| libzstd1 | 1 |
| dirmngr | 1 |
| gpgv | 1 |

全量漏洞如下所示，漏洞详情请看第二部分的扫描结果。

| 漏洞名称 | 漏洞数量 |
|--- | --- |
| CVE-2022-3219 : gnupg: denial of service issue (resource consumption) using compressed packets | 11 |
| CVE-2023-50495 : ncurses: segmentation fault via _nc_wrap_entry() | 5 |
| CVE-2023-45918 : ncurses: NULL pointer dereference in tgetstr in tinfo/lib_termcap.c | 5 |
| CVE-2024-26461 : krb5: Memory leak at /krb5/src/lib/gssapi/krb5/k5sealv3.c | 4 |
| CVE-2024-10041 : pam: libpam: Libpam vulnerable to read hashed password | 4 |
| CVE-2024-10963 : pam: Improper Hostname Interpretation in pam_access Leads to Access Control Bypass | 4 |
| CVE-2024-26462 : krb5: Memory leak at /krb5/src/kdc/ndr.c | 4 |
| CVE-2024-26458 : krb5: Memory leak at /krb5/src/lib/rpc/pmap_rmt.c | 4 |
| CVE-2023-4039 : gcc: -fstack-protector fails to guard dynamic stack allocations on ARM64 | 3 |
| CVE-2022-27943 : binutils: libiberty/rust-demangle.c in GNU GCC 11.2 allows stack exhaustion in demangle_const | 3 |
| CVE-2016-20013 | 3 |
| CVE-2023-7008 : systemd-resolved: Unsigned name response in signed zone is not refused when DNSSEC=yes | 2 |
| CVE-2024-9681 : curl: HSTS subdomain overwrites parent cache entry | 2 |
| CVE-2024-41996 : openssl: remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations | 2 |
| CVE-2023-29383 : shadow: Improper input validation in shadow-utils package utility chfn | 2 |
| CVE-2021-31879 : wget: authorization header disclosure on redirect | 1 |
| CVE-2016-2781 : coreutils: Non-privileged session can escape to the parent session in chroot | 1 |
| CVE-2024-2236 : libgcrypt: vulnerable to Marvin Attack | 1 |
| CVE-2022-41409 : pcre2: negative repeat value in a pcre2test subject line leads to inifinite loop | 1 |
| CVE-2017-11164 : pcre: OP_KETRMAX feature in the match function in pcre_exec.c | 1 |
| CVE-2022-4899 : zstd: mysql: buffer overrun in util.c | 1 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2017 年 02 月 07 日 23:59:00 |
| 上次修改时间 | 2023 年 11 月 07 日 10:32:03 |

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
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2024 年 11 月 06 日 16:15:03 |
| 上次修改时间 | 2024 年 11 月 07 日 02:17:17 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 09 月 13 日 17:15:15 |
| 上次修改时间 | 2024 年 08 月 02 日 16:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2022 年 03 月 26 日 21:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:45:32 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 02 月 24 日 04:15:12 |
| 上次修改时间 | 2023 年 05 月 27 日 00:31:34 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2022 年 02 月 19 日 13:15:09 |
| 上次修改时间 | 2022 年 03 月 04 日 00:43:19 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2022 年 02 月 19 日 13:15:09 |
| 上次修改时间 | 2022 年 03 月 04 日 00:43:19 |

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
| 状态 | 该软件包已发布修复补丁 |
| 披露时间 | 2024 年 11 月 06 日 16:15:03 |
| 上次修改时间 | 2024 年 11 月 07 日 02:17:17 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 09 月 13 日 17:15:15 |
| 上次修改时间 | 2024 年 08 月 02 日 16:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2022 年 03 月 26 日 21:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:45:32 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 03 月 07 日 06:15:57 |
| 上次修改时间 | 2024 年 11 月 13 日 02:15:20 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:01 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 05 月 14 日 23:09:00 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 29 日 09:44:18 |
| 上次修改时间 | 2024 年 08 月 15 日 00:35:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 10 月 23 日 22:15:03 |
| 上次修改时间 | 2024 年 11 月 13 日 05:15:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 11 月 08 日 00:15:17 |
| 上次修改时间 | 2024 年 11 月 12 日 02:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 07 月 18 日 22:15:12 |
| 上次修改时间 | 2023 年 07 月 27 日 11:46:09 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2017 年 07 月 11 日 11:29:00 |
| 上次修改时间 | 2023 年 11 月 07 日 10:38:10 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 08 月 26 日 14:15:04 |
| 上次修改时间 | 2024 年 08 月 27 日 00:35:11 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 09 月 13 日 17:15:15 |
| 上次修改时间 | 2024 年 08 月 02 日 16:15:14 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2022 年 03 月 26 日 21:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:45:32 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 23 日 21:15:07 |
| 上次修改时间 | 2024 年 09 月 17 日 01:16:02 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 23 日 21:15:07 |
| 上次修改时间 | 2024 年 09 月 17 日 01:16:02 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 04 月 01 日 04:15:07 |
| 上次修改时间 | 2023 年 11 月 07 日 11:59:16 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2022 年 02 月 19 日 13:15:09 |
| 上次修改时间 | 2022 年 03 月 04 日 00:43:19 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 04 月 15 日 06:15:07 |
| 上次修改时间 | 2023 年 04 月 25 日 02:05:30 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 02 月 17 日 06:15:07 |
| 上次修改时间 | 2024 年 11 月 01 日 02:35:03 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 12 月 12 日 23:15:07 |
| 上次修改时间 | 2024 年 01 月 31 日 11:15:08 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2024 年 08 月 26 日 14:15:04 |
| 上次修改时间 | 2024 年 08 月 27 日 00:35:11 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2023 年 04 月 15 日 06:15:07 |
| 上次修改时间 | 2023 年 04 月 25 日 02:05:30 |

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
| 状态 | 该软件包在此平台上受该漏洞的影响，但是暂未发布补丁 |
| 披露时间 | 2021 年 04 月 29 日 13:15:08 |
| 上次修改时间 | 2022 年 05 月 14 日 04:52:24 |

