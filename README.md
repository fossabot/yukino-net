# yukino-net
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/503d76c5366b4838be3b01cbb6e3fa0b)](https://app.codacy.com/gh/xpy123993/yukino-net?utm_source=github.com&utm_medium=referral&utm_content=xpy123993/yukino-net&utm_campaign=Badge_Grade_Settings)
[![Go](https://github.com/xpy123993/yukino-net/actions/workflows/go.yml/badge.svg)](https://github.com/xpy123993/yukino-net/actions/workflows/go.yml)
[![Create Debian Packages](https://github.com/xpy123993/yukino-net/actions/workflows/debian.yml/badge.svg)](https://github.com/xpy123993/yukino-net/actions/workflows/debian.yml)
[![Docker Image](https://github.com/xpy123993/yukino-net/actions/workflows/docker.yml/badge.svg)](https://github.com/xpy123993/yukino-net/actions/workflows/docker.yml)

## 简介

yukino-net 是本人使用的一套嵌入式网络模块，主要使用场景为在拥有公网 IP 地址的情况下，以 POST 请求的方式执行嵌入式设备的指令。

主要功能有：

1. 内网穿透：每个客户端通过公网服务器来进行数据传输。
2. TLS 支持：本程序可以创建 TLS 证书并生成相应的配置文件，使得所有客户端到服务器的通信均由 TLS 加密。
3. Webhook 支持：本程序内置一个简易网页服务器，通过合理配置自动化 Workflow，最终可以实现用 Google Assistant 等来安全的控制嵌入式设备。

## 安装

本程序为单文件程序，您可以在 [Release 页面](https://github.com/xpy123993/yukino-net/releases/) 下载。

当安装成功后，运行：

```bash
yukino-net
```

将会输出可供使用的命令列表。

您还可以使用 Docker 版本，详见 [Package 页面](https://github.com/xpy123993/yukino-net/pkgs/container/yukino-net)。

## 使用说明

### 根证书

第一次使用时我们需要生成根证书来用于认证及加密客户端与服务端之间的通信，生成方法为：

```bash
yukino-net cert new-ca x509
```

这会在 `x509` 目录下生成两个文件：

- ca.key: 根证书的密钥
- ca.crt: 根证书的证书

请妥善保管根证书，或在部署结束后删除根证书密钥：密钥的泄露将会导致端到端之间的通信不再可信。

### 部署公网服务器

首先，我们需要决定一个监听地址，如 `123.123.123.123:1234`, 其中 `123.123.123.123` 为公网服务器所在的 IP 地址，`1234` 为一个服务器上一个可用端口。然后运行以下命令：

```bash
yukino-net gen-config 123.123.123.123:1234 x509 123.123.123.123:1234 router.zip
```

这将会产生一个 `router.zip` 包含了一个公网服务器的配置，将它复制到公网服务器上，解压后在其目录下运行：

```sh
yukino-net route                                                      
```

即可。您可能需要将 `config.json` 中的路径改为绝对路径来防止设置开机自启动时程序找不到配置文件。

### 部署网页服务器

本程序内置了一个 HTTP 服务器，这里 **不推荐** 直接将 HTTP 服务器端口直接暴露在公网下，一种常见的做法是申请一个域名，利用 Nginx + Certbot 来将 HTTPS 暴露在公网。

首先生成一组 Config:

```sh
yukino-net gen-config 123.123.123.123:1234 x509 webhook webhook.zip
```

然后生成一组 Token:

```sh
yukino-net endpoint gen-token

Token (EndPoint-Service-Token): [Token A]
WebHook HashToken: [Token B]
```

其中 `[Token A]` 需要出现在 POST 请求的 Header `EndPoint-Service-Token` 中，`[Token B]` 则在部署 Webhook 服务时需要。

在公网服务器上将其解压，运行

```sh
yukino-net endpoint webhook :8080 [Token B]
```

Webhook Server 将会在 8080 端口服务，所有不包含 `[Token A]` 的 POST 请求将会被拒绝。

### 嵌入式设备

本程序将会作为一个 Shell Proxy 在嵌入式设备上监听并执行收到的命令。

首先生成一组 Config:

```sh
yukino-net gen-config 123.123.123.123:1234 x509 endpoint.A endpoint.A.zip
```

生成一组公钥：

```sh
yukino-net cert new-pubkey

Public Key: [Token C]
Private Key: [Token D]
```

最后在嵌入式设备上运行

```sh
yukino-net endpoint serve endpoint.A -m [Token C]
```

即可。

通过网页服务器，我们可以远程执行命令，如：

```sh
curl -I -H "EndPoint-Service-Token: [Token A]" -H "Command: echo hello world" -H "Private-Key: [Token D]" http://[WebServer Address]/endpoint.A
```

## 附录

### 使用 IFTTT + Google Assistant

在 IFTTT 中，设定一个 Google Assitant 的触发条件，如 `Say a sentence.`

在触发动作中选择 `Make a web request`, 其中：

- Method 为 POST
- Header 为
  ```
  EndPoint-Service-Token: [Token A]
  Private-Key: [Token D]
  Command: [要执行的 Command]
  ```

保存即可。

## 免责声明

请勿用于非法的用途，否则造成的严重后果与本项目无关。
