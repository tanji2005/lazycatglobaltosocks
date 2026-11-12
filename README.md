# lazycatglobaltosocks

在服务器本机只读导出 LazyCat `proxy v1.8.0` 的本地配置或实时节点信息。

**主程序是一个可直接运行的 POSIX `sh` 文件，运行时不需要 Python、pip、jq、UPX 或内存扫描。**

## 从 GitHub 下载后直接运行

在服务器本机、自己控制的目录中，以 **root** 身份执行。普通用户请将下方的 `sh` 改为 `sudo sh`。
依赖 OpenSSL 3.x、awk 和常用系统工具；获取节点另需 curl。

**输出加密配置文件的全部明文：**

```sh
curl -fsSL https://raw.githubusercontent.com/tanji2005/lazycatglobaltosocks/main/proxy_dump.sh -o proxy_dump.sh && sh ./proxy_dump.sh config
```

**获取全部实时 SOCKS 节点，包括地址、端口、用户名和密码：**

```sh
curl -fsSL https://raw.githubusercontent.com/tanji2005/lazycatglobaltosocks/main/proxy_dump.sh -o proxy_dump.sh && sh ./proxy_dump.sh nodes
```

下载失败时，`&&` 后面的脚本不会执行。已经下载过脚本时可以直接运行：

```sh
sh ./proxy_dump.sh config
sh ./proxy_dump.sh nodes
```

脚本只读，不切换节点，不修改 sing-box、Tunnel 或客户端配置。
输出含真实凭据，不要把结果粘贴到公开的 GitHub Issue 或提交到仓库。

## 使用

环境：Linux、OpenSSL 3.x、awk 和常用系统工具；`nodes` 命令另外需要 curl。
输入文件通常只有 root 可读，因此下面使用 `sudo`；已经是 root 时可省略。

```sh
# 解密并输出 /opt/.lazycat/client.bin 的全部内容；不联网
sudo sh proxy_dump.sh config

# 使用解密得到的 API 凭据，获取并输出完整实时节点响应
sudo sh proxy_dump.sh nodes
```

`config` 默认输出紧凑 JSON，`nodes` 原样输出接口的 HTTP 200 响应。
如果另外装有 jq，可以自行管道格式化：

```sh
sudo sh proxy_dump.sh config | jq .
sudo sh proxy_dump.sh nodes | jq .
```

显式指定配置路径：

```sh
sudo sh proxy_dump.sh config --file /opt/.lazycat/client.bin
```

保存到**新文件**，自动使用 `0600` 权限；已有文件或符号链接不会被覆盖：

```sh
mkdir -m 700 private
sudo sh proxy_dump.sh config --output private/config.json
sudo sh proxy_dump.sh nodes --output private/nodes.json
```

`--output` 的父目录应由你控制。不要使用 shell 的普通 `>` 重定向保存凭据，除非已经正确设置 `umask`。

## 本地配置不等于节点列表

已验证版本的 `client.bin` 包含管理端地址、端口、`api_token`、调试状态等客户端配置。
完整的 SOCKS 节点列表通常由接口实时下发，包含转发端口及节点账号密码。

- `config`：离线读取本地文件，不查询 API。
- `nodes`：解密本地文件后，仅执行一次 `GET /guest/nodes`；不注册客户端、不切换节点、不修复配置。

`nodes` 只支持已经观测确认的接口：

```text
http://<mother_ip>:<api_port>/guest/nodes
Authorization: Bearer <api_token>
```

接口还会校验客户端 User-Agent。脚本使用已验证客户端的相同值 `What-You-Wanna-Do`，避免凭据正确却收到 HTTP 401。
脚本不会自动跟随重定向，也不会使用环境中的 `HTTP_PROXY`/`HTTPS_PROXY`，防止管理令牌被意外送给其他代理。
它不尝试登录其他账号、不枚举其他接口，也不会访问 SSH 密钥等无关文件。

如果从另一台机器通过 SSH 转发管理接口，可以显式指定完整 URL：

```sh
sh proxy_dump.sh nodes \
  --file ./private/client.bin \
  --api-url http://127.0.0.1:14399/guest/nodes \
  --timeout 15
```

此例假设你已自行建立转发；脚本本身不建立 SSH 连接。

## 格式与范围

支持的是已验证的 **v1.8.0 AES-256-GCM 格式**：

```text
12-byte nonce || ciphertext || 16-byte authentication tag
```

该版本使用程序内置的应用级 AES 常量。源码里的常量不是任何实例的 API 令牌、节点密码或机器标识。
本版本的文件不依赖本机 machine-id，因此持有原文件也可以离线解密。

脚本将原始 nonce、密文、标签放入一个临时 CMS AuthEnvelopedData 容器，由 OpenSSL 验证完整的 GCM 认证标签，再对外输出明文。
这不是忽略认证标签的 AES-CTR 裸解密；任何 nonce、密文或标签的篡改都会使操作失败，不会输出暂存明文。
临时 CMS 的零值 KEK 只是把既有内容密钥交给 CMS 解密器的封装机制，不是应用实际使用的 AES 密钥，也不参与原文件加密。

实现参考：[OpenSSL CMS](https://docs.openssl.org/3.0/man1/openssl-cms/)、[OpenSSL ASN.1 parser](https://docs.openssl.org/3.0/man1/openssl-asn1parse/)。

限制：

- **不支持**此前 `/usr/share/doc/global/client.bin` 的 XChaCha20 版本；把它交给本脚本会认证失败。
- 不保证兼容同名程序的所有版本。格式、内置密钥或 API 改变后应重新验证，不能仅凭文件名判断。
- 配置输入上限为 64 KiB，节点响应上限为 4 MiB。
- `nodes` 模式严格解析当前版本的平面 ASCII 配置；嵌套结构、重复字段或不支持的格式会拒绝处理，而不是猜测凭据。
- 如已知另一个 AES-256 内容密钥，可以通过 `--key-file PATH` 提供 64 位十六进制文件；它不是 API token。
- `nodes` 原样输出成功响应，不提供通用 JSON schema 校验，也不证明接口列出的节点一定连通。
- 文件不可读、认证失败、接口非 HTTP 200 或网络错误时返回非零状态；错误信息不回显 API 令牌或响应正文。

## 数据与开源

默认输出**不脱敏**，因为本工具用于导出完整内容。不要将真实的 `client.bin`、密钥文件、解密结果或节点响应提交到 GitHub。
临时工作目录及文件权限受 `umask 077` 保护，正常退出或收到常见终止信号时清理；不承诺 SIGKILL 后的清理或磁盘安全擦除。

`.gitignore` 已排除 `private/`、常见配置输出及密钥文件，但不能替代提交前检查。
发布时仅上传本项目目录，不要把上一级工作区的 `artifacts/` 等实际运维数据一起提交。

## 开发测试

Python 仅用于开发测试，**运行 `.sh` 不需要 Python**：

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m unittest discover -s tests -v
sh -n proxy_dump.sh
```

测试数据全部是运行时生成的合成数据和本地回环 HTTP 服务；不包含真实账号或节点。
覆盖认证标签/nonce/密文篡改、空载荷和块边界、大小限制、输出权限、不覆盖文件、API 认证、禁止重定向以及不依赖 Python/jq 的运行环境。

## License

MIT，见 [LICENSE](LICENSE)。
