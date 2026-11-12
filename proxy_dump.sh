#!/bin/sh
# Read-only exporter for the observed LazyCat proxy v1.8.0 AES-GCM format.
# Runtime dependencies: POSIX sh, OpenSSL 3.x, awk, curl (nodes only), coreutils.
# No Python, jq, process-memory inspection, node switching or service changes.
set -eu
LC_ALL=C
export LC_ALL
umask 077

die() { printf '错误：%s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'HELP'
用法：sh proxy_dump.sh [config|nodes] [选项]

  config              离线输出完整的 client.bin 明文（默认）
  nodes               使用本地 api_token GET /guest/nodes，输出完整响应
  --file PATH         client.bin 路径，默认 /opt/.lazycat/client.bin
  --output PATH       写入新的 0600 文件；拒绝覆盖已有文件
  --key-file PATH     可选 AES 密钥文件：64 个十六进制字符，不是 API token
  --api-url URL       nodes 模式下指定完整接口 URL，如 SSH 转发地址
  --timeout SECONDS   节点接口超时，整数 1–300，默认 10
  --raw               原样输出，不自动换行缩进（适合其他程序读取）
  -h, --help          显示帮助
  --version           显示版本

仅支持已验证的 v1.8.0 AES-256-GCM 格式，不支持旧的 XChaCha20 版本。
默认按字段换行缩进，不需要 jq；输出包含真实凭据，请勿提交到 GitHub。
HELP
}

mode=config
input=/opt/.lazycat/client.bin
output=
key_file=
api_url=
timeout=10
mode_set=0
raw=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        config|nodes)
            [ "$mode_set" -eq 0 ] || die '只能指定一个命令。'
            mode=$1; mode_set=1; shift ;;
        --file|--output|--key-file|--api-url|--timeout)
            [ "$#" -ge 2 ] || die "$1 缺少参数。"
            case "$1" in
                --file) input=$2 ;;
                --output) output=$2 ;;
                --key-file) key_file=$2 ;;
                --api-url) api_url=$2 ;;
                --timeout) timeout=$2 ;;
            esac
            shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --raw) raw=1; shift ;;
        --version) printf '1.1.0\n'; exit 0 ;;
        *) die "未知选项：$1" ;;
    esac
done
[ -n "$input" ] || die '输入路径不能为空。'
[ "$mode" = nodes ] || [ -z "$api_url" ] || die '--api-url 仅适用于 nodes。'
case "$timeout" in ''|*[!0-9]*) die 'timeout 必须是 1–300 的整数。';; esac
[ "${#timeout}" -le 3 ] && [ "$timeout" -ge 1 ] && [ "$timeout" -le 300 ] || die 'timeout 超出范围。'

for tool in openssl awk od dd tr wc mktemp cat rm; do
    command -v "$tool" >/dev/null 2>&1 || die "缺少依赖：$tool"
done
[ -f "$input" ] && [ -r "$input" ] || die '输入必须是可读的普通文件；可能需要 sudo。'
if [ -n "$output" ] && { [ -e "$output" ] || [ -L "$output" ]; }; then
    die '输出路径已存在；拒绝覆盖文件或跟随符号链接。'
fi

work=$(mktemp -d /tmp/proxy-config-dump.XXXXXXXX) || die '无法创建临时目录。'
cleanup() { rm -rf -- "$work"; }
trap cleanup 0
trap 'exit 130' 1 2 3 15

# Snapshot once: concurrent replacement of the source must not mix nonce/tag.
dd if="$input" of="$work/input.bin" bs=65537 count=1 2>"$work/error.log" || die '读取配置失败。'
size=$(wc -c < "$work/input.bin" | tr -d '[:space:]')
[ "$size" -ge 28 ] && [ "$size" -le 65536 ] || die '文件长度不受支持（28–65536 字节）。'

# Application-wide constant from the observed binary, NOT an instance token,
# machine identifier, node username or node password.
key=a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef
if [ -n "$key_file" ]; then
    [ -f "$key_file" ] && [ -r "$key_file" ] || die '密钥文件不可读。'
    dd if="$key_file" of="$work/key.hex" bs=1025 count=1 2>"$work/error.log" || die '读取密钥失败。'
    [ "$(wc -c < "$work/key.hex")" -le 1024 ] || die '密钥文件过长。'
    key=$(tr -d '[:space:]' < "$work/key.hex")
fi
[ "${#key}" -eq 64 ] || die 'AES 密钥必须是 64 个十六进制字符。'
case "$key" in *[!0-9a-fA-F]*) die 'AES 密钥包含非十六进制字符。';; esac
printf '%s\n' "$key" | awk '
function hex(c) { return index("0123456789abcdef", tolower(c)) - 1 }
{ for (i=1; i<=length($0); i+=2) printf "%c", 16*hex(substr($0,i,1))+hex(substr($0,i+1,1)) }
' > "$work/content.key"

hex_file() { od -An -v -tx1 "$1" | tr -d '[:space:]'; }
cipher_size=$((size - 28))
dd if="$work/input.bin" of="$work/nonce" bs=1 count=12 2>"$work/error.log"
dd if="$work/input.bin" of="$work/cipher" bs=1 skip=12 count="$cipher_size" 2>"$work/error.log"
dd if="$work/input.bin" of="$work/tag" bs=1 skip=$((size - 16)) count=16 2>"$work/error.log"

# OpenSSL enc does NOT support GCM. Wrap the *existing* nonce/ciphertext/tag in
# a temporary CMS AuthEnvelopedData container and let OpenSSL authenticate it.
# The zero KEK is only CMS packaging; it is not the application's AES key.
kek=0000000000000000000000000000000000000000000000000000000000000000
openssl enc -id-aes256-wrap -K "$kek" -iv a6a6a6a6a6a6a6a6 -nosalt \
    -in "$work/content.key" -out "$work/wrapped.key" 2>"$work/error.log" \
    || die 'OpenSSL 不支持所需的 AES key wrap。请使用 OpenSSL 3.x。'
if [ "$cipher_size" -eq 0 ]; then
    cipher_field='ciphertext=IMPLICIT:0,OCTETSTRING:'
else
    cipher_field="ciphertext=IMPLICIT:0,FORMAT:HEX,OCTETSTRING:$(hex_file "$work/cipher")"
fi
cat > "$work/envelope.conf" <<ASN1
asn1=SEQUENCE:content_info
[content_info]
content_type=OID:1.2.840.113549.1.9.16.1.23
content=EXPLICIT:0,SEQUENCE:auth_enveloped
[auth_enveloped]
version=INTEGER:0
recipients=SET:recipients
encrypted_content=SEQUENCE:encrypted_content
mac=FORMAT:HEX,OCTETSTRING:$(hex_file "$work/tag")
[recipients]
recipient=IMPLICIT:2,SEQUENCE:kek_recipient
[kek_recipient]
version=INTEGER:4
identifier=SEQUENCE:kek_identifier
algorithm=SEQUENCE:wrap_algorithm
encrypted_key=FORMAT:HEX,OCTETSTRING:$(hex_file "$work/wrapped.key")
[kek_identifier]
key_identifier=FORMAT:HEX,OCTETSTRING:01
[wrap_algorithm]
algorithm=OID:2.16.840.1.101.3.4.1.45
[encrypted_content]
content_type=OID:1.2.840.113549.1.7.1
algorithm=SEQUENCE:gcm_algorithm
$cipher_field
[gcm_algorithm]
algorithm=OID:2.16.840.1.101.3.4.1.46
parameters=SEQUENCE:gcm_parameters
[gcm_parameters]
nonce=FORMAT:HEX,OCTETSTRING:$(hex_file "$work/nonce")
tag_length=INTEGER:16
ASN1
openssl asn1parse -genconf "$work/envelope.conf" -out "$work/envelope.der" -noout \
    2>"$work/error.log" || die '无法构造 AES-GCM 验证容器。'
if ! openssl cms -decrypt -binary -inform DER -in "$work/envelope.der" \
    -secretkey "$kek" -secretkeyid 01 -out "$work/plain.json" 2>"$work/error.log"; then
    # CMS may have produced tentative plaintext: never publish it on failure.
    die '认证校验失败：文件损坏、密钥不符或格式不受支持；不输出任何明文。'
fi
result=$work/plain.json

if [ "$mode" = nodes ]; then
    command -v curl >/dev/null 2>&1 || die 'nodes 模式需要 curl。'
    # Parse the observed flat config strictly. Do not source/eval decrypted data.
    # Unknown/nested future formats fail closed rather than guessing credentials.
    if ! awk '
function bad() { failed=1; exit 1 }
function ws() { while (substr(doc,pos,1) ~ /[ \t\r\n]/ && pos<=length(doc)) pos++ }
function string(  s,c,e,h,i,n,v) {
    if (substr(doc,pos++,1)!="\"") bad()
    s=""
    while (pos<=length(doc)) {
        c=substr(doc,pos++,1)
        if (c=="\"") return s
        if (c ~ /[[:cntrl:]]/) bad()
        if (c=="\\") {
            e=substr(doc,pos++,1)
            if (e=="u") {
                h=substr(doc,pos,4); if (length(h)!=4 || h ~ /[^0-9a-fA-F]/) bad()
                n=0; for (i=1;i<=4;i++) n=n*16+index("0123456789abcdef",tolower(substr(h,i,1)))-1
                pos+=4
                # These configuration fields are ASCII. Reject unsupported UTF-16.
                if (n<32 || n>126) bad()
                c=sprintf("%c",n)
            } else if (e=="\"" || e=="\\" || e=="/") c=e
            else bad()
        }
        s=s c
    }
    bad()
}
{ doc=doc $0 "\n" }
END {
    if (failed) exit 1
    pos=1; ws(); if (substr(doc,pos++,1)!="{") bad(); ws()
    if (substr(doc,pos,1)!="}") while (1) {
        key=string(); if (key in seen) bad(); seen[key]=1
        ws(); if (substr(doc,pos++,1)!=":") bad(); ws()
        if (substr(doc,pos,1)=="\"") { value=string(); type="string" }
        else {
            rest=substr(doc,pos)
            if (match(rest,/^-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?/)) type="number"
            else if (match(rest,/^(true|false|null)/)) type="literal"
            else bad()
            value=substr(rest,1,RLENGTH); pos+=RLENGTH
        }
        values[key]=value; types[key]=type
        ws(); c=substr(doc,pos++,1); if (c=="}") break
        if (c!=",") bad(); ws()
    } else pos++
    ws(); if (pos<=length(doc)) bad()
    host=values["mother_ip"]; port=values["api_port"]; token=values["api_token"]
    if (types["mother_ip"]!="string" || length(host)<1 || length(host)>253 || host ~ /[^A-Za-z0-9.:-]/) bad()
    if (types["api_port"]!="number" || port ~ /[^0-9]/ || port<1 || port>65535) bad()
    if (types["api_token"]!="string" || length(token)<1 || length(token)>512 || token ~ /[^A-Za-z0-9._~+\/=\055]/) bad()
    print host; print port; print token
}
' "$work/plain.json" > "$work/api.fields"; then
        die '配置不是受支持的平面 JSON，或缺少有效的 mother_ip/api_port/api_token。'
    fi
    { IFS= read -r host; IFS= read -r port; IFS= read -r token; } < "$work/api.fields"
    if [ -z "$api_url" ]; then
        case "$host" in *:*) host=[$host];; esac
        api_url=http://$host:$port/guest/nodes
    fi
    case "$api_url" in http://*|https://*) ;; *) die 'API URL 仅允许 HTTP(S)。';; esac
    # Reject controls before escaping the URL for curl config syntax.
    if printf '%s\n' "$api_url" | awk 'NR>1 || /[[:cntrl:]]/ { found=1 } END { exit !found }'; then
        die 'API URL 包含控制字符。'
    fi
    # Configuration and token are sent to curl on stdin, never as argv.
    escaped_url=$(printf '%s' "$api_url" | awk '{ gsub(/\\/,"\\\\"); gsub(/\"/,"\\\""); printf "%s",$0 }')
    if ! status=$(
        {
            printf 'url = "%s"\n' "$escaped_url"
            printf 'header = "Authorization: Bearer %s"\n' "$token"
            printf 'header = "Accept: application/json"\n'
            # The observed server rejects otherwise valid credentials with a
            # different User-Agent. Match the client protocol, not curl defaults.
            printf 'user-agent = "What-You-Wanna-Do"\n'
            printf 'proxy = ""\nnoproxy = "*"\n'
        } | curl -q --config - --proto '=http,https' --silent --show-error \
            --connect-timeout 5 --max-time "$timeout" --max-filesize 4194304 \
            --output "$work/nodes.json" --write-out '%{http_code}' 2>"$work/error.log"
    ); then
        die '节点接口请求失败（未输出响应正文或凭据）。'
    fi
    # No -L: never forward the API token to a redirect target.
    [ "$status" = 200 ] || die "节点接口返回 HTTP $status；请检查 API 凭据是否已更新。"
    [ "$(wc -c < "$work/nodes.json")" -le 4194304 ] || die '节点响应过大。'
    result=$work/nodes.json
fi

if [ "$raw" -eq 0 ]; then
    # Formatting only: preserve scalar/string bytes, including escaped JSON
    # characters and unknown fields. Never eval data or require jq/Python.
    if ! awk '
function indent(  j) { for (j=0;j<depth;j++) printf "  " }
function next_token(pos) {
    while (pos<=length(doc) && substr(doc,pos,1) ~ /[ \t\r\n]/) pos++
    return pos
}
function bad() { failed=1; exit 1 }
{ doc=doc $0 "\n" }
END {
    if (failed) exit 1
    for (i=1;i<=length(doc);i++) {
        c=substr(doc,i,1)
        if (in_string) {
            printf "%s",c
            if (escaped) escaped=0
            else if (c=="\\") escaped=1
            else if (c=="\"") in_string=0
        } else if (c=="\"") { in_string=1; printf "%s",c }
        else if (c=="{" || c=="[") {
            close_token=(c=="{" ? "}" : "]")
            j=next_token(i+1)
            if (substr(doc,j,1)==close_token) { printf "%s%s",c,close_token; i=j }
            else {
                if (depth>=128) bad()
                stack[++depth]=close_token
                printf "%s\n",c; indent()
            }
        } else if (c=="}" || c=="]") {
            if (depth<1 || stack[depth]!=c) bad()
            delete stack[depth--]
            printf "\n"; indent(); printf "%s",c
        } else if (c==",") { printf ",\n"; indent() }
        else if (c==":") printf ": "
        else if (c !~ /[ \t\r\n]/) printf "%s",c
    }
    if (in_string || depth!=0) bad()
    printf "\n"
}
' "$result" > "$work/pretty.json"; then
        die '无法格式化输出；如需查看原始内容，请加 --raw。'
    fi
    result=$work/pretty.json
fi

printf '注意：输出包含明文凭据，请勿将运行结果提交到 GitHub。\n' >&2
if [ -n "$output" ]; then
    # POSIX noclobber plus the earlier existence check protects normal files and
    # symlinks. Use a trusted parent directory when choosing an output path.
    if ! ( set -C; cat "$result" > "$output" ); then die '写入失败；输出路径可能已存在。'; fi
else
    cat "$result"
    if [ "$raw" -eq 1 ]; then printf '\n'; fi
fi
