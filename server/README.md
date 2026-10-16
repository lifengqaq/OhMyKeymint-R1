# OhMyKeymint 云端服务端

给 OhMyKeymint 模块提供 keybox 云端分发（含自动吊销校验）与 PIF 指纹聚合下发。
自包含的 PHP，只依赖同目录 `lib/`。

## 目录结构

```
server/
  config.php         配置（base_url / 上游源 / 签名 / 目录）
  update_keybox.php  定时任务：拉取并择优 keybox（含证书链/有效期/吊销校验）
  update_pif.php     定时任务：聚合 PIF 指纹
  update.sh          宝塔计划任务包装
  lib/               http / keybox 校验 / 吊销 / Ed25519 签名 / PIF 聚合
  keys/              Ed25519 密钥（首次运行自动生成，必须在 web 根之外）
  public/            web 根（站点 URL 前缀 /api/omk 指向这里）
    index.php        前端控制器：?action=manifest / keybox / stats / pif
    pif/             指纹 feed 数据（device_list.json + device_prop/*.prop）
  data/              私有数据（web 根之外，只能由 index.php 读取）
    keybox.xml
    manifest.json
    revocation.json
    pool/
```

职责边界：

- `public/` 是唯一的 web 根，只有 `index.php` 会被直接访问；PIF 与 keybox
  的请求全部经 `index.php` 转发，服务端因此可以按请求计数/鉴权/限流。
- `data/`、`keys/`、`lib/`、`update_*.php` 全部位于 web 根之外，无法经 URL 访问。
- keybox、manifest 与 PIF 指纹都不作为可直接下载的静态文件暴露，客户端只能
  通过 `index.php` 读取。

## 客户端取用契约

| 资源 | URL |
| --- | --- |
| keybox | `<base>/index.php?action=keybox` |
| 清单（sha256 + 签名 + 有效性） | `<base>/index.php?action=manifest` |
| 下发计数（keybox/pif） | `<base>/index.php?action=stats` |
| PIF 设备目录 | `<base>/pif/device_list.json` |
| PIF 指定设备指纹 | `<base>/pif/device_prop/<product>.prop` |

`<base>` 即 `config.php` 的 `base_url`，默认 `https://omk.5ijxa.com/api/omk`。

keybox 的完整性由 `manifest.json` 的 `signature` 字段保障：它是用 Ed25519
私钥（`keys/ed25519.key`）对 `keybox.xml` 原始字节做 detached 签名得到的，
`sign_public` 为对应公钥（base64）。客户端内置了默认站点的公钥作为编译期信任
锚；`config.toml` 的 `server.trusted_keybox_pubkey` 可覆盖它，支持直接粘贴
base64 或 64 位 hex。

## 下发计数

`data/counter.json` 记录 keybox 与 pif 的累计下发次数，`index.php?action=stats`
以 JSON 返回 `{"keybox":N,"pif":M}`，供站点首页展示。

- keybox：`index.php` 在成功下发 `keybox.xml` 时用 `lib/counter.php` 自增（
  `manifest` 是校验清单，不计入）。
- pif：PIF 请求由 nginx 重写到 `index.php?action=pif&file=…`，由 `index.php`
  成功转发指纹文件时自增。URL 契约不变，请求即实时计数，无需解析访问日志。

`stats` 是只读接口，不暴露文件内容，可安全公开。首页脚本每 30 秒轮询一次
（`scripts/app/stats.js` 的 `POLL_MS`，可按需调小）。

## 环境要求

- PHP 8.x（示例路径 `/www/server/php/84/bin/php`）。
- PHP 扩展：`curl`、`openssl`、`mbstring`、`sodium`（Ed25519 签名必需），
  `json`（PHP 8 默认内置）。
- nginx（或 Apache），需要一个可用的 php-fpm 上游。
- 以 `www` 用户运行更新脚本，使生成文件的属主与 PHP 进程一致。

检查扩展是否齐全：

```sh
/www/server/php/84/bin/php -m | grep -E 'curl|openssl|mbstring|sodium'
```

## 部署步骤

1. 把整个 `server/` 目录放到站点目录下的可写位置，例如
   `/www/wwwroot/omk.5ijxa.com/api/omk/server/`。

2. 在站点（`omk.5ijxa.com`）里把 URL 前缀 `/api/omk` 指向 `server/public/`，
   并让 `index.php` 走 php-fpm。宝塔 nginx 可直接加：

   ```nginx
   # 前端控制器：keybox / manifest / stats
   location = /api/omk/index.php {
       alias /www/wwwroot/omk.5ijxa.com/api/omk/server/public/index.php;
       fastcgi_pass unix:/tmp/php-cgi-84.sock;
       fastcgi_index index.php;
       include fastcgi.conf;
   }

   # PIF 指纹 feed：重写到前端控制器，下载即实时计数（URL 契约不变）
   location /api/omk/pif/ {
       rewrite ^/api/omk/pif/(.*)$ /api/omk/index.php?action=pif&file=$1 last;
   }

   # 其余 /api/omk/* 一律拒绝，避免暴露内部结构
   location /api/omk/ {
       return 404;
   }
   ```

   `fastcgi_pass` 的值按实际 PHP-FPM 监听方式填写（宝塔通常是
   `unix:/tmp/php-cgi-84.sock`；若为 TCP 则形如 `127.0.0.1:9000`）。

   也可以把站点根直接设为 `server/public/`，此时把 `config.php` 的 `base_url`
   改成站点根地址，并相应调整上面的 location 前缀。

3. 核对 `config.php` 的 `base_url` 与公开访问地址一致（无结尾斜杠）。

4. 首次运行一次 keybox 更新，让服务端生成密钥与数据文件：

   ```sh
   /path/to/server/update.sh keybox
   ```

   运行后 `keys/ed25519.pub`（即 `sign_public`，base64）会被创建。它是客户端
   校验签名所需的公钥。若你要更换默认站点公钥，把该值同步进客户端
   `src/remote_keybox.rs` 的 `TRUSTED_PUBKEY_B64` 并重新编译。

5. 确认 `data/`、`public/` 属主均为 `www`，`keys/` 权限收紧到 `700`。
   `update.sh` 每次运行都会自动修正，无需手工处理。

## 计划任务

宝塔「计划任务」添加两条 Shell 脚本（先按实际路径改 `update.sh` 顶部的
`PHP` 与 `DIR`）：

```sh
# 每天 00:00 更新 keybox
/path/to/server/update.sh keybox

# 每天 02:00 聚合 PIF 指纹
/path/to/server/update.sh pif
```

也可直接写进 crontab（与宝塔等价）：

```cron
0 0 * * * /path/to/server/update.sh keybox
0 2 * * * /path/to/server/update.sh pif
```

日志落盘在 `server/update.log`。

## 上游源

- keybox：`config.php` 的 `sources`（按 `priority` 择优，同优先级取剩余有效期最长）。
- 吊销名单：`revocation_sources`（GitHub 镜像优先，官方地址兜底）。
- PIF：`pif_sources`，默认 2 个 GitHub 源（Elcapitanoe/PIF-Config-Generator、
  xprateek/PIF-JSON-Generator）。

所有 GitHub 下载都先走加速前缀 `github_accel`（默认 `https://gh-proxy.com/`），
失败再直连；设为空字符串即全程直连。

## 人工固定 / 回滚

放一份 `keybox.pinned.xml` 于 `server/` 根目录，`update_keybox.php` 在其校验
通过时会永久优先使用它，不再被上游覆盖。删除该文件即恢复自动择优。

## 自检

```sh
# 语法检查
php -l config.php
php -l public/index.php
php -l update_keybox.php
php -l update_pif.php

# 手动跑一次并观察日志
/path/to/server/update.sh all
tail -n 50 /path/to/server/update.log
```
