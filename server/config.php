<?php
/**
 * OhMyKeymint 云端服务端配置。
 *
 * 自包含：只依赖同目录的 lib/。
 *
 * 部署：把整个 server/ 目录放到不可从 web 直接访问的位置，并把网站 URL 前缀
 * `/api/omk` 指向 `server/public/`。客户端按下面的 base_url 取：
 *   <base>/index.php?action=manifest  清单（sha256 + Ed25519 签名 + 有效性报告）
 *   <base>/index.php?action=keybox    当前 keybox
 *   <base>/pif/device_list.json       PIF 指纹目录（静态文件）
 *   <base>/pif/device_prop/<product>.prop
 *
 * 结构性说明：
 *   - `public/` 是 web 根。只有 `index.php`（Keybox/manifest 前端控制器）和
 *     `pif/`（静态指纹 feed）位于其中，可直接访问。
 *   - `data/`（keybox.xml / manifest.json / revocation.json / pool/）是私有数据，
 *     放在 web 根之外，只能由 `index.php` 通过 action 参数读取。
 *   - `keys/`、`lib/`、`update_*.php` 同样在 web 根之外，不会被直接访问。
 */
return [
    // 对客户端可见的基础地址（必须以 http(s):// 开头，无结尾斜杠）
    'base_url' => 'https://omk.5ijxa.com/api/omk',

    // 私有数据目录（keybox.xml / manifest.json / revocation.json / pool/，web 根之外）
    'data_dir' => __DIR__ . '/data',

    // 公开的 PIF 指纹 feed 目录（web 根内，静态文件；URL 契约不变）
    'pif_dir' => __DIR__ . '/public/pif',

    // 密钥目录（Ed25519 私钥/公钥，web 根之外）
    'keys_dir' => __DIR__ . '/keys',

    'keybox_in' => 'keybox.xml',
    'version'      => 'v1.3.6',
    'version_code' => 100,

    // 人工固定 keybox：文件存在且校验通过时，update_keybox.php 永远优先用它，
    // 不再被上游源覆盖（A/B 实验/回滚用：删掉该文件即恢复自动择优）。
    'keybox_pin' => __DIR__ . '/keybox.pinned.xml',

    // GitHub 加速前缀：github.com 源先走此加速，失败再直连。
    'github_accel' => 'https://gh-proxy.com/',

    // 下载重试次数 / 单次超时秒
    'download_retries' => 3,
    'timeout' => 60,

    // ---- keybox 上游源（与 yypm 一致，按优先级择优）----
    'sources' => [
        'yurikey' => [
            'enabled'  => true,
            'url'      => 'https://raw.githubusercontent.com/Yurii0307/yurikey/main/key',
            'type'     => 'base64',
            'priority' => 1,
        ],
        'integritybox' => [
            'enabled'  => true,
            'url'      => 'https://raw.githubusercontent.com/MeowDump/MeowDump/refs/heads/main/NullVoid/OptimusPrime',
            'type'     => 'multi_base64_hex_rot13',
            'priority' => 1,
        ],
        'megatron' => [
            'enabled'  => true,
            'url'      => 'https://raw.githubusercontent.com/MeowDump/MeowDump/main/Megatron',
            'type'     => 'multi_base64_hex_rot13',
            'priority' => 1,
        ],
        'keyboxhub' => [
            'enabled'  => true,
            'type'     => 'github_dir',
            'priority' => 2,
            'repo'     => 'shall0e/KeyboxHub',
            'dir'      => 'KeyboxHub',
        ],
        'keyboxstatus' => [
            'enabled'  => true,
            'type'     => 'github_dir',
            'priority' => 2,
            'repo'     => 'SSM-FX/KeyboxStatus',
            'dir'      => '',
        ],
    ],

    /**
     * 吊销名单（Google attestation/status）多源：官方地址在国内服务器连不通，
     * 所以把 GitHub 镜像排在前面，官方地址放在最后作形式兜底。
     * 服务器缓存到 public/revocation.json，设备通过 <base>/revocation.json 取走。
     */
    'revocation_sources' => [
        'purainity' => 'https://raw.githubusercontent.com/purainity/keybox-tools/main/res/status.json',
        'kimmyxyc'  => 'https://raw.githubusercontent.com/KimmyXYC/KeyboxChecker/main/res/json/status.json',
        'google'    => 'https://android.googleapis.com/attestation/status',
    ],
    // 吊销名单缓存新鲜度（秒）
    'revocation_max_age' => 86400,

    // 已知被吊销的证书序列号（十进制或十六进制混写均可）
    'revoked_serials' => [
        // '64DEAA4D53885472AFAC267BDBD4A472',
    ],

    // Ed25519 签名（防盗，需 PHP sodium）
    'sign_enable'     => true,
    'sign_public_out' => 'ed25519.pub',
    'sign_secret_in'  => 'ed25519.key',

    // ---- PIF 指纹聚合源 ----
    // 每个源给出「如何从上游拿到 PIF 指纹」。type=github_release 表示扫描该仓库
    // 最新 release 的资产，挑出能解析为 Google Pixel 指纹的 .json/.prop 文件。
    // 服务器会归一化成 OMK 客户端能直接消费的 device_list.json + device_prop/*.prop。
    // 只保留实测能产出指纹的源：JingMatrix/PlayIntegrityFix 无 release、
    // IR0NBYTE/playIntegrityFixDetector 的 release 无 json/prop 资产，均已移除。
    'pif_sources' => [
        'elcapitanoe' => [
            'enabled'  => true,
            'type'     => 'github_release',
            'repo'     => 'Elcapitanoe/PIF-Config-Generator',
            'priority' => 1,
            'asset'    => '/\.json$/i',
        ],
        'xprateek' => [
            'enabled'  => true,
            'type'     => 'github_release',
            'repo'     => 'xprateek/PIF-JSON-Generator',
            'priority' => 1,
            'asset'    => '/\.json$/i',
        ],
    ],

    // 客户端可见的 PIF feed 上限（与 OMK 客户端契约一致）
    'pif_max_devices' => 64,
];
