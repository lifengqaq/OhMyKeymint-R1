<?php
/**
 * 定时更新脚本（供 crontab 调用，建议 00:00 每天一次）：
 *   1. 按 config 依次拉取上游 keybox 源并解码
 *   2. 对每个候选做有效性校验（证书解析/链验证/过期/吊销）
 *   3. 在有效候选里择优（优先级 -> 剩余有效期），写入 data/keybox.xml（web 根之外）
 *   4. 生成 data/manifest.json（sha256 + Ed25519 签名 + 有效性报告 + 备用池 + 吊销快照）
 *
 * keybox.xml 与 manifest.json 都是私有数据，客户端经 public/index.php?action= 读取。
 *
 * 用法（由 update.sh 包装，宝塔计划任务调用）：
 *   sudo -u www /www/server/php/84/bin/php /path/to/server/update_keybox.php
 */

require_once __DIR__ . '/lib/sources.php';
require_once __DIR__ . '/lib/keybox.php';
require_once __DIR__ . '/lib/revocation.php';
require_once __DIR__ . '/lib/sign.php';

$cfg = require(getenv('OMK_SERVER_CONFIG') ?: __DIR__ . '/config.php');

$dataDir = $cfg['data_dir'];
@mkdir($dataDir, 0755, true);

$keyboxFile = $dataDir . '/' . $cfg['keybox_in'];
$manifest   = $dataDir . '/manifest.json';
$poolDir    = $dataDir . '/pool';

$ts = '[' . date('Y-m-d H:i:s') . ']';

// ---- 吊销名单：手工列表 + 在线多源 ----
$manualRevoked = $cfg['revoked_serials'] ?? [];
$revInfo = rev_fetch(
    $cfg['revocation_sources'] ?? [],
    (string)($cfg['github_accel'] ?? ''),
    $dataDir . '/revocation.json',
    (int)($cfg['timeout'] ?? 20),
    (int)($cfg['revocation_max_age'] ?? 86400)
);
echo "{$ts} 吊销名单：{$revInfo['source']}，" . count($revInfo['entries']) . " 条"
    . ($revInfo['fresh'] ? '' : '（未能刷新）') . "\n";
foreach ($revInfo['tried'] as $t) { echo "    - {$t}\n"; }

$revoked = kb_normalize_revoked(array_merge($manualRevoked, rev_to_revoked_list($revInfo['entries'])));
$GLOBALS['OMK_REV_INFO'] = $revInfo;

$modVer = $cfg['version'];
$modVc  = (int)$cfg['version_code'];

// ---- 1. 收集所有候选并逐个校验 ----
$candidates = [];
foreach ($cfg['sources'] as $name => $src) {
    if (empty($src['enabled'])) {
        continue;
    }
    echo "{$ts} 拉取源: {$name} ...\n";
    if (($src['type'] ?? '') === 'github_dir') {
        $pick = fetch_dir_source(
            $src,
            (string)$cfg['github_accel'],
            (int)$cfg['timeout'],
            (int)$cfg['download_retries'],
            15,
            function ($xml) use ($revoked) {
                $r = kb_validity_report($xml, $revoked);
                return !empty($r['ok']);
            }
        );
        if ($pick === false) {
            echo "    目录里没有取到可用 keybox，跳过\n";
            $candidates[] = ['name' => $name, 'ok' => false, 'why' => '目录取样失败'];
            continue;
        }
        echo "    取自 {$pick['file']}（试了 " . ($pick['tried'] ?? 1) . " 个）\n";
        $name .= '/' . preg_replace('/\.xml$/i', '', $pick['file']);
        $dec = $pick['keybox'];
    } else {
        $raw = http_get($src['url'], $cfg['github_accel'], (int)$cfg['timeout'], (int)$cfg['download_retries']);
        if ($raw === false || $raw === '') {
            echo "    下载失败或为空，跳过\n";
            $candidates[] = ['name' => $name, 'ok' => false, 'why' => '下载失败'];
            continue;
        }
        $dec = decode_keybox($raw, $src['type']);
        if ($dec === false) {
            echo "    解码失败，跳过\n";
            $candidates[] = ['name' => $name, 'ok' => false, 'why' => '解码失败'];
            continue;
        }
    }
    if (!validate_keybox($dec)) {
        echo "    基础校验失败（非有效 keybox XML），跳过\n";
        $candidates[] = ['name' => $name, 'ok' => false, 'why' => '基础校验失败'];
        continue;
    }

    $rep = kb_validity_report($dec, $revoked);
    $sha = hash('sha256', $dec);
    $candidates[] = [
        'name'      => $name,
        'priority'  => (int)($src['priority'] ?? 1),
        'ok'        => $rep['ok'],
        'why'       => $rep['ok'] ? '' : implode('；', $rep['reasons']),
        'keybox'    => $dec,
        'sha256'    => $sha,
        'validity'  => $rep,
        'serials'   => $rep['serials'],
    ];
    if ($rep['ok']) {
        echo "    通过：有效，剩余 {$rep['days_remaining']} 天，证书 " . count($rep['serials']) . " 个序列号\n";
    } else {
        echo "    *** 判定无效：" . implode('；', $rep['reasons']) . "\n";
    }
    if (!empty($rep['warnings'])) {
        echo "    提示：" . implode('；', $rep['warnings']) . "\n";
    }
}

// ---- 1.5 人工固定 keybox（A/B 实验 / 一键回滚）----
$pinned = null;
$pinFile = (string)($cfg['keybox_pin'] ?? '');
if ($pinFile !== '' && is_file($pinFile) && @filesize($pinFile) > 0) {
    echo "{$ts} 检测到固定 keybox: {$pinFile}\n";
    $pinXml = (string)@file_get_contents($pinFile);
    if (!validate_keybox($pinXml)) {
        echo "{$ts} 固定 keybox 校验失败：基础校验失败，回退到自动择优\n";
    } else {
        $pinRep = kb_validity_report($pinXml, $revoked);
        if (!$pinRep['ok']) {
            echo "{$ts} 固定 keybox 校验失败：" . implode('；', $pinRep['reasons']) . "，回退到自动择优\n";
        } else {
            $pinned = [
                'name'      => 'pinned',
                'priority'  => 0,
                'ok'        => true,
                'why'       => '',
                'keybox'    => $pinXml,
                'sha256'    => hash('sha256', $pinXml),
                'validity'  => $pinRep,
                'serials'   => $pinRep['serials'],
            ];
            echo "{$ts} 固定 keybox 校验通过：有效，剩余 {$pinRep['days_remaining']} 天，将优先于所有上游源\n";
        }
    }
}

// ---- 2. 择优 ----
$valid = array_values(array_filter($candidates, fn($c) => !empty($c['ok'])));
$chosen = null;
$fallbacks = [];
if (!empty($valid)) {
    usort($valid, function ($a, $b) {
        $pa = (int)($a['priority'] ?? 1);
        $pb = (int)($b['priority'] ?? 1);
        if ($pa !== $pb) return ($pa < $pb) ? -1 : 1;
        $da = $a['validity']['days_remaining'];
        $db = $b['validity']['days_remaining'];
        $da = ($da === null) ? -1 : $da;
        $db = ($db === null) ? -1 : $db;
        if ($da === $db) return 0;
        return ($da > $db) ? -1 : 1;
    });
}
if ($pinned !== null) {
    $chosen = $pinned;
    echo "{$ts} 选中源: pinned（人工固定，剩余 {$pinned['validity']['days_remaining']} 天）\n";
    $pool = $valid;
} elseif (!empty($valid)) {
    $chosen = $valid[0];
    echo "{$ts} 选中源: {$chosen['name']}（优先级 {$chosen['priority']}，剩余 {$chosen['validity']['days_remaining']} 天）\n";
    $pool = array_slice($valid, 1);
} else {
    $pool = [];
}
foreach ($pool as $v) {
    $fallbacks[] = [
        'source'         => $v['name'],
        'sha256'         => $v['sha256'],
        'size'           => strlen($v['keybox']),
        'days_remaining' => $v['validity']['days_remaining'],
        'min_not_after'  => $v['validity']['min_not_after'],
    ];
}

// ---- 3. 没有有效候选时保留上一份，并如实写入当前有效性 ----
if ($chosen === null) {
    echo "{$ts} 本轮无有效候选，保留上一次的 keybox\n";
    if (!is_file($keyboxFile)) {
        echo "{$ts} 且本地也没有 keybox，结束\n";
        exit(0);
    }
    $keybox  = file_get_contents($keyboxFile);
    $sha256  = hash('sha256', $keybox);
    $recheck = kb_validity_report($keybox, $revoked);
    echo "{$ts} 保留的这份有效性：{$recheck['level']}"
        . (empty($recheck['reasons']) ? '' : '，原因：' . implode('；', $recheck['reasons'])) . "\n";
    write_manifest($cfg, $dataDir, $manifest, '(保留上一份)', $keybox, $sha256, $recheck, $fallbacks, $candidates, $revoked, $modVer, $modVc);
    exit(0);
}

// ---- 4. 写入并生成 manifest ----
file_put_contents($keyboxFile, $chosen['keybox']);
write_pool_snapshot($poolDir, $chosen, $candidates, $revoked);
echo "{$ts} 完成。keybox={$keyboxFile} sha256={$chosen['sha256']}\n";
write_manifest($cfg, $dataDir, $manifest, $chosen['name'], $chosen['keybox'], $chosen['sha256'], $chosen['validity'], $fallbacks, $candidates, $revoked, $modVer, $modVc);

// ============================================================
// 辅助函数
// ============================================================

/** 写 manifest.json。 */
function write_manifest(array $cfg, string $dataDir, string $manifestFile, string $sourceName,
                        string $keybox, string $sha256, array $validity, array $fallbacks,
                        array $candidates, array $revoked, string $modVer, int $modVc): void {
    $entry = [
        'updated_at' => date('Y-m-d H:i:s'),
        'source'     => $sourceName,
        'size'       => strlen($keybox),
        'sha256'     => $sha256,
        'url'        => rtrim($cfg['base_url'], '/') . '/index.php?action=keybox',
        'validity'   => [
            'level'          => $validity['level'],
            'ok'             => (bool)$validity['ok'],
            'reasons'        => $validity['reasons'],
            'warnings'       => $validity['warnings'],
            'checked_at'     => $validity['checked_at'],
            'min_not_after'  => $validity['min_not_after'],
            'days_remaining' => $validity['days_remaining'],
            'cert_count'     => $validity['cert_markers'] ?? null,
            'serial_count'   => count($validity['serials'] ?? []),
            'serials'        => $validity['serials'] ?? [],
            'chains'         => $validity['chains'] ?? [],
        ],
        'fallbacks'  => $fallbacks,
    ];

    $ri = $GLOBALS['OMK_REV_INFO'] ?? null;
    if (is_array($ri)) {
        $entry['revocation'] = [
            'source'     => (string)($ri['source'] ?? ''),
            'count'      => count($ri['entries'] ?? []),
            'fresh'      => (bool)($ri['fresh'] ?? false),
            'fetched_at' => (int)($ri['fetched_at'] ?? 0),
            'checked'    => count($revoked),
            'tried'      => $ri['tried'] ?? [],
        ];
    }

    if (!empty($cfg['sign_enable'])) {
        try {
            [$secret, $public] = sign_ensure_keys($cfg['keys_dir'], $cfg['sign_public_out'], $cfg['sign_secret_in']);
            $entry['signature'] = sign_data($secret, $keybox);
            $entry['sign_public'] = $public;
        } catch (Throwable $e) {
            echo "    签名失败（sodium?）: " . $e->getMessage() . "\n";
        }
    }

    $health = [];
    foreach ($candidates as $c) {
        $health[] = [
            'source' => $c['name'],
            'ok'     => !empty($c['ok']),
            'why'    => $c['why'] ?? '',
        ];
    }

    $payload = [
        'version'       => $modVer,
        'version_code'  => $modVc,
        'base_url'      => $cfg['base_url'],
        'keybox'        => $entry,
        'server'        => [
            'updated_at'      => date('Y-m-d H:i:s'),
            'revoked_count'   => count($revoked),
            'sources'         => $health,
            'candidate_count' => count($candidates),
            'valid_count'     => count(array_filter($candidates, fn($c) => !empty($c['ok']))),
        ],
    ];

    // 保留已有的 PIF 摘要字段（由 update_pif.php 写入），避免 keybox 更新冲掉它。
    if (is_file($manifestFile)) {
        $old = json_decode((string)@file_get_contents($manifestFile), true);
        if (is_array($old) && isset($old['pif'])) {
            $payload['pif'] = $old['pif'];
        }
    }

    file_put_contents($manifestFile, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
}

/** 候选池快照 */
function write_pool_snapshot(string $poolDir, ?array $chosen, array $candidates, array $revoked): void {
    @mkdir($poolDir, 0755, true);
    $rows = [];
    foreach ($candidates as $c) {
        $rows[] = [
            'source'         => $c['name'],
            'ok'             => !empty($c['ok']),
            'why'            => $c['why'] ?? '',
            'sha256'         => $c['sha256'] ?? null,
            'days_remaining' => $c['validity']['days_remaining'] ?? null,
            'min_not_after'  => $c['validity']['min_not_after'] ?? null,
        ];
    }
    $snap = [
        'at'         => date('Y-m-d H:i:s'),
        'chosen'     => $chosen['name'] ?? null,
        'revoked'    => $revoked,
        'candidates' => $rows,
    ];
    @file_put_contents($poolDir . '/last_pool.json', json_encode($snap, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    @file_put_contents($poolDir . '/pool_' . date('Ymd') . '.json', json_encode($snap, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $hist = glob($poolDir . '/pool_*.json');
    if (is_array($hist) && count($hist) > 30) {
        sort($hist);
        foreach (array_slice($hist, 0, count($hist) - 30) as $old) { @unlink($old); }
    }
}
