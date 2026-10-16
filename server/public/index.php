<?php
/**
 * OhMyKeymint 前端控制器。
 *
 * 客户端按 action 参数取云端资源：
 *   /api/omk/index.php?action=manifest   返回 manifest.json
 *   /api/omk/index.php?action=keybox     返回 keybox.xml
 *   /api/omk/index.php?action=stats      返回下发计数（网站首页用）
 *   /api/omk/index.php?action=pif&file=… 转发 PIF 指纹 feed 并计数
 *
 * 成功下发 keybox 或 PIF 指纹时都会在 data/counter.json 累加一次。
 *
 * PIF 指纹 feed 的 URL 契约不变（仍是 <base>/pif/device_list.json 与
 * <base>/pif/device_prop/<product>.prop）。nginx 把 /api/omk/pif/(.*) 重写成
 * /api/omk/index.php?action=pif&file=$1，于是 PIF 请求也经本控制器转发并实时
 * 计数，无需再解析 nginx 访问日志。
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/lib/counter.php';

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

$cfg = require dirname(__DIR__) . '/config.php';

$action = isset($_GET['action']) && is_string($_GET['action']) ? $_GET['action'] : '';

// 下发计数：只读，供网站首页 fetch
if ($action === 'stats') {
    header('Access-Control-Allow-Origin: *');
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(omk_counter_read($cfg), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * 校验 PIF 相对路径，只放行契约内的两种文件，杜绝目录穿越：
 *   device_list.json
 *   device_prop/<product>.prop
 */
function omk_pif_relpath(string $file): ?string
{
    if ($file === 'device_list.json') {
        return $file;
    }
    if (preg_match('#^device_prop/[A-Za-z0-9_]+\.prop$#', $file) === 1) {
        return $file;
    }
    return null;
}

// PIF 指纹 feed 转发 + 计数（URL 契约不变，nginx rewrite 到此）
if ($action === 'pif') {
    $file = isset($_GET['file']) && is_string($_GET['file']) ? $_GET['file'] : '';
    $rel = omk_pif_relpath($file);
    $path = $rel === null ? '' : rtrim((string)$cfg['pif_dir'], '/') . '/' . $rel;

    if ($path === '' || !is_file($path) || !is_readable($path)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo "not found\n";
        exit;
    }

    $body = @file_get_contents($path);
    if ($body === false) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo "read error\n";
        exit;
    }

    omk_counter_bump($cfg, 'pif');

    header('Content-Type: ' . (substr($rel, -5) === '.json' ? 'application/json; charset=utf-8' : 'application/octet-stream'));
    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

// action -> [文件, Content-Type]
$routes = [
    'manifest' => [rtrim((string)$cfg['data_dir'], '/') . '/manifest.json', 'application/json; charset=utf-8'],
    'keybox'   => [rtrim((string)$cfg['data_dir'], '/') . '/' . ($cfg['keybox_in'] ?? 'keybox.xml'), 'application/xml; charset=utf-8'],
];

if (!isset($routes[$action])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}

[$path, $contentType] = $routes[$action];

if (!is_file($path) || !is_readable($path)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not available\n";
    exit;
}

$body = @file_get_contents($path);
if ($body === false) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "read error\n";
    exit;
}

// 成功下发 keybox 后计数（manifest 是校验用清单，不计入下发次数）
if ($action === 'keybox') {
    omk_counter_bump($cfg, 'keybox');
}

header('Content-Type: ' . $contentType);
header('Content-Length: ' . strlen($body));
echo $body;
