<?php
error_reporting(0);
ini_set('display_errors', 0);

$scriptName   = basename(__FILE__);
$usersFile    = __DIR__ . '/.users.json';

function fm_load_users($usersFile){
    if(!file_exists($usersFile)){
        $seed = [[ 'user'=>'admin', 'hash'=>password_hash('dradam', PASSWORD_DEFAULT), 'root'=>'', 'readonly'=>false, 'admin'=>true ]];
        @file_put_contents($usersFile, json_encode($seed, JSON_PRETTY_PRINT));
        return $seed;
    }
    $c = @file_get_contents($usersFile);
    $d = json_decode($c, true);
    return is_array($d) ? $d : [];
}
function fm_save_users($usersFile, $users){ @file_put_contents($usersFile, json_encode(array_values($users), JSON_PRETTY_PRINT)); }
function fm_find_user($users, $name){ foreach($users as $u){ if($u['user']===$name) return $u; } return null; }

if (session_status() === PHP_SESSION_NONE) session_start();
if (empty($_SESSION['login_csrf'])) $_SESSION['login_csrf'] = bin2hex(random_bytes(32));

$IDLE_TIMEOUT = 900; // 15 minutes of inactivity
$idleExpired = false;
if (isset($_SESSION['auth']) && $_SESSION['auth'] === true) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $IDLE_TIMEOUT) {
        $_SESSION = [];
        session_destroy();
        session_start();
        $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
        $idleExpired = true;
    } else {
        $_SESSION['last_activity'] = time();
    }
}
if (isset($_GET['idle'])) $idleExpired = true;

if (isset($_POST['login_pass'])) {
    $loginCsrfOk = isset($_POST['login_csrf']) && hash_equals($_SESSION['login_csrf'], $_POST['login_csrf']);
    $users = fm_load_users($usersFile);
    $uname = isset($_POST['login_user']) ? trim($_POST['login_user']) : '';
    $u = fm_find_user($users, $uname);
    if ($loginCsrfOk && $u && password_verify($_POST['login_pass'], $u['hash'])) {
        $_SESSION['auth'] = true;
        $_SESSION['fm_user'] = $u['user'];
        $_SESSION['fm_root'] = !empty($u['root']) ? $u['root'] : '';
        $_SESSION['fm_readonly'] = !empty($u['readonly']);
        $_SESSION['fm_admin'] = !empty($u['admin']);
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        unset($_SESSION['login_csrf']);
        header("Location: " . $scriptName); exit;
    } else {
        $_SESSION['login_csrf'] = bin2hex(random_bytes(32));
        $loginError = $loginCsrfOk ? "Incorrect username or password." : "Security error. Please try again.";
    }
}

if (!isset($_SESSION['auth']) || $_SESSION['auth'] !== true) { ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In — File Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;font-family:'Inter',system-ui,sans-serif}
body{
  background:#09090b;
  display:flex;align-items:center;justify-content:center;
  min-height:100vh;padding:20px;
  background-image:
    radial-gradient(ellipse 80% 60% at 30% 0%,rgba(99,102,241,.13),transparent),
    radial-gradient(ellipse 60% 50% at 80% 100%,rgba(16,185,129,.06),transparent);
}
.card{
  width:100%;max-width:380px;
  background:rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.08);
  border-radius:24px;padding:40px 36px;
  backdrop-filter:blur(24px);
  box-shadow:0 32px 80px rgba(0,0,0,.6),inset 0 1px 0 rgba(255,255,255,.07);
  animation:fadeUp .45s cubic-bezier(.34,1.56,.64,1) both;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(28px) scale(.97)}to{opacity:1;transform:none}}
.logo{
  width:56px;height:56px;margin:0 auto 24px;
  display:flex;align-items:center;justify-content:center;
}
.logo img{width:56px;height:56px;object-fit:contain;filter:drop-shadow(0 8px 20px rgba(99,102,241,.5))}
h1{text-align:center;font-size:20px;font-weight:700;color:#f4f4f5;margin-bottom:4px;letter-spacing:-.3px}
.sub{text-align:center;font-size:13px;color:#52525b;margin-bottom:28px}
label{display:block;font-size:11px;font-weight:600;color:#71717a;text-transform:uppercase;letter-spacing:.7px;margin-bottom:7px}
.input-wrap{position:relative}
.input-wrap svg{position:absolute;left:13px;top:50%;transform:translateY(-50%);width:17px;height:17px;stroke:#3f3f46;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;pointer-events:none}
input[type=password]{
  width:100%;padding:12px 14px 12px 40px;
  background:rgba(0,0,0,.45);border:1px solid rgba(255,255,255,.09);
  border-radius:12px;color:#f4f4f5;font-size:15px;letter-spacing:.1em;outline:none;
  transition:border-color .2s,box-shadow .2s;font-family:'Inter',sans-serif;
}
input[type=password]::placeholder{letter-spacing:0;color:#3f3f46}
input[type=password]:focus{border-color:rgba(99,102,241,.65);box-shadow:0 0 0 3px rgba(99,102,241,.14)}
.btn{
  width:100%;margin-top:18px;padding:13px;
  background:linear-gradient(135deg,#6366f1,#4f46e5);
  border:none;border-radius:12px;color:#fff;
  font-size:14px;font-weight:600;font-family:'Inter',sans-serif;
  cursor:pointer;letter-spacing:.1px;
  transition:transform .18s cubic-bezier(.34,1.56,.64,1),box-shadow .18s;
  box-shadow:0 4px 20px rgba(99,102,241,.38);
}
.btn:hover{transform:translateY(-2px) scale(1.015);box-shadow:0 10px 32px rgba(99,102,241,.52)}
.btn:active{transform:scale(.97)}
.error{
  display:flex;align-items:center;gap:9px;
  padding:11px 14px;background:rgba(239,68,68,.07);
  border:1px solid rgba(239,68,68,.18);border-radius:10px;
  color:#fca5a5;font-size:13px;margin-bottom:18px;
  animation:shake .4s cubic-bezier(.36,.07,.19,.97) both;
}
@keyframes shake{10%,90%{transform:translateX(-2px)}20%,80%{transform:translateX(3px)}30%,50%,70%{transform:translateX(-3px)}40%,60%{transform:translateX(3px)}}
.error svg{width:16px;height:16px;stroke:#ef4444;fill:none;stroke-width:2;stroke-linecap:round;flex-shrink:0}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <svg viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" style="width:32px;height:32px"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.18)"/></svg>
  </div>
  <h1>File Manager</h1>
  <p class="sub">Enter your password to continue</p>
  <?php if(isset($loginError)):?>
  <div class="error">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
    <?=htmlspecialchars($loginError)?>
  </div>
  <?php elseif(!empty($idleExpired)):?>
  <div class="error" style="background:rgba(245,158,11,.08);border-color:rgba(245,158,11,.2);color:#fcd34d">
    <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
    You were signed out due to inactivity. Please sign in again.
  </div>
  <?php endif;?>
  <form method="post">
    <input type="hidden" name="login_csrf" value="<?=htmlspecialchars($_SESSION['login_csrf'])?>">
    <div style="margin-bottom:14px">
      <label for="un">Username</label>
      <div class="input-wrap">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/></svg>
        <input type="text" id="un" name="login_user" placeholder="Enter username" required autofocus style="width:100%;padding:12px 14px 12px 40px;background:rgba(0,0,0,.45);border:1px solid rgba(255,255,255,.09);border-radius:12px;color:#f4f4f5;font-size:15px;outline:none;font-family:'Inter',sans-serif">
      </div>
    </div>
    <div>
      <label for="pw">Password</label>
      <div class="input-wrap">
        <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <input type="password" id="pw" name="login_pass" placeholder="Enter password" required>
      </div>
    </div>
    <button type="submit" class="btn">Sign In</button>
  </form>
</div>
</body></html>
<?php exit; }

/* ── FileManager ── */
class FileManager {
    private $currentDir;
    private $messages = [];
    private $favFile;
    private $root;
    private $readonly;
    private $trashDir;
    private $trashMeta;
    public function __construct() {
        $this->root = !empty($_SESSION['fm_root']) ? realpath($_SESSION['fm_root']) : null;
        $this->readonly = !empty($_SESSION['fm_readonly']);
        $base = $this->root ?: __DIR__;
        $this->currentDir = isset($_GET['dir']) && $_GET['dir'] ? realpath($_GET['dir']) : $base;
        if ($this->currentDir === false || !file_exists($this->currentDir)) { $this->currentDir = $base; $this->addMessage('Directory not found. Returned to root.','warning'); }
        if ($this->root && strpos($this->currentDir.DIRECTORY_SEPARATOR, rtrim($this->root,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR) !== 0 && $this->currentDir !== $this->root) {
            $this->currentDir = $this->root;
            $this->addMessage('Access restricted to your assigned folder.','warning');
        }
        $this->favFile = __DIR__ . '/.favorites.json';
        $this->trashDir = __DIR__ . '/.trash';
        $this->trashMeta = __DIR__ . '/.trash.json';
        if (!is_dir($this->trashDir)) @mkdir($this->trashDir, 0755, true);
    }
    public function isReadonly(){ return $this->readonly; }
    public function getRoot(){ return $this->root; }
    public function getCurrentDir(){return $this->currentDir;}
    public function getMessages(){return $this->messages;}
    public function addMessage($m,$t){$this->messages[]=['text'=>$m,'type'=>$t];}
    public function getSystemRoot(){return strtoupper(substr(PHP_OS,0,3))==='WIN'?getenv("SystemDrive")."\\":"/";}

    /* ── Favorites ── */
    public function getFavorites(){
        if(!file_exists($this->favFile)) return [];
        $c=@file_get_contents($this->favFile);
        $d=@json_decode($c,true);
        return is_array($d)?$d:[];
    }
    private function saveFavorites($f){ @file_put_contents($this->favFile, json_encode(array_values(array_unique($f)))); }
    public function isFavorite($path){ return in_array($path, $this->getFavorites()); }
    private function addFavorite($p){ if(!$p||!is_dir($p))return; $f=$this->getFavorites(); if(!in_array($p,$f)){$f[]=$p;$this->saveFavorites($f);} $this->addMessage('Added to favorites.','success'); }
    private function removeFavorite($p){ $f=array_values(array_diff($this->getFavorites(),[$p])); $this->saveFavorites($f); $this->addMessage('Removed from favorites.','warning'); }

    /* ── Trash ── */
    private function loadTrash(){ if(!file_exists($this->trashMeta)) return []; $d=@json_decode(@file_get_contents($this->trashMeta),true); return is_array($d)?$d:[]; }
    private function saveTrash($t){ @file_put_contents($this->trashMeta, json_encode(array_values($t), JSON_PRETTY_PRINT)); }
    public function getTrashItems(){ $t=$this->loadTrash(); usort($t, function($a,$b){ return $b['trashed_at'] <=> $a['trashed_at']; }); return $t; }
    private function moveToTrash($p, $originalDir){
        if(!file_exists($p)) return false;
        $name = basename($p);
        $id = uniqid('t', true);
        $trashName = $id.'__'.$name;
        $trashPath = $this->trashDir.'/'.$trashName;
        if(@rename($p, $trashPath)){
            $t = $this->loadTrash();
            $t[] = [
                'id' => $id,
                'trash_name' => $trashName,
                'original_name' => $name,
                'original_dir' => $originalDir,
                'type' => is_dir($trashPath) ? 'dir' : 'file',
                'trashed_at' => time(),
                'trashed_by' => isset($_SESSION['fm_user']) ? $_SESSION['fm_user'] : '',
            ];
            $this->saveTrash($t);
            return true;
        }
        return false;
    }
    private function restoreTrashItem($id){
        $t = $this->loadTrash();
        foreach($t as $i=>$e){
            if($e['id']===$id){
                $trashPath = $this->trashDir.'/'.$e['trash_name'];
                if(!file_exists($trashPath)){ $this->addMessage('Trashed item no longer exists.','danger'); array_splice($t,$i,1); $this->saveTrash($t); return; }
                if(!is_dir($e['original_dir'])){ $this->addMessage('Original folder no longer exists. Restore aborted.','danger'); return; }
                $dest = rtrim($e['original_dir'],'/').'/'.$e['original_name'];
                if(file_exists($dest)) $dest = rtrim($e['original_dir'],'/').'/restored_'.time().'_'.$e['original_name'];
                if(@rename($trashPath, $dest)){
                    array_splice($t,$i,1); $this->saveTrash($t);
                    $this->addMessage('Restored "'.$e['original_name'].'".','success');
                } else {
                    $this->addMessage('Restore failed.','danger');
                }
                return;
            }
        }
        $this->addMessage('Trash item not found.','danger');
    }
    private function permanentDeleteTrash($id){
        $t = $this->loadTrash();
        foreach($t as $i=>$e){
            if($e['id']===$id){
                $this->recursiveDelete($this->trashDir.'/'.$e['trash_name']);
                array_splice($t,$i,1); $this->saveTrash($t);
                $this->addMessage('Permanently deleted "'.$e['original_name'].'".','warning');
                return;
            }
        }
        $this->addMessage('Trash item not found.','danger');
    }
    private function emptyTrash(){
        $t = $this->loadTrash();
        foreach($t as $e){ $this->recursiveDelete($this->trashDir.'/'.$e['trash_name']); }
        $this->saveTrash([]);
        $this->addMessage('Trash emptied.','warning');
    }

    /* ── Content search ── */
    public function contentSearch($q){
        $results = [];
        $q = trim($q);
        if($q === '') return $results;
        $textTypes = ['text','code','data','config'];
        $maxResults = 200; $maxSize = 2*1024*1024; $count = 0;
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->currentDir, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
        } catch(Exception $e){ return $results; }
        foreach($it as $item){
            if($count >= $maxResults) break;
            if(!$item->isFile()) continue;
            $p = $item->getPathname();
            if($p === __FILE__) continue;
            if(strpos(basename($p),'.trash')===0 || strpos($p, $this->trashDir)===0) continue;
            if($item->getSize() > $maxSize) continue;
            $type = $this->getFileType($item->getFilename());
            if(!in_array($type, $textTypes)) continue;
            $content = @file_get_contents($p);
            if($content === false) continue;
            $pos = stripos($content, $q);
            if($pos !== false){
                $start = max(0, $pos - 40);
                $snippet = substr($content, $start, 140);
                $snippet = trim(preg_replace('/\s+/', ' ', $snippet));
                $results[] = [
                    'path' => $p,
                    'name' => $item->getFilename(),
                    'dir'  => dirname($p),
                    'snippet' => $snippet,
                ];
                $count++;
            }
        }
        return $results;
    }

    /* ── Disk usage ── */
    public function diskTotal(){ $t=@disk_total_space($this->currentDir); return $t===false?0:$t; }
    public function diskFree(){ $f=@disk_free_space($this->currentDir); return $f===false?0:$f; }

    public function handleRequest(){
        if($_SERVER['REQUEST_METHOD']!=='POST')return;
        if(!isset($_POST['csrf_token'])||$_POST['csrf_token']!==$_SESSION['csrf_token']){$this->addMessage('Security error.','danger');return;}
        $a=isset($_POST['action'])?$_POST['action']:'';
        $writeActions=['upload','create_folder','delete','rename','save_edit','bypass_permissions','bulk_delete','bulk_copy','bulk_move','zip_create','zip_extract','restore_trash','trash_delete_permanent','trash_empty'];
        if($this->readonly && in_array($a,$writeActions)){$this->addMessage('Your account has read-only access.','danger');return;}
        switch($a){
            case 'upload':$this->upload();break;
            case 'create_folder':$this->createFolder();break;
            case 'delete':$this->deleteItem();break;
            case 'rename':$this->renameItem();break;
            case 'save_edit':$this->saveFile();break;
            case 'bypass_permissions':$this->bypassPermissions();break;
            case 'go_to_path':$this->goToPath();break;
            case 'add_favorite':$this->addFavorite(isset($_POST['path'])?$_POST['path']:'');break;
            case 'remove_favorite':$this->removeFavorite(isset($_POST['path'])?$_POST['path']:'');break;
            case 'bulk_delete':$this->bulkDelete();break;
            case 'bulk_copy':$this->bulkCopyMove(false);break;
            case 'bulk_move':$this->bulkCopyMove(true);break;
            case 'zip_create':$this->zipCreate();break;
            case 'zip_extract':$this->zipExtract();break;
            case 'restore_trash':$this->restoreTrashItem(isset($_POST['trash_id'])?$_POST['trash_id']:'');break;
            case 'trash_delete_permanent':$this->permanentDeleteTrash(isset($_POST['trash_id'])?$_POST['trash_id']:'');break;
            case 'trash_empty':$this->emptyTrash();break;
            case 'logout':session_destroy();header("Location: ".basename(__FILE__));exit;
        }
    }
    private function goToPath(){$p=isset($_POST['path'])?trim($_POST['path']):'';if($p&&is_dir($p)){header("Location: ?dir=".urlencode($p));exit;}else $this->addMessage('Invalid path.','danger');}
    private function upload(){
        if(!isset($_FILES['file'])) return;
        $names = $_FILES['file']['name'];
        if(is_array($names)){
            $ok=0;$fail=0;
            foreach($names as $i=>$n){
                if($_FILES['file']['error'][$i]!==0){$fail++;continue;}
                $n=basename($n);
                if(move_uploaded_file($_FILES['file']['tmp_name'][$i],$this->currentDir.'/'.$n))$ok++;else $fail++;
            }
            if($ok)$this->addMessage("$ok file(s) uploaded successfully.".($fail?" $fail failed.":''),'success');
            else $this->addMessage('Upload failed.','danger');
        } else {
            if($_FILES['file']['error']!==0)return;
            $n=basename($names);
            if(move_uploaded_file($_FILES['file']['tmp_name'],$this->currentDir.'/'.$n))$this->addMessage('File uploaded successfully.','success');else $this->addMessage('Upload failed.','danger');
        }
    }
    private function createFolder(){$n=basename(trim(isset($_POST['folder_name'])?$_POST['folder_name']:'')); if(!$n)return;$p=$this->currentDir.'/'.$n;if(!file_exists($p)&&@mkdir($p))$this->addMessage('Folder created.','success');else $this->addMessage('Could not create folder.','danger');}
    private function deleteItem(){$n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');if(!$n)return;if($this->isSelf($n)){$this->addMessage('Access denied.','danger');return;}$p=$this->currentDir.'/'.$n;if($this->moveToTrash($p,$this->currentDir))$this->addMessage('Moved to trash.','warning');else $this->addMessage('Delete failed.','danger');}
    private function renameItem(){$o=basename(isset($_POST['old_name'])?$_POST['old_name']:'');$nw=basename(isset($_POST['new_name'])?$_POST['new_name']:'');if(!$o||!$nw||$o===$nw)return;if($this->isSelf($o)){$this->addMessage('Access denied.','danger');return;}$po=$this->currentDir.'/'.$o;$pn=$this->currentDir.'/'.$nw;if(file_exists($po)&&!file_exists($pn)&&@rename($po,$pn))$this->addMessage('Renamed successfully.','success');else $this->addMessage('Rename failed.','danger');}
    private function saveFile(){$n=basename(isset($_POST['filename'])?$_POST['filename']:'');if(!$n)return;if($this->isSelf($n)){$this->addMessage('Access denied.','danger');return;}$p=$this->currentDir.'/'.$n;if(!file_exists($p)||!is_file($p)){$this->addMessage('File not found.','danger');return;}$c=isset($_POST['content'])?$_POST['content']:'';if(trim($c)===''){$this->addMessage('Cannot save empty content.','warning');return;}if(file_put_contents($p,$c)!==false)$this->addMessage('File saved.','success');else $this->addMessage('Save failed.','danger');}
    private function bypassPermissions(){$cnt=0;$f=0;$self=__FILE__;$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->currentDir,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST);foreach($it as $item){$p=$item->getPathname();if($p===$self)continue;if($item->isDir()){if(@chmod($p,0777))$cnt++;else $f++;}else{if(@chmod($p,0666))$cnt++;else $f++;}}$this->addMessage("Permissions updated: $cnt changed".($f?", $f failed":""),$f?'warning':'success');}
    private function recursiveDelete($p){if(is_file($p)||is_link($p))return @unlink($p);if(is_dir($p)){foreach(glob($p.'/*')as $i)$this->recursiveDelete($i);return @rmdir($p);}return false;}
    private function isSelf($name){return realpath($this->currentDir.'/'.$name)===__FILE__;}
    public function getSelfName(){return basename(__FILE__);}

    /* ── Bulk operations ── */
    private function getSelectedItems(){
        $raw = isset($_POST['items']) ? $_POST['items'] : '';
        $arr = json_decode($raw, true);
        if(!is_array($arr)) return [];
        $r=[];
        foreach($arr as $n){ $n=basename($n); if($n && !$this->isSelf($n)) $r[]=$n; }
        return $r;
    }
    private function bulkDelete(){
        $items=$this->getSelectedItems(); if(!$items){$this->addMessage('No items selected.','warning');return;}
        $ok=0;foreach($items as $n){ if($this->recursiveDelete($this->currentDir.'/'.$n)) $ok++; }
        $this->addMessage("$ok item(s) deleted.",'warning');
    }
    private function recursiveCopy($src,$dst){
        if(is_dir($src)){
            if(!file_exists($dst)) @mkdir($dst,0755,true);
            foreach(glob($src.'/*') as $item){ $this->recursiveCopy($item, $dst.'/'.basename($item)); }
            return true;
        }
        return @copy($src,$dst);
    }
    private function bulkCopyMove($move){
        $items=$this->getSelectedItems(); if(!$items){$this->addMessage('No items selected.','warning');return;}
        $target=isset($_POST['target'])?trim($_POST['target']):'';
        if(!$target||!is_dir($target)){$this->addMessage('Invalid target folder.','danger');return;}
        $ok=0;
        foreach($items as $n){
            $src=$this->currentDir.'/'.$n; $dst=rtrim($target,'/').'/'.$n;
            if(file_exists($dst))continue;
            if($move){ if(@rename($src,$dst))$ok++; }
            else { if($this->recursiveCopy($src,$dst))$ok++; }
        }
        $this->addMessage("$ok item(s) ".($move?'moved':'copied').".",'success');
    }

    /* ── Zip ── */
    private function zipAddFolder($zip,$path,$base){
        $items = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::LEAVES_ONLY);
        foreach($items as $item){
            $filePath = $item->getPathname();
            $relPath = $base.'/'.substr($filePath, strlen($path)+1);
            $zip->addFile($filePath, $relPath);
        }
    }
    private function zipCreate(){
        if(!class_exists('ZipArchive')){$this->addMessage('ZIP support is not available on this server.','danger');return;}
        $items=$this->getSelectedItems(); if(!$items){$this->addMessage('No items selected.','warning');return;}
        $zipName = 'archive_'.date('Ymd_His').'.zip';
        $zipPath = $this->currentDir.'/'.$zipName;
        $zip = new ZipArchive();
        if($zip->open($zipPath, ZipArchive::CREATE) !== true){$this->addMessage('Could not create zip file.','danger');return;}
        foreach($items as $n){
            $p=$this->currentDir.'/'.$n;
            if(is_dir($p)) $this->zipAddFolder($zip,$p,$n);
            elseif(is_file($p)) $zip->addFile($p,$n);
        }
        $zip->close();
        $this->addMessage("Created $zipName with ".count($items)." item(s).",'success');
    }
    private function zipExtract(){
        if(!class_exists('ZipArchive')){$this->addMessage('ZIP support is not available on this server.','danger');return;}
        $n=basename(isset($_POST['item_name'])?$_POST['item_name']:''); if(!$n)return;
        $p=$this->currentDir.'/'.$n;
        if(!is_file($p) || strtolower(pathinfo($p,PATHINFO_EXTENSION))!=='zip'){$this->addMessage('Not a valid zip file.','danger');return;}
        $target = $this->currentDir.'/'.pathinfo($n,PATHINFO_FILENAME);
        $zip = new ZipArchive();
        if($zip->open($p)===true){
            if(!file_exists($target)) @mkdir($target,0755,true);
            $zip->extractTo($target);
            $zip->close();
            $this->addMessage('Extracted to '.pathinfo($n,PATHINFO_FILENAME).'/','success');
        } else $this->addMessage('Failed to open zip file.','danger');
    }

    public function scanDir(){
        $items=@scandir($this->currentDir);if($items===false)return['folders'=>[],'files'=>[]];
        $r=['folders'=>[],'files'=>[]];$self=basename(__FILE__);
        $q = isset($_GET['q']) ? trim($_GET['q']) : '';
        foreach($items as $i){
            if($i=='.'||$i=='..')continue;
            if($i===$self&&$this->currentDir===__DIR__)continue;
            if($i==='.favorites.json')continue;
            if($q !== '' && stripos($i, $q) === false) continue;
            $p=$this->currentDir.'/'.$i;
            if(is_dir($p))$r['folders'][]=$i;else $r['files'][]=$i;
        }
        return $r;
    }
    public function getFileType($f){
        $e=strtolower(pathinfo($f,PATHINFO_EXTENSION));
        $map=['jpg'=>'image','jpeg'=>'image','png'=>'image','gif'=>'image','svg'=>'image','webp'=>'image','ico'=>'image','bmp'=>'image',
              'mp4'=>'video','avi'=>'video','mkv'=>'video','mov'=>'video','webm'=>'video',
              'mp3'=>'audio','wav'=>'audio','flac'=>'audio','ogg'=>'audio','aac'=>'audio',
              'zip'=>'archive','rar'=>'archive','7z'=>'archive','tar'=>'archive','gz'=>'archive','bz2'=>'archive',
              'pdf'=>'pdf','doc'=>'word','docx'=>'word','xls'=>'excel','xlsx'=>'excel',
              'php'=>'code','html'=>'code','htm'=>'code','css'=>'code','js'=>'code','ts'=>'code',
              'py'=>'code','java'=>'code','sh'=>'code','bash'=>'code','rb'=>'code','go'=>'code','rs'=>'code','c'=>'code','cpp'=>'code',
              'json'=>'data','xml'=>'data','yml'=>'data','yaml'=>'data','sql'=>'data','csv'=>'data',
              'txt'=>'text','log'=>'text','md'=>'text','env'=>'config','gitignore'=>'config'];
        return isset($map[$e])?$map[$e]:'file';
    }
    public function getFileColor($type){
        $colors=['image'=>'#f59e0b','video'=>'#ec4899','audio'=>'#8b5cf6','archive'=>'#f97316',
                 'pdf'=>'#ef4444','word'=>'#3b82f6','excel'=>'#22c55e','code'=>'#818cf8',
                 'data'=>'#06b6d4','text'=>'#94a3b8','config'=>'#fb7185','file'=>'#52525b'];
        return isset($colors[$type])?$colors[$type]:'#52525b';
    }
    public function isPreviewable($type){
        return in_array($type, ['image','video','pdf','text','code','data','config']);
    }
    public function getBreadcrumbs(){
        $d=$this->currentDir;$parts=explode(DIRECTORY_SEPARATOR,$d);$path='';$r=[];
        foreach($parts as $p){if($p==='')continue;$path.=DIRECTORY_SEPARATOR.$p;$r[]=['path'=>$path,'label'=>$p];}
        return $r;
    }
}

$fm = new FileManager();

/* ── Raw file serving (for previews & downloads) ── */
if (isset($_GET['raw'])) {
    $fn = basename($_GET['raw']);
    $dir = isset($_GET['dir']) ? realpath($_GET['dir']) : __DIR__;
    if ($dir === false) $dir = __DIR__;
    $fp = realpath($dir . '/' . $fn);
    if ($fp && is_file($fp) && $fp !== __FILE__) {
        $mime = function_exists('mime_content_type') ? @mime_content_type($fp) : 'application/octet-stream';
        if (!$mime) $mime = 'application/octet-stream';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($fp));
        if (isset($_GET['dl'])) header('Content-Disposition: attachment; filename="'.$fn.'"');
        readfile($fp);
        exit;
    }
    http_response_code(404); exit;
}

$fm->handleRequest();

$userMessage = null;
if($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action']) && in_array($_POST['action'],['add_user','remove_user','update_user'])){
    if(!isset($_POST['csrf_token'])||$_POST['csrf_token']!==$_SESSION['csrf_token']){ $userMessage=['Security error.','danger']; }
    elseif(empty($_SESSION['fm_admin'])){ $userMessage=['Only admins can manage users.','danger']; }
    else {
        $users = fm_load_users($usersFile);
        if($_POST['action']==='add_user'){
            $nu = trim(isset($_POST['new_user'])?$_POST['new_user']:'');
            $np = isset($_POST['new_pass'])?$_POST['new_pass']:'';
            $nr = trim(isset($_POST['new_root'])?$_POST['new_root']:'');
            $nro = isset($_POST['new_readonly']) && $_POST['new_readonly']==='1';
            if(!$nu || !$np){ $userMessage=['Username and password are required.','danger']; }
            elseif(fm_find_user($users,$nu)){ $userMessage=['That username already exists.','danger']; }
            elseif($nr!=='' && !is_dir($nr)){ $userMessage=['Assigned folder path does not exist.','danger']; }
            else {
                $users[] = ['user'=>$nu,'hash'=>password_hash($np,PASSWORD_DEFAULT),'root'=>$nr,'readonly'=>$nro,'admin'=>false];
                fm_save_users($usersFile,$users);
                $userMessage=["User '$nu' created.",'success'];
            }
        } elseif($_POST['action']==='remove_user'){
            $tu = trim(isset($_POST['target_user'])?$_POST['target_user']:'');
            if($tu==='admin'||$tu===$_SESSION['fm_user']){ $userMessage=['Cannot remove this account.','danger']; }
            else {
                $users = array_values(array_filter($users, function($u) use ($tu){ return $u['user']!==$tu; }));
                fm_save_users($usersFile,$users);
                $userMessage=["User '$tu' removed.",'success'];
            }
        }
    }
    header("Location: ".$scriptName."?dir=".urlencode($fm->getCurrentDir())."&umsg=".urlencode($userMessage[0])."&utype=".urlencode($userMessage[1]));
    exit;
}
if(isset($_GET['umsg'])) $fm->addMessage($_GET['umsg'], isset($_GET['utype'])?$_GET['utype']:'success');

$list = $fm->scanDir();
$editMode = false; $editContent = ''; $editFile = '';
if(isset($_GET['edit'])){
  $fn=basename($_GET['edit']);
  $fp=realpath($fm->getCurrentDir().'/'.$fn);
  if($fp && is_file($fp) && $fp!==__FILE__){
    $editMode=true;$editFile=$fn;$editContent=file_get_contents($fp);
  }
}

$totalFolders=count($list['folders']);
$totalFiles=count($list['files']);
$totalSize=0;foreach($list['files']as $f)$totalSize+=@filesize($fm->getCurrentDir().'/'.$f);
function fmtSize($b){if($b>=1073741824)return round($b/1073741824,2).' GB';if($b>=1048576)return round($b/1048576,1).' MB';if($b>=1024)return round($b/1024,1).' KB';return $b.' B';}

$diskTotal = $fm->diskTotal();
$diskFree  = $fm->diskFree();
$diskUsed  = $diskTotal - $diskFree;
$diskPct   = $diskTotal > 0 ? round(($diskUsed / $diskTotal) * 100) : 0;

// SVG icon helpers (inline SVGs for all file/type icons — crisp at any size, colored via currentColor)
function svgFolder(){
    return '<svg class="type-icon" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.18)"/></svg>';
}
function svgFile($type='file'){
    global $fm;
    $color = $fm->getFileColor($type);
    $paths = [
        'image' => '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>',
        'video' => '<rect x="2" y="5" width="14" height="14" rx="2"/><path d="M16 10l6-4v12l-6-4z"/>',
        'audio' => '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
        'archive' => '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 3v18M14 8h2M14 12h2M14 16h2"/>',
        'pdf' => '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><text x="12" y="18" font-size="6.5" text-anchor="middle" fill="currentColor" stroke="none" font-weight="700">PDF</text>',
        'word' => '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
        'excel' => '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><path d="M9.5 13l5 6M14.5 13l-5 6"/>',
        'code' => '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
        'data' => '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
        'text' => '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>',
        'config' => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
        'file' => '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>',
    ];
    $inner = isset($paths[$type]) ? $paths[$type] : $paths['file'];
    return '<svg class="type-icon" viewBox="0 0 24 24" fill="none" stroke="'.$color.'" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'.$inner.'</svg>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>File Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
/* ══════════════════════════════════════════════
   TOKENS
══════════════════════════════════════════════ */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  /* Surfaces */
  --bg:         #09090b;
  --panel:      #0d0d10;
  --surface:    #111115;
  --raised:     #18181c;
  --hover:      #1c1c21;
  --active:     #222228;
  --border:     rgba(255,255,255,.065);
  --border2:    rgba(255,255,255,.11);

  /* Text */
  --t1:    #f4f4f5;
  --t2:    #71717a;
  --t3:    #3f3f46;
  --link:  #818cf8;

  /* Brand */
  --indigo:  #6366f1;
  --indigo2: #4f46e5;

  /* Semantic */
  --green:  #22c55e;
  --amber:  #f59e0b;
  --red:    #ef4444;
  --blue:   #3b82f6;

  /* Layout */
  --sidebar-w: 240px;
  --topbar-h:  52px;
  --bar-h:     28px;
  --r:    10px;
  --r-lg: 14px;
  --r-xl: 18px;

  /* iOS spring easing */
  --ease-spring: cubic-bezier(.34,1.56,.64,1);
  --ease-out:    cubic-bezier(.25,.46,.45,.94);
  --ease-in-out: cubic-bezier(.45,0,.15,1);
}

html{height:100%;-webkit-tap-highlight-color:transparent}
body{
  font-family:'Inter',system-ui,sans-serif;
  background:var(--bg);color:var(--t1);
  font-size:13.5px;line-height:1.5;
  height:100vh;overflow:hidden;
  -webkit-font-smoothing:antialiased;
}

/* ══════════════════════════════════════════════
   LAYOUT
══════════════════════════════════════════════ */
.shell{
  display:grid;
  grid-template:
    "topbar  topbar"  var(--topbar-h)
    "sidebar main"    1fr
    "bar     bar"     var(--bar-h)
    / var(--sidebar-w) 1fr;
  height:100vh;
  width:100vw;
  overflow:hidden;
}

/* ══════════════════════════════════════════════
   TOPBAR
══════════════════════════════════════════════ */
.topbar{
  grid-area:topbar;
  background:var(--panel);
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;
  padding:0 12px;gap:8px;
  z-index:200;
}

.brand{
  display:flex;align-items:center;gap:9px;
  width:var(--sidebar-w);flex-shrink:0;
  text-decoration:none;padding-right:4px;
}
.brand-icon{
  width:30px;height:30px;
  display:flex;align-items:center;justify-content:center;flex-shrink:0;
  transition:transform .25s var(--ease-spring);
}
.brand-icon:hover{transform:scale(1.1)}
.brand-icon img{width:26px;height:26px;object-fit:contain}
.brand-name{font-size:13.5px;font-weight:700;color:var(--t1);letter-spacing:-.2px}

.divider-v{width:1px;height:20px;background:var(--border);flex-shrink:0}

/* Breadcrumb */
.bc{
  display:flex;align-items:center;gap:0;
  flex:1;overflow:hidden;min-width:0;
}
.bc-crumb{
  display:flex;align-items:center;gap:0;
  animation:fadeSlide .3s var(--ease-spring) both;
}
@keyframes fadeSlide{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.bc-crumb:nth-child(2){animation-delay:.04s}
.bc-crumb:nth-child(3){animation-delay:.08s}
.bc-crumb:nth-child(4){animation-delay:.12s}

.bc a{
  font-family:'JetBrains Mono',monospace;font-size:11.5px;
  color:var(--t2);text-decoration:none;
  padding:3px 7px;border-radius:6px;
  transition:background .15s var(--ease-out),color .15s;
  white-space:nowrap;max-width:130px;
  overflow:hidden;text-overflow:ellipsis;display:inline-block;
}
.bc a:hover{background:var(--hover);color:var(--link)}
.bc a.last{color:var(--t1);font-weight:500}
.bc-sep{
  font-family:'JetBrains Mono',monospace;font-size:11px;
  color:var(--t3);padding:0 2px;
  user-select:none;
}

.topbar-actions{display:flex;align-items:center;gap:5px;margin-left:auto}
.topbar-search{display:flex;align-items:center;gap:6px;background:rgba(0,0,0,.35);border:1px solid var(--border);border-radius:var(--r);padding:0 4px 0 10px}
.topbar-search img{width:14px;height:14px;opacity:.6;flex-shrink:0}
.topbar-search input{background:transparent;border:none;outline:none;color:var(--t1);font-size:12.5px;padding:7px 4px;width:160px}
.topbar-search input::placeholder{color:var(--t3)}

/* ══════════════════════════════════════════════
   SIDEBAR
══════════════════════════════════════════════ */
.sidebar{
  grid-area:sidebar;
  background:var(--panel);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  overflow:hidden;
}

.sb-section{padding:12px 10px 0}
.sb-label{
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
  color:var(--t3);padding:4px 8px 6px;
  display:flex;align-items:center;justify-content:space-between;
}
.sb-nav{display:flex;flex-direction:column;gap:1px}

.sb-item{
  display:flex;align-items:center;gap:9px;
  padding:8px 10px;border-radius:var(--r);
  color:var(--t2);text-decoration:none;
  font-size:13px;font-weight:500;
  transition:background .18s var(--ease-out),color .18s,transform .18s var(--ease-spring);
  cursor:pointer;border:none;background:transparent;width:100%;text-align:left;
}
.sb-item svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0;transition:transform .2s var(--ease-spring)}
.sb-item svg.type-icon-sm{width:16px;height:16px;flex-shrink:0}
.sb-item:hover{background:var(--hover);color:var(--t1);transform:translateX(2px)}
.sb-item:hover svg{transform:scale(1.12)}
.sb-item:active{transform:scale(.97)}
.sb-item.danger{color:var(--t2)}
.sb-item.danger:hover{background:rgba(239,68,68,.08);color:#fca5a5}

.sb-div{height:1px;background:var(--border);margin:8px 12px}

.sb-folders{
  flex:0 1 auto;overflow-y:auto;
  padding:0 10px 10px;
  overflow-x:hidden;
  max-height:32vh;
}
.sb-folder-list{display:flex;flex-direction:column;gap:1px}
.sb-flink{
  display:flex;align-items:center;gap:8px;
  padding:7px 10px;border-radius:var(--r);
  color:var(--t2);text-decoration:none;font-size:13px;
  transition:background .18s var(--ease-out),color .18s,transform .18s var(--ease-spring);
}
.sb-flink img{width:15px;height:15px;flex-shrink:0}
.sb-flink span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.sb-flink:hover{background:var(--hover);color:var(--t1);transform:translateX(2px)}
.sb-flink:active{transform:scale(.97)}
.sb-empty{font-size:12px;color:var(--t3);padding:10px 8px;font-style:italic}

.sb-fav-row{display:flex;align-items:center;gap:4px}
.sb-fav-remove{background:none;border:none;color:var(--t3);cursor:pointer;padding:3px;border-radius:6px;flex-shrink:0;display:flex}
.sb-fav-remove:hover{color:#fca5a5;background:rgba(239,68,68,.1)}
.sb-fav-remove svg{width:12px;height:12px;stroke:currentColor;fill:none;stroke-width:2}

.sb-footer{padding:10px;flex-shrink:0;display:flex;flex-direction:column;gap:8px}

/* Disk usage bar */
.disk-widget{padding:4px 4px 2px}
.disk-label{display:flex;justify-content:space-between;font-size:10.5px;color:var(--t3);margin-bottom:5px;font-family:'JetBrains Mono',monospace}
.disk-track{height:6px;background:var(--raised);border-radius:6px;overflow:hidden}
.disk-fill{height:100%;background:linear-gradient(90deg,var(--indigo2),var(--indigo));border-radius:6px;transition:width .4s var(--ease-out)}
.disk-fill.warn{background:linear-gradient(90deg,#d97706,var(--amber))}
.disk-fill.crit{background:linear-gradient(90deg,#b91c1c,var(--red))}

/* ══════════════════════════════════════════════
   MAIN
══════════════════════════════════════════════ */
.main{
  grid-area:main;
  background:var(--bg);
  display:flex;flex-direction:column;
  overflow:hidden;min-width:0;
  position:relative;
}

/* Toolbar */
.toolbar{
  padding:10px 14px;
  border-bottom:1px solid var(--border);
  background:var(--panel);
  display:flex;flex-wrap:wrap;gap:7px;align-items:center;
  flex-shrink:0;
}

/* Content area */
.content{flex:1;overflow-y:auto;padding:14px;position:relative}
.content::-webkit-scrollbar{width:4px}
.content::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:10px}
.content.drag-over::after{
  content:'Drop files to upload';
  position:absolute;inset:8px;border:2px dashed var(--indigo);border-radius:var(--r-lg);
  background:rgba(99,102,241,.08);
  display:flex;align-items:center;justify-content:center;
  font-size:16px;font-weight:600;color:var(--link);
  pointer-events:none;z-index:50;
}

/* ══════════════════════════════════════════════
   ALERTS
══════════════════════════════════════════════ */
.alerts{display:flex;flex-direction:column;gap:7px;margin-bottom:12px}
.alert{
  display:flex;align-items:center;gap:10px;
  padding:10px 13px;border-radius:var(--r);
  font-size:13px;border:1px solid transparent;
  animation:alertIn .35s var(--ease-spring) both;
  position:relative;
}
@keyframes alertIn{from{opacity:0;transform:translateY(-10px) scale(.97)}to{opacity:1;transform:none}}
.alert svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;flex-shrink:0}
.alert.success{background:rgba(34,197,94,.07);border-color:rgba(34,197,94,.2);color:#86efac}
.alert.danger {background:rgba(239,68,68,.07); border-color:rgba(239,68,68,.2); color:#fca5a5}
.alert.warning{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.2);color:#fcd34d}
.alert-close{
  margin-left:auto;background:none;border:none;cursor:pointer;
  color:inherit;opacity:.5;padding:2px;border-radius:4px;
  display:flex;align-items:center;
  transition:opacity .15s,transform .15s var(--ease-spring);
}
.alert-close:hover{opacity:1;transform:scale(1.15)}
.alert-close svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round}

/* ══════════════════════════════════════════════
   FILE TABLE
══════════════════════════════════════════════ */
.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--r-lg);overflow:hidden;
}
.table-wrap{overflow-x:auto}
.file-table{width:100%;border-collapse:collapse}

.file-table thead tr{
  background:var(--raised);
  border-bottom:1px solid var(--border);
}
.file-table th{
  padding:9px 14px;
  font-size:10.5px;font-weight:700;
  text-transform:uppercase;letter-spacing:.65px;
  color:var(--t3);text-align:left;white-space:nowrap;
  user-select:none;
}
.file-table tbody tr{
  border-bottom:1px solid var(--border);
  transition:background .15s var(--ease-out);
  animation:rowIn .3s var(--ease-spring) both;
}
.file-table tbody tr:last-child{border-bottom:none}
.file-table tbody tr:hover{background:var(--hover)}
.file-table tbody tr:active{background:var(--active)}
.file-table tbody tr.selected{background:rgba(99,102,241,.1)}

/* stagger rows */
<?php for($i=1;$i<=50;$i++) echo ".file-table tbody tr:nth-child($i){animation-delay:".($i*.025)."s}\n"; ?>

@keyframes rowIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}

.file-table td{padding:9px 14px;vertical-align:middle}
.col-check{width:34px}
.row-check{
  width:16px;height:16px;cursor:pointer;
  appearance:none;-webkit-appearance:none;
  background:rgba(0,0,0,.45);
  border:1.5px solid rgba(255,255,255,.18);
  border-radius:5px;
  display:inline-block;position:relative;flex-shrink:0;
  transition:background .15s,border-color .15s;
}
.row-check:hover{border-color:rgba(255,255,255,.32)}
.row-check:checked{background:var(--indigo);border-color:var(--indigo)}
.row-check:checked::after{
  content:'';position:absolute;left:4px;top:0.5px;
  width:5px;height:9px;
  border:solid #fff;border-width:0 2px 2px 0;
  transform:rotate(45deg);
}

/* Name cell */
.name-cell{display:flex;align-items:center;gap:11px;cursor:pointer}
.icon-box{
  width:36px;height:36px;flex-shrink:0;
  border-radius:10px;display:flex;align-items:center;justify-content:center;
  transition:transform .2s var(--ease-spring);
}
.file-table tbody tr:hover .icon-box{transform:scale(1.08)}
.icon-box .type-icon{width:22px;height:22px;object-fit:contain}
.name-main{min-width:0}
.name-text{
  color:var(--t1);font-weight:500;font-size:13.5px;
  display:block;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;max-width:240px;
  text-decoration:none;
  transition:color .15s;
}
a.name-text:hover{color:var(--link)}
.ext-badge{
  display:inline-block;margin-top:2px;
  font-family:'JetBrains Mono',monospace;
  font-size:9.5px;font-weight:600;letter-spacing:.4px;text-transform:uppercase;
  padding:1px 6px;border-radius:4px;
  background:var(--raised);color:var(--t3);
}
.mono-text{
  font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--t2);
  padding:3px 8px;border-radius:6px;background:var(--raised);white-space:nowrap;
}
.size-text{
  font-family:'JetBrains Mono',monospace;font-size:12px;
  color:var(--t2);white-space:nowrap;
}

.actions{display:flex;gap:4px;justify-content:flex-end}

/* ══════════════════════════════════════════════
   FLOATING BULK ACTION BAR
══════════════════════════════════════════════ */
.bulk-bar{
  position:absolute;left:50%;bottom:16px;transform:translate(-50%,120%);
  background:var(--raised);border:1px solid var(--border2);
  border-radius:14px;padding:8px 10px;
  display:flex;align-items:center;gap:8px;
  box-shadow:0 16px 40px rgba(0,0,0,.5);
  transition:transform .28s var(--ease-spring);
  z-index:80;
}
.bulk-bar.show{transform:translate(-50%,0)}
.bulk-count{font-size:12.5px;color:var(--t1);font-weight:600;padding:0 6px;white-space:nowrap}

/* ══════════════════════════════════════════════
   PREVIEW MODAL
══════════════════════════════════════════════ */
.preview-overlay{
  display:none;position:fixed;inset:0;z-index:300;
  background:rgba(0,0,0,.78);backdrop-filter:blur(8px);
  align-items:center;justify-content:center;padding:24px;
}
.preview-overlay.open{display:flex}
.preview-box{
  background:var(--surface);border:1px solid var(--border2);
  border-radius:var(--r-lg);max-width:min(900px,92vw);max-height:88vh;
  display:flex;flex-direction:column;overflow:hidden;
  animation:fadeUp .3s var(--ease-spring) both;
}
.preview-head{
  display:flex;align-items:center;gap:10px;padding:12px 16px;
  border-bottom:1px solid var(--border);background:var(--raised);
}
.preview-head span{font-size:13px;font-weight:600;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.preview-body{padding:0;overflow:auto;display:flex;align-items:center;justify-content:center;background:#000}
.preview-body img{max-width:100%;max-height:78vh;display:block}
.preview-body video{max-width:100%;max-height:78vh}
.preview-body iframe{width:min(860px,88vw);height:75vh;border:none;background:#fff}
.preview-body pre{width:min(860px,88vw);max-height:75vh;overflow:auto;padding:18px;font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#cdd6f4;background:#07090e;text-align:left;white-space:pre-wrap;word-break:break-word}

/* ══════════════════════════════════════════════
   EMPTY STATE
══════════════════════════════════════════════ */
.empty{text-align:center;padding:64px 20px}
.empty svg{width:48px;height:48px;stroke:var(--t3);fill:none;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;margin:0 auto 14px}
.empty p{color:var(--t3);font-size:14px;font-weight:500}

/* ══════════════════════════════════════════════
   EDITOR
══════════════════════════════════════════════ */
.editor-card{
  background:var(--surface);border:1px solid var(--border);
  border-radius:var(--r-lg);overflow:hidden;
  animation:fadeUp .35s var(--ease-spring) both;
}
@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
.editor-header{
  display:flex;align-items:center;flex-wrap:wrap;gap:10px;
  padding:11px 16px;background:var(--raised);border-bottom:1px solid var(--border);
}
.editor-filename{
  display:flex;align-items:center;gap:8px;
  font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:500;color:var(--t1);
}
.editor-filename svg{width:15px;height:15px;stroke:var(--indigo);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.editor-meta{font-size:11.5px;color:var(--t3);font-family:'JetBrains Mono',monospace;margin-left:auto}
textarea.code{
  display:block;width:100%;min-height:500px;
  background:#07090e;color:#cdd6f4;
  border:none;padding:20px 22px;
  font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.85;
  resize:vertical;outline:none;tab-size:4;
  transition:box-shadow .2s;
}
textarea.code:focus{box-shadow:inset 0 0 0 1px rgba(99,102,241,.5)}
.editor-footer{
  padding:10px 16px;background:var(--raised);border-top:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;
}
.editor-hint{
  font-size:11.5px;color:var(--t3);
  font-family:'JetBrains Mono',monospace;
}
kbd{
  background:var(--surface);border:1px solid var(--border);
  border-radius:4px;padding:1px 5px;font-size:10.5px;
  font-family:'JetBrains Mono',monospace;color:var(--t2);
}

/* ══════════════════════════════════════════════
   STATUS BAR
══════════════════════════════════════════════ */
.bar{
  grid-area:bar;
  background:linear-gradient(90deg,var(--indigo2),var(--indigo));
  display:flex;align-items:center;
  padding:0 14px;gap:20px;overflow:hidden;
}
.bar-stat{
  display:flex;align-items:center;gap:5px;
  font-size:11px;font-family:'JetBrains Mono',monospace;
  color:rgba(255,255,255,.72);white-space:nowrap;
}
.bar-stat svg{width:12px;height:12px;stroke:rgba(255,255,255,.8);fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.bar-stat strong{color:#fff;font-weight:600}
.bar-right{margin-left:auto;display:flex;gap:20px;align-items:center}

/* ══════════════════════════════════════════════
   BUTTONS
══════════════════════════════════════════════ */
.btn{
  display:inline-flex;align-items:center;gap:6px;
  padding:8px 14px;border-radius:var(--r);
  font-family:'Inter',system-ui,sans-serif;
  font-size:13px;font-weight:600;
  border:none;cursor:pointer;
  text-decoration:none;white-space:nowrap;line-height:1;
  transition:background .18s var(--ease-out),transform .2s var(--ease-spring),box-shadow .18s;
  -webkit-user-select:none;user-select:none;
}
.btn svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.btn img{width:14px;height:14px;flex-shrink:0}
.btn:active{transform:scale(.94) !important}

/* sizes */
.btn-sm {padding:6px 12px;font-size:12.5px;border-radius:8px}
.btn-sm svg{width:13px;height:13px}
.btn-icon{padding:7px;border-radius:8px}
.btn-icon svg{width:15px;height:15px}
.btn-xs{padding:5px 9px;font-size:12px;border-radius:7px;gap:4px}
.btn-xs svg{width:13px;height:13px}

/* variants */
.btn-primary{
  background:var(--indigo);color:#fff;
  box-shadow:0 2px 10px rgba(99,102,241,.3);
}
.btn-primary:hover{background:#7c3aed;transform:translateY(-1.5px) scale(1.01);box-shadow:0 6px 20px rgba(124,58,237,.45)}
.btn-ghost{
  background:transparent;color:var(--t2);
  border:1px solid var(--border);
}
.btn-ghost:hover{background:var(--hover);color:var(--t1);border-color:var(--border2);transform:translateY(-1px)}
.btn-green{background:rgba(34,197,94,.1);color:#86efac;border:1px solid rgba(34,197,94,.2)}
.btn-green:hover{background:rgba(34,197,94,.18);transform:translateY(-1px)}
.btn-amber{background:rgba(245,158,11,.1);color:#fcd34d;border:1px solid rgba(245,158,11,.2)}
.btn-amber:hover{background:rgba(245,158,11,.18);transform:translateY(-1px)}
.btn-red{background:rgba(239,68,68,.1);color:#fca5a5;border:1px solid rgba(239,68,68,.18)}
.btn-red:hover{background:rgba(239,68,68,.18);transform:translateY(-1px)}
.btn-blue{background:rgba(59,130,246,.1);color:#93c5fd;border:1px solid rgba(59,130,246,.2)}
.btn-blue:hover{background:rgba(59,130,246,.18);transform:translateY(-1px)}
.btn-star{background:rgba(245,158,11,.12);color:#fcd34d;border:1px solid rgba(245,158,11,.25)}
.btn-star:hover{background:rgba(245,158,11,.2);transform:translateY(-1px)}

/* ══════════════════════════════════════════════
   INPUTS
══════════════════════════════════════════════ */
.input{
  background:rgba(0,0,0,.35);border:1px solid var(--border);
  color:var(--t1);border-radius:var(--r);
  padding:8px 12px;font-size:13px;
  font-family:'Inter',system-ui,sans-serif;
  outline:none;min-width:0;
  transition:border-color .18s,box-shadow .18s,background .18s;
}
.input::placeholder{color:var(--t3)}
.input:focus{border-color:rgba(99,102,241,.55);background:rgba(0,0,0,.5);box-shadow:0 0 0 3px rgba(99,102,241,.1)}

/* Upload trigger */
.upload-label{
  display:inline-flex;align-items:center;gap:7px;
  padding:8px 14px;border-radius:var(--r);
  font-size:13px;font-weight:600;font-family:'Inter',system-ui,sans-serif;
  cursor:pointer;white-space:nowrap;
  border:1.5px dashed rgba(99,102,241,.35);
  color:var(--t2);
  background:rgba(99,102,241,.04);
  transition:border-color .18s,color .18s,background .18s,transform .2s var(--ease-spring);
}
.upload-label img{width:14px;height:14px}
.upload-label:hover{border-color:var(--indigo);color:var(--link);background:rgba(99,102,241,.09);transform:translateY(-1px)}
.upload-label:active{transform:scale(.97)}
input[type=file]{display:none}

/* ══════════════════════════════════════════════
   OVERLAY
══════════════════════════════════════════════ */
.overlay{
  display:none;position:fixed;inset:0;
  background:rgba(0,0,0,.65);z-index:150;
  backdrop-filter:blur(6px);
  -webkit-backdrop-filter:blur(6px);
  opacity:0;transition:opacity .3s var(--ease-out);
}
.overlay.visible{opacity:1}

/* ══════════════════════════════════════════════
   SCROLLBAR
══════════════════════════════════════════════ */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:rgba(255,255,255,.09);border-radius:10px}
::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.16)}

/* ══════════════════════════════════════════════
   MOBILE MENU BUTTON (hidden on desktop)
══════════════════════════════════════════════ */
.menu-btn{display:none}

/* ══════════════════════════════════════════════
   TOOLBAR — mobile stacking
══════════════════════════════════════════════ */
.toolbar-row{display:contents}
@media(max-width:768px){
  .toolbar{
    padding:12px;gap:10px;
    flex-direction:column;align-items:stretch;
  }
  .toolbar-row{display:flex;align-items:stretch;gap:10px;width:100%}
  .toolbar-row .upload-label{flex:1;justify-content:center;min-height:44px;padding:11px 14px}
  .toolbar-row .input{flex:1;min-height:44px;padding:11px 14px}
  .toolbar-row .btn-sm{flex-shrink:0;min-height:44px;padding:11px 16px}
  .toolbar-row .btn-green{min-width:52px}
  .topbar-search{display:none}
}

/* ══════════════════════════════════════════════
   RESPONSIVE — tablet 769–1024
══════════════════════════════════════════════ */
@media(min-width:769px) and (max-width:1024px){
  :root{--sidebar-w:200px}
  .name-text{max-width:170px}
  .bc a{max-width:100px}
  .topbar-search input{width:100px}
}

/* ══════════════════════════════════════════════
   RESPONSIVE — mobile ≤768
══════════════════════════════════════════════ */
@media(max-width:768px){
  :root{
    --sidebar-w:0px;
    --topbar-h: 56px;
    --bar-h:    32px;
  }
  .shell{
    grid-template:
      "topbar" var(--topbar-h)
      "main"   1fr
      "bar"    var(--bar-h)
      / 1fr;
  }
  /* topbar */
  .topbar{padding:0 12px;gap:8px}
  .brand{width:auto;flex:1;min-width:0}
  .brand-name{font-size:14px}
  .bc{display:none}
  .menu-btn{display:flex !important;min-width:40px;min-height:40px}
  .topbar-actions{gap:4px}
  .topbar-actions .divider-v{display:none}
  /* show only logout icon on mobile */
  .topbar-actions .btn-sm:not([style]){display:none}
  .topbar-actions form .btn-sm span{display:none}
  .topbar-actions .btn-icon{min-width:40px;min-height:40px}
  #usersBtn{display:none}

  /* sidebar drawer */
  .sidebar{
    position:fixed;
    top:var(--topbar-h);left:0;
    width:min(86vw,320px);
    height:calc(100dvh - var(--topbar-h));
    z-index:160;
    transform:translateX(-100%);
    transition:transform .3s var(--ease-spring);
    border-right:1px solid var(--border2);
    box-shadow:12px 0 48px rgba(0,0,0,.8);
    padding-bottom:env(safe-area-inset-bottom);
  }
  .sidebar.open{transform:translateX(0)}
  .sb-item{padding:12px 14px;min-height:44px}
  .sb-flink{padding:10px 12px;min-height:40px}

  /* content */
  .content{padding:12px}

  /* file table */
  .col-perms{display:none}
  .file-table{font-size:13.5px}
  .file-table td{padding:14px 12px}
  .file-table th{padding:11px 12px}
  .name-text{max-width:none;flex:1}
  .name-cell{gap:10px}

  /* action buttons: icon only */
  .btn-xs .btn-label{display:none}
  .btn-xs{padding:10px 11px;border-radius:9px;min-width:40px;min-height:40px}
  .btn-xs svg{width:16px;height:16px}
  .actions{gap:8px}

  /* status bar */
  .bar{padding:0 12px;gap:12px}
  .bar-stat{font-size:10.5px}
  .bar-right{gap:12px}

  /* bulk actions bar */
  .bulk-bar{width:calc(100% - 24px);left:12px;right:12px;transform:translate(0,120%);flex-wrap:wrap;padding:12px;gap:8px}
  .bulk-bar.show{transform:translate(0,0)}
  .bulk-bar .btn{min-height:40px}

  /* preview / users modal */
  .preview-box{width:96vw;max-height:88dvh}
}

/* ══════════════════════════════════════════════
   RESPONSIVE — small mobile ≤430
══════════════════════════════════════════════ */
@media(max-width:430px){
  :root{--topbar-h:52px}
  .brand-icon{width:28px;height:28px;border-radius:8px}
  .brand-icon img{width:20px;height:20px}
  .brand-name{font-size:13px}
  .topbar{padding:0 10px;gap:6px}

  .icon-box{width:34px;height:34px;border-radius:9px}
  .icon-box .type-icon{width:19px;height:19px}
  .ext-badge{display:none}

  /* hide size on smallest screens */
  .col-size,.col-size-td{display:none}

  .editor-header{padding:10px 12px}
  textarea.code{min-height:320px;font-size:12.5px;padding:14px 14px;line-height:1.75}
  .editor-footer{padding:9px 12px}

  /* status bar minimal */
  .bar-stat:nth-child(n+3):not(:last-child){display:none}
}
</style>
</head>
<body>
<div class="shell">

<!-- ══ TOPBAR ══ -->
<header class="topbar">
  <button class="btn btn-icon btn-ghost menu-btn" id="menuBtn" aria-label="Toggle menu">
    <svg viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>

  <a href="?dir=<?=urlencode(__DIR__)?>" class="brand">
    <div class="brand-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.18)"/></svg>
    </div>
    <span class="brand-name">File Manager</span>
  </a>

  <div class="divider-v"></div>

  <nav class="bc" aria-label="Breadcrumb">
    <?php $bcs=$fm->getBreadcrumbs(); $last=count($bcs)-1; foreach($bcs as $i=>$b): ?>
      <div class="bc-crumb">
        <?php if($i>0):?><span class="bc-sep">/</span><?php endif;?>
        <a href="?dir=<?=urlencode($b['path'])?>" class="<?=$i===$last?'last':''?>"><?=htmlspecialchars(mb_strimwidth($b['label'],0,20,'…'))?></a>
      </div>
    <?php endforeach;?>
  </nav>

  <form method="get" class="topbar-search">
    <input type="hidden" name="dir" value="<?=htmlspecialchars($fm->getCurrentDir())?>">
    <svg viewBox="0 0 24 24" fill="none" stroke="#71717a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;flex-shrink:0"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input type="text" name="q" placeholder="Search this folder…" value="<?=htmlspecialchars(isset($_GET['q'])?$_GET['q']:'')?>">
  </form>

  <div class="topbar-actions">
    <?php $isFav = $fm->isFavorite($fm->getCurrentDir()); ?>
    <form method="post" style="display:contents">
      <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
      <input type="hidden" name="action" value="<?=$isFav?'remove_favorite':'add_favorite'?>">
      <input type="hidden" name="path" value="<?=htmlspecialchars($fm->getCurrentDir())?>">
      <button class="btn btn-icon <?=$isFav?'btn-star':'btn-ghost'?>" title="<?=$isFav?'Remove from favorites':'Add to favorites'?>">
        <svg viewBox="0 0 24 24" fill="<?=$isFav?'currentColor':'none'?>" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
      </button>
    </form>
    <a href="?dir=<?=urlencode(dirname($fm->getCurrentDir()))?>" class="btn btn-sm btn-ghost" title="Up one level">
      <svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>
      Up
    </a>
    <a href="?<?=http_build_query(array_merge($_GET,['_r'=>time()]))?>" class="btn btn-icon btn-ghost" title="Refresh">
      <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
    </a>
    <?php if(!empty($_SESSION['fm_admin'])): ?>
    <button type="button" class="btn btn-sm btn-ghost" id="usersBtn" title="Manage users">
      <svg viewBox="0 0 24 24"><circle cx="9" cy="7" r="4"/><path d="M2 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2"/><circle cx="19" cy="8" r="3"/></svg>
      Users
    </button>
    <?php endif; ?>
    <span style="font-size:12px;color:#71717a;padding:0 4px" title="Signed in as">
      <?=htmlspecialchars(isset($_SESSION['fm_user'])?$_SESSION['fm_user']:'')?><?=!empty($_SESSION['fm_readonly'])?' (read-only)':''?>
    </span>
    <div class="divider-v"></div>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
      <input type="hidden" name="action" value="logout">
      <button class="btn btn-sm btn-ghost" style="color:#fca5a5;border-color:rgba(239,68,68,.2)">
        <svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Sign out
      </button>
    </form>
  </div>
</header>

<!-- ══ OVERLAY ══ -->
<div class="overlay" id="overlay" aria-hidden="true"></div>

<!-- ══ SIDEBAR ══ -->
<aside class="sidebar" id="sidebar">
  <div class="sb-section">
    <div class="sb-nav">
      <a href="?dir=<?=urlencode($fm->getSystemRoot())?>" class="sb-item">
        <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        Root
      </a>
      <a href="?dir=<?=urlencode(__DIR__)?>" class="sb-item">
        <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        Home
      </a>
      <a href="?dir=<?=urlencode(dirname($fm->getCurrentDir()))?>" class="sb-item">
        <svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>
        Up one level
      </a>
    </div>
  </div>

  <div class="sb-div"></div>

  <div style="padding:0 10px 4px;flex-shrink:0">
    <div class="sb-label">Favorites</div>
  </div>
  <div class="sb-folders" style="flex-shrink:0">
    <div class="sb-folder-list">
      <?php $favs = $fm->getFavorites(); foreach($favs as $fp): ?>
      <div class="sb-fav-row">
        <a href="?dir=<?=urlencode($fp)?>" class="sb-flink" style="flex:1">
          <svg viewBox="0 0 24 24" fill="#f59e0b" stroke="#f59e0b" stroke-width="1.5" stroke-linejoin="round" style="width:15px;height:15px;flex-shrink:0"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          <span><?=htmlspecialchars(basename($fp))?></span>
        </a>
        <form method="post">
          <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
          <input type="hidden" name="action" value="remove_favorite">
          <input type="hidden" name="path" value="<?=htmlspecialchars($fp)?>">
          <button class="sb-fav-remove" title="Remove">
            <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </form>
      </div>
      <?php endforeach; ?>
      <?php if(empty($favs)): ?>
      <div class="sb-empty">No favorites yet — star a folder</div>
      <?php endif; ?>
    </div>
  </div>

  <div class="sb-div"></div>

  <div style="padding:0 10px 4px;flex-shrink:0">
    <div class="sb-label">Folders</div>
  </div>
  <div class="sb-folders">
    <div class="sb-folder-list">
      <?php foreach($list['folders'] as $f): ?>
      <a href="?dir=<?=urlencode($fm->getCurrentDir().'/'.$f)?>" class="sb-flink">
        <svg viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px;flex-shrink:0"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.18)"/></svg>
        <span><?=htmlspecialchars($f)?></span>
      </a>
      <?php endforeach; ?>
      <?php if(empty($list['folders'])): ?>
      <div class="sb-empty">No folders here</div>
      <?php endif; ?>
    </div>
  </div>

  <div class="sb-div"></div>
  <div class="sb-footer">
    <div class="disk-widget">
      <div class="disk-label"><span>Disk usage</span><span><?=fmtSize($diskUsed)?> / <?=fmtSize($diskTotal)?></span></div>
      <div class="disk-track"><div class="disk-fill <?=$diskPct>=90?'crit':($diskPct>=75?'warn':'')?>" style="width:<?=$diskPct?>%"></div></div>
    </div>
    <?php if(!$fm->isReadonly()): ?>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
      <input type="hidden" name="action" value="bypass_permissions">
      <button type="button"
        onclick="if(confirm('Change permissions for all items in this directory?')){this.closest('form').submit()}"
        class="sb-item danger">
        <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Bypass Permissions
      </button>
    </form>
    <?php endif; ?>
  </div>
</aside>

<!-- ══ MAIN ══ -->
<main class="main">

  <?php if(!$editMode): ?>
  <!-- Toolbar -->
  <div class="toolbar">
    <!-- Row 1: Upload + Create Folder -->
    <?php if(!$fm->isReadonly()): ?>
    <div class="toolbar-row">
      <form method="post" enctype="multipart/form-data" id="uploadForm">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="upload">
        <input type="file" name="file[]" id="upFile" multiple onchange="this.form.submit()">
        <label for="upFile" class="upload-label">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:15px;height:15px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          Upload
        </label>
      </form>
      <form method="post" style="display:contents">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="create_folder">
        <input type="text" name="folder_name" class="input" placeholder="New folder name…" required>
        <button class="btn btn-sm btn-green" style="flex-shrink:0">
          <svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
          <span class="btn-label">Create</span>
        </button>
      </form>
    </div>
    <?php endif; ?>
    <!-- Row 2: Jump to path -->
    <div class="toolbar-row">
      <form method="post" style="display:contents">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="go_to_path">
        <input type="text" name="path" class="input" placeholder="Jump to path…" required>
        <button class="btn btn-sm btn-ghost" style="flex-shrink:0">
          <svg viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
          Go
        </button>
      </form>
    </div>
  </div>
  <?php endif; ?>

  <div class="content" id="dropzone">

    <!-- Alerts -->
    <?php if(!empty($fm->getMessages())): ?>
    <div class="alerts">
      <?php foreach($fm->getMessages() as $msg):
        $svgMap=[
          'success'=>'<polyline points="20 6 9 17 4 12"/>',
          'danger' =>'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
          'warning'=>'<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'];
        $ico=isset($svgMap[$msg['type']])?$svgMap[$msg['type']]:'';
      ?>
      <div class="alert <?=htmlspecialchars($msg['type'])?>" role="alert">
        <svg viewBox="0 0 24 24"><?=$ico?></svg>
        <?=htmlspecialchars($msg['text'])?>
        <button class="alert-close" aria-label="Dismiss">
          <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <?php if($editMode): ?>
    <!-- EDITOR -->
    <div class="editor-card">
      <div class="editor-header">
        <div class="editor-filename">
          <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          <?=htmlspecialchars($editFile)?>
        </div>
        <span class="editor-meta"><?=number_format(strlen($editContent))?> bytes · <?=substr_count($editContent,"\n")+1?> lines</span>
        <a href="?dir=<?=urlencode(isset($_GET['dir'])?$_GET['dir']:'')?>" class="btn btn-xs btn-ghost" style="margin-left:8px">
          <svg viewBox="0 0 24 24"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>
          Back
        </a>
      </div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="save_edit">
        <input type="hidden" name="filename" value="<?=htmlspecialchars($editFile)?>">
        <textarea name="content" class="code" spellcheck="false"><?=htmlspecialchars($editContent)?></textarea>
        <div class="editor-footer">
          <div class="editor-hint"><kbd>Tab</kbd> to indent &nbsp;&middot;&nbsp; <kbd>Ctrl</kbd>+<kbd>S</kbd> to save</div>
          <div style="display:flex;gap:7px">
            <a href="?dir=<?=urlencode(isset($_GET['dir'])?$_GET['dir']:'')?>" class="btn btn-sm btn-ghost">Cancel</a>
            <button class="btn btn-sm btn-primary">
              <svg viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
              Save
            </button>
          </div>
        </div>
      </form>
    </div>

    <?php else: ?>
    <!-- FILE TABLE -->
    <div class="card">
      <div class="table-wrap">
        <table class="file-table">
          <thead>
            <tr>
              <th class="col-check"><input type="checkbox" class="row-check" id="checkAll"></th>
              <th style="width:99%">Name</th>
              <th class="col-perms">Permissions</th>
              <th class="col-size">Size</th>
              <th style="text-align:right;padding-right:16px">Actions</th>
            </tr>
          </thead>
          <tbody>

          <?php foreach($list['folders'] as $f):
            $perms = substr(sprintf('%o', fileperms($fm->getCurrentDir().'/'.$f)), -4);
          ?>
          <tr data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
            <td class="col-check"><input type="checkbox" class="row-check item-check" value="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"></td>
            <td>
              <div class="name-cell" onclick="location.href='?dir=<?=urlencode($fm->getCurrentDir().'/'.$f)?>'">
                <div class="icon-box" style="background:rgba(245,158,11,.1)">
                  <?= svgFolder() ?>
                </div>
                <div class="name-main">
                  <span class="name-text"><?=htmlspecialchars($f)?></span>
                  <span class="ext-badge">DIR</span>
                </div>
              </div>
            </td>
            <td class="col-perms"><span class="mono-text"><?=htmlspecialchars($perms)?></span></td>
            <td class="col-size col-size-td"><span class="size-text" style="color:var(--t3)">—</span></td>
            <td>
              <div class="actions">
                <button data-action="ren" data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"
                  class="btn btn-xs btn-amber"
                  aria-label="Rename <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                  <span class="btn-label">Rename</span>
                </button>
                <button data-action="del" data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"
                  class="btn btn-xs btn-red"
                  aria-label="Delete <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/></svg>
                  <span class="btn-label">Delete</span>
                </button>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>

          <?php foreach($list['files'] as $f):
            $size  = @filesize($fm->getCurrentDir().'/'.$f);
            $type  = $fm->getFileType($f);
            $color = $fm->getFileColor($type);
            $ext   = strtolower(pathinfo($f, PATHINFO_EXTENSION));
            $perms = substr(sprintf('%o', fileperms($fm->getCurrentDir().'/'.$f)), -4);
            $canPreview = $fm->isPreviewable($type);
            $rawUrl = '?raw='.urlencode($f).'&dir='.urlencode($fm->getCurrentDir());
          ?>
          <tr data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
            <td class="col-check"><input type="checkbox" class="row-check item-check" value="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"></td>
            <td>
              <div class="name-cell" <?php if($canPreview):?>data-preview="<?=htmlspecialchars($rawUrl,ENT_QUOTES|ENT_HTML5)?>" data-type="<?=$type?>" data-fname="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"<?php endif;?>>
                <div class="icon-box" style="background:<?=$color?>18">
                  <?= svgFile($type) ?>
                </div>
                <div class="name-main">
                  <span class="name-text"><?=htmlspecialchars($f)?></span>
                  <?php if($ext):?><span class="ext-badge"><?=htmlspecialchars(strtoupper($ext))?></span><?php endif;?>
                </div>
              </div>
            </td>
            <td class="col-perms"><span class="mono-text"><?=htmlspecialchars($perms)?></span></td>
            <td class="col-size col-size-td"><span class="size-text"><?=fmtSize($size)?></span></td>
            <td>
              <div class="actions">
                <a href="<?=$rawUrl?>&dl=1" class="btn btn-xs btn-ghost" aria-label="Download <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                  <span class="btn-label">Download</span>
                </a>
                <?php if($type==='archive' && $ext==='zip'): ?>
                <button data-action="unzip" data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"
                  class="btn btn-xs btn-blue" aria-label="Extract <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
                  <span class="btn-label">Extract</span>
                </button>
                <?php endif; ?>
                <a href="?edit=<?=urlencode($f)?>&dir=<?=urlencode(isset($_GET['dir'])?$_GET['dir']:'')?>"
                   class="btn btn-xs btn-blue"
                   aria-label="Edit <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                  <span class="btn-label">Edit</span>
                </a>
                <button data-action="ren" data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"
                  class="btn btn-xs btn-amber"
                  aria-label="Rename <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><polyline points="5 12 12 5 19 12"/><line x1="12" y1="5" x2="12" y2="19"/></svg>
                  <span class="btn-label">Rename</span>
                </button>
                <button data-action="del" data-name="<?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>"
                  class="btn btn-xs btn-red"
                  aria-label="Delete <?=htmlspecialchars($f,ENT_QUOTES|ENT_HTML5)?>">
                  <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>
                  <span class="btn-label">Delete</span>
                </button>
              </div>
            </td>
          </tr>
          <?php endforeach; ?>

          <?php if(empty($list['folders']) && empty($list['files'])): ?>
          <tr><td colspan="5">
            <div class="empty">
              <svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
              <p><?=isset($_GET['q']) && $_GET['q']!==''?'No items match your search':'This folder is empty'?></p>
            </div>
          </td></tr>
          <?php endif; ?>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Floating bulk action bar -->
    <div class="bulk-bar" id="bulkBar">
      <span class="bulk-count" id="bulkCount">0 selected</span>
      <button type="button" class="btn btn-xs btn-ghost" id="bulkZip">
        <svg viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
        Zip
      </button>
      <button type="button" class="btn btn-xs btn-blue" id="bulkCopy">
        <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        Copy
      </button>
      <button type="button" class="btn btn-xs btn-amber" id="bulkMove">
        <svg viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8"/><line x1="21" y1="3" x2="14" y2="10"/><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/></svg>
        Move
      </button>
      <button type="button" class="btn btn-xs btn-red" id="bulkDelete">
        <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
        Delete
      </button>
    </div>

    <?php endif; ?>

  </div><!-- .content -->
</main>

<!-- ══ STATUS BAR ══ -->
<footer class="bar">
  <div class="bar-stat">
    <svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
    <strong><?=$totalFolders?></strong> folders
  </div>
  <div class="bar-stat">
    <svg viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
    <strong><?=$totalFiles?></strong> files
  </div>
  <?php if($totalSize > 0): ?>
  <div class="bar-stat">
    <svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
    <strong><?=fmtSize($totalSize)?></strong>
  </div>
  <?php endif; ?>
  <div class="bar-stat" title="Disk free">
    <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
    <strong><?=fmtSize($diskFree)?></strong> free
  </div>
  <div class="bar-right">
    <div class="bar-stat">
      <svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
      PHP <strong><?=PHP_VERSION?></strong>
    </div>
    <div class="bar-stat">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
      <strong><?=date('H:i')?></strong>
    </div>
  </div>
</footer>

</div><!-- .shell -->

<!-- Hidden action form -->
<form id="af" method="post" style="display:none">
  <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
  <input type="hidden" name="action"    id="af_action">
  <input type="hidden" name="item_name" id="af_item">
  <input type="hidden" name="old_name"  id="af_old">
  <input type="hidden" name="new_name"  id="af_new">
  <input type="hidden" name="items"     id="af_items">
  <input type="hidden" name="target"    id="af_target">
</form>

<!-- ══ PREVIEW MODAL ══ -->
<div class="preview-overlay" id="previewOverlay">
  <div class="preview-box">
    <div class="preview-head">
      <span id="previewName"></span>
      <button type="button" class="btn btn-icon btn-ghost" id="previewClose">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="preview-body" id="previewBody"></div>
  </div>
</div>

<?php if(!empty($_SESSION['fm_admin'])): ?>
<!-- ══ USERS MODAL ══ -->
<div class="preview-overlay" id="usersOverlay">
  <div class="preview-box" style="max-width:520px;width:94%">
    <div class="preview-head">
      <span>Manage Users</span>
      <button type="button" class="btn btn-icon btn-ghost" id="usersClose">
        <svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
      </button>
    </div>
    <div class="preview-body" style="padding:18px;overflow:auto">
      <div style="margin-bottom:18px">
        <?php foreach(fm_load_users($usersFile) as $u): ?>
        <div style="display:flex;align-items:center;justify-content:space-between;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.06)">
          <div style="font-size:13px;color:#e4e4e7">
            <strong><?=htmlspecialchars($u['user'])?></strong>
            <?php if(!empty($u['admin'])):?><span style="color:#818cf8;font-size:11px"> · admin</span><?php endif;?>
            <?php if(!empty($u['readonly'])):?><span style="color:#f59e0b;font-size:11px"> · read-only</span><?php endif;?>
            <div style="color:#71717a;font-size:11px;margin-top:2px"><?=htmlspecialchars($u['root']?:'Full access')?></div>
          </div>
          <?php if($u['user']!=='admin' && $u['user']!==$_SESSION['fm_user']): ?>
          <form method="post" onsubmit="return confirm('Remove this user?')">
            <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
            <input type="hidden" name="action" value="remove_user">
            <input type="hidden" name="target_user" value="<?=htmlspecialchars($u['user'])?>">
            <button class="btn btn-icon btn-ghost" title="Remove" style="color:#fca5a5">
              <svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            </button>
          </form>
          <?php endif; ?>
        </div>
        <?php endforeach; ?>
      </div>
      <div style="font-size:12px;font-weight:600;color:#a1a1aa;text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px">Add new user</div>
      <form method="post" style="display:flex;flex-direction:column;gap:10px">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="add_user">
        <input type="text" name="new_user" placeholder="Username" required class="input-field">
        <input type="password" name="new_pass" placeholder="Password" required class="input-field">
        <input type="text" name="new_root" placeholder="Restrict to folder path (leave empty for full access)" class="input-field">
        <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#a1a1aa">
          <input type="checkbox" name="new_readonly" value="1"> Read-only access
        </label>
        <button type="submit" class="btn btn-primary" style="align-self:flex-start">Create user</button>
      </form>
    </div>
  </div>
</div>
<style>.input-field{width:100%;padding:10px 12px;background:rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.09);border-radius:10px;color:#f4f4f5;font-size:13px;outline:none;font-family:'Inter',sans-serif}.input-field:focus{border-color:rgba(99,102,241,.6)}</style>
<?php endif; ?>

<script>
const currentDir = <?=json_encode($fm->getCurrentDir())?>;

/* ─── iOS-style sidebar toggle ─── */
const menuBtn = document.getElementById('menuBtn');
const sidebar = document.getElementById('sidebar');
const overlay = document.getElementById('overlay');

function openSidebar() {
  sidebar.classList.add('open');
  overlay.style.display = 'block';
  requestAnimationFrame(() => overlay.classList.add('visible'));
  document.body.style.overflow = 'hidden';
}
function closeSidebar() {
  sidebar.classList.remove('open');
  overlay.classList.remove('visible');
  setTimeout(() => { overlay.style.display = 'none'; }, 300);
  document.body.style.overflow = '';
}

menuBtn?.addEventListener('click', () =>
  sidebar.classList.contains('open') ? closeSidebar() : openSidebar()
);
overlay.addEventListener('click', closeSidebar);
sidebar.querySelectorAll('.sb-item,.sb-flink').forEach(el =>
  el.addEventListener('click', () => { if (window.innerWidth <= 768) closeSidebar(); })
);

/* ─── File actions (XSS-safe via data-*) ─── */
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const name   = btn.dataset.name;
  const action = btn.dataset.action;

  if (action === 'del') {
    if (!confirm(`Permanently delete "${name}"?\n\nThis action cannot be undone.`)) return;
    document.getElementById('af_action').value = 'delete';
    document.getElementById('af_item').value   = name;
    document.getElementById('af').submit();
  } else if (action === 'ren') {
    const nw = prompt(`Rename "${name}" to:`, name);
    if (nw && nw.trim() && nw.trim() !== name) {
      document.getElementById('af_action').value = 'rename';
      document.getElementById('af_old').value    = name;
      document.getElementById('af_new').value    = nw.trim();
      document.getElementById('af').submit();
    }
  } else if (action === 'unzip') {
    if (!confirm(`Extract "${name}" into a new folder here?`)) return;
    document.getElementById('af_action').value = 'zip_extract';
    document.getElementById('af_item').value   = name;
    document.getElementById('af').submit();
  }
});

/* ─── Editor keyboard shortcuts ─── */
const ta = document.querySelector('textarea.code');
if (ta) {
  ta.addEventListener('keydown', e => {
    if (e.key === 'Tab') {
      e.preventDefault();
      const s = ta.selectionStart, en = ta.selectionEnd;
      ta.value = ta.value.slice(0, s) + '    ' + ta.value.slice(en);
      ta.selectionStart = ta.selectionEnd = s + 4;
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
      e.preventDefault();
      ta.closest('form').submit();
    }
  });
}

/* ─── Alert dismiss ─── */
document.querySelectorAll('.alert-close').forEach(btn => {
  btn.addEventListener('click', () => {
    const alert = btn.closest('.alert');
    alert.style.transition = 'opacity .25s, transform .25s cubic-bezier(.34,1.56,.64,1)';
    alert.style.opacity = '0';
    alert.style.transform = 'translateY(-8px) scale(.97)';
    setTimeout(() => alert.remove(), 260);
  });
});

/* ─── Button tap ripple (iOS feel) ─── */
document.querySelectorAll('.btn,.sb-item,.sb-flink').forEach(el => {
  el.addEventListener('pointerdown', function(e) {
    const r = document.createElement('span');
    r.style.cssText = `
      position:absolute;border-radius:50%;
      width:6px;height:6px;
      background:rgba(255,255,255,.25);
      transform:scale(0);
      animation:ripple .5s cubic-bezier(.25,.46,.45,.94) forwards;
      pointer-events:none;
      left:${e.offsetX - 3}px;top:${e.offsetY - 3}px;
    `;
    const cur = getComputedStyle(this).position;
    if (cur === 'static') this.style.position = 'relative';
    this.style.overflow = 'hidden';
    this.appendChild(r);
    setTimeout(() => r.remove(), 520);
  });
});

const rippleStyle = document.createElement('style');
rippleStyle.textContent = '@keyframes ripple{to{transform:scale(28);opacity:0}}';
document.head.appendChild(rippleStyle);

/* ══════════════════════════════════════════════
   MULTI-SELECT + BULK ACTIONS
══════════════════════════════════════════════ */
const checkAll = document.getElementById('checkAll');
const bulkBar = document.getElementById('bulkBar');
const bulkCount = document.getElementById('bulkCount');

function getChecks() { return Array.from(document.querySelectorAll('.item-check')); }
function selectedNames() { return getChecks().filter(c => c.checked).map(c => c.value); }
function refreshBulkBar() {
  const sel = selectedNames();
  document.querySelectorAll('.file-table tbody tr').forEach(tr => {
    const cb = tr.querySelector('.item-check');
    tr.classList.toggle('selected', !!(cb && cb.checked));
  });
  if (sel.length > 0) {
    bulkBar.classList.add('show');
    bulkCount.textContent = sel.length + ' selected';
  } else {
    bulkBar.classList.remove('show');
  }
}
checkAll?.addEventListener('change', () => {
  getChecks().forEach(c => c.checked = checkAll.checked);
  refreshBulkBar();
});
document.addEventListener('change', e => {
  if (e.target.classList.contains('item-check')) refreshBulkBar();
});

document.getElementById('bulkDelete')?.addEventListener('click', () => {
  const sel = selectedNames();
  if (!sel.length) return;
  if (!confirm(`Permanently delete ${sel.length} item(s)?\n\nThis action cannot be undone.`)) return;
  document.getElementById('af_action').value = 'bulk_delete';
  document.getElementById('af_items').value = JSON.stringify(sel);
  document.getElementById('af').submit();
});
document.getElementById('bulkZip')?.addEventListener('click', () => {
  const sel = selectedNames();
  if (!sel.length) return;
  document.getElementById('af_action').value = 'zip_create';
  document.getElementById('af_items').value = JSON.stringify(sel);
  document.getElementById('af').submit();
});
document.getElementById('bulkCopy')?.addEventListener('click', () => {
  const sel = selectedNames();
  if (!sel.length) return;
  const target = prompt('Copy selected item(s) to full folder path:', currentDir);
  if (!target) return;
  document.getElementById('af_action').value = 'bulk_copy';
  document.getElementById('af_items').value = JSON.stringify(sel);
  document.getElementById('af_target').value = target.trim();
  document.getElementById('af').submit();
});
document.getElementById('bulkMove')?.addEventListener('click', () => {
  const sel = selectedNames();
  if (!sel.length) return;
  const target = prompt('Move selected item(s) to full folder path:', currentDir);
  if (!target) return;
  document.getElementById('af_action').value = 'bulk_move';
  document.getElementById('af_items').value = JSON.stringify(sel);
  document.getElementById('af_target').value = target.trim();
  document.getElementById('af').submit();
});

/* ══════════════════════════════════════════════
   FILE PREVIEW
══════════════════════════════════════════════ */
const previewOverlay = document.getElementById('previewOverlay');
const previewBody = document.getElementById('previewBody');
const previewName = document.getElementById('previewName');

document.addEventListener('click', e => {
  const cell = e.target.closest('.name-cell[data-preview]');
  if (!cell) return;
  const url = cell.dataset.preview;
  const type = cell.dataset.type;
  const fname = cell.dataset.fname;
  openPreview(url, type, fname);
});

function openPreview(url, type, fname) {
  previewName.textContent = fname;
  previewBody.innerHTML = '';
  if (type === 'image') {
    const img = document.createElement('img');
    img.src = url;
    previewBody.appendChild(img);
  } else if (type === 'video') {
    const v = document.createElement('video');
    v.src = url; v.controls = true; v.autoplay = true;
    previewBody.appendChild(v);
  } else if (type === 'pdf') {
    const ifr = document.createElement('iframe');
    ifr.src = url;
    previewBody.appendChild(ifr);
  } else {
    const pre = document.createElement('pre');
    pre.textContent = 'Loading…';
    previewBody.appendChild(pre);
    fetch(url).then(r => r.text()).then(txt => {
      pre.textContent = txt.length > 200000 ? txt.slice(0, 200000) + '\n\n… (truncated)' : txt;
    }).catch(() => { pre.textContent = 'Could not load file.'; });
  }
  previewOverlay.classList.add('open');
}
function closePreview() {
  previewOverlay.classList.remove('open');
  previewBody.innerHTML = '';
}
document.getElementById('previewClose')?.addEventListener('click', closePreview);
previewOverlay.addEventListener('click', e => { if (e.target === previewOverlay) closePreview(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closePreview(); if (e.key === 'Escape') document.getElementById('usersOverlay')?.classList.remove('open'); });

const usersOverlay = document.getElementById('usersOverlay');
document.getElementById('usersBtn')?.addEventListener('click', () => usersOverlay?.classList.add('open'));
document.getElementById('usersClose')?.addEventListener('click', () => usersOverlay?.classList.remove('open'));
usersOverlay?.addEventListener('click', e => { if (e.target === usersOverlay) usersOverlay.classList.remove('open'); });

/* ══════════════════════════════════════════════
   DRAG & DROP UPLOAD
══════════════════════════════════════════════ */
const dropzone = document.getElementById('dropzone');
if (dropzone) {
  ['dragenter', 'dragover'].forEach(evt => {
    dropzone.addEventListener(evt, e => {
      e.preventDefault(); e.stopPropagation();
      dropzone.classList.add('drag-over');
    });
  });
  ['dragleave', 'drop'].forEach(evt => {
    dropzone.addEventListener(evt, e => {
      e.preventDefault(); e.stopPropagation();
      if (evt === 'dragleave' && e.target !== dropzone) return;
      dropzone.classList.remove('drag-over');
    });
  });
  dropzone.addEventListener('drop', e => {
    const files = e.dataTransfer.files;
    if (!files || !files.length) return;
    const fd = new FormData();
    fd.append('csrf_token', <?=json_encode($_SESSION['csrf_token'])?>);
    fd.append('action', 'upload');
    for (const f of files) fd.append('file[]', f);
    fetch(window.location.href, { method: 'POST', body: fd }).then(() => window.location.reload());
  });
}
</script>
</body>
</html>
