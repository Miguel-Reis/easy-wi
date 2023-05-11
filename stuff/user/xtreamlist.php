<?php

 
if ((!isset($main) or $main != 1) or (!isset($user_id) or (isset($user_id) and !$pa['restart']))) {
    header('Location: userpanel.php');
    die('No Access');
}

include(EASYWIDIR . '/stuff/keyphrasefile.php');
include(EASYWIDIR . '/stuff/methods/class_ftp.php');
include(EASYWIDIR . '/stuff/methods/functions_gs.php');
include(EASYWIDIR . '/stuff/methods/class_app.php');

if (isset($resellerLockupID)) {
    $reseller_id = $resellerLockupID;
}

$sprache = getlanguagefile('gserver', $user_language, $reseller_id);
$imageSprache = getlanguagefile('images', $user_language, $reseller_id);
$loguserid = $user_id;
$logusername = getusername($user_id);
$logusertype = 'user';
$logreseller = 0;

if (isset($admin_id)) {
	$logsubuser = $admin_id;
} else if (isset($subuser_id)) {
	$logsubuser = $subuser_id;
} else {
	$logsubuser = 0;
}

	$table = array();
	
	// $xtreamid = $_REQUEST["id"];
	
	// if(!isset($xtreamid)){
		// echo '123123123';
	// }else{
		// $xtreamid1 = $xtreamid;
	// }
	
	
	/*$query = $sql->prepare("SELECT g.`serverip`,g.`port`,g.`id`,g.`stopped`,t.`liveConsole` FROM `gsswitch` AS g INNER JOIN `serverlist` AS s ON g.`serverid`=s.`id` INNER JOIN `servertypes` AS t ON s.`servertype`=t.`id` WHERE g.`id`=? AND g.`userid`=? AND g.`resellerid`=? LIMIT 1");
    $query->execute(array($id, $user_id, $resellerLockupID));
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $serverIp = $row['serverip'];
        $port = $row['port'];
        $liveConsole = $row['liveConsole'];
        $id = $row['id'];
        $stopped = $row['stopped'];
    }*/
	

    #$query = $sql->prepare("SELECT AES_DECRYPT(`ftppassword`,?) AS `cftppass`,g.*,s.`servertemplate`,s.`upload`,t.`id` AS `tid`,t.`ramLimited`,t.`shorten`,t.`protected` AS `tp`,u.`cname` FROM `gsswitch` g INNER JOIN `serverlist` s ON g.`serverid`=s.`id` INNER JOIN `servertypes` t ON s.`servertype`=t.`id` INNER JOIN `userdata` u ON g.`userid`=u.`id` WHERE g.`id`='$xtreamid' AND g.`userid`=? AND g.`resellerid`=?");
     $query = $sql->prepare("SELECT AES_DECRYPT(`ftppassword`,?) AS `cftppass`,g.*,s.`servertemplate`,s.`upload`,t.`id` AS `tid`,t.`ramLimited`,t.`shorten`,t.`protected` AS `tp`,u.`cname` FROM `gsswitch` g INNER JOIN `serverlist` s ON g.`serverid`=s.`id` INNER JOIN `servertypes` t ON s.`servertype`=t.`id` INNER JOIN `userdata` u ON g.`userid`=u.`id` WHERE g.`active`='Y' AND g.`userid`=? AND g.`resellerid`=? ORDER BY g.`serverip`,g.`port`");
    
	$query2 = $sql->prepare("SELECT `ftpport` FROM `rserverdata` WHERE `id`=? LIMIT 1");
    $query3 = $sql->prepare("SELECT * FROM `servertypes` WHERE `id`=? AND `ftpAccess`='N' LIMIT 1");
    $query->execute(array($aeskey, $user_id,$resellerLockupID));
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        if (!isset($_SESSION['sID']) or in_array($row['id'],$substituteAccess['gs'])) {
            $description = $row['description'];
            $rootid = $row['rootID'];
            $war = $row['war'];
            $brandname = $row['brandname'];
            $protected = $row['protected'];
            $tprotected = $row['tp'];
            $pallowed = $row['pallowed'];
            $cname = $row['cname'];
            $shorten = $row['shorten'];
            $gameserverid = $row['id'];
            $name = $row['queryName'];
            $ip = $row['serverip'];
            $port = $row['port'];
            $numplayers = $row['queryNumplayers'];
            $maxplayers = $row['queryMaxplayers'];
            $password = $row['queryPassword'];
            $stopped = $row['stopped'];
            $notified = $row['notified'];
            $cftppass = $row['cftppass'];
            $servertemplate = $row['servertemplate'];

            $address = $ip . ':' . $port;
            $map = (in_array($row['queryMap'], array(false, null, ''))) ? 'Unknown' : $row['queryMap'];
            $updatetime = ($user_language == 'de') ? (($row['queryUpdatetime'] != '') ? date('d.m.Y H:i:s', strtotime($row['queryUpdatetime'])) : $sprache->never) : $row['queryUpdatetime'];
            $upload = ($row['upload'] > 1 and $row['upload'] < 4) ? true : false;
            $currentTemplate = (($protected == 'N' or $tprotected == 'N') and $servertemplate > 1) ? $row['shorten'] . '-' . $servertemplate : $row['shorten'];
            $ce = explode(',', $row['cores']);
            $coreCount = count($ce);
            $cores = array();
			
            if ($row['taskset'] == 'Y' and $coreCount>0) {
                foreach ($ce as $uc) {
                    $cores[] = $uc;
                }
            }

            $cores = implode(', ', $cores);
            // if ($stopped == 'Y') {
                // $name = 'OFFLINE';
            // }

            $imgNameP = '';
            $imgAltP = '';
            $pro = '';
            $pserver = '/server/';

            if ($protected == 'N' and ($pallowed == 'Y' and $tprotected == 'Y')) {
                $imgNameP = '16_unprotected';
                $imgAltP = $sprache->off2;
                $pro = $sprache->off2;
            } else if ($protected == 'Y' and $tprotected == 'Y' and $pallowed == 'Y') {
                $imgNameP = '16_protected';
                $imgAltP = $sprache->on;
                $pserver = '/pserver/';
                $pro = $sprache->on;
            }

            if ($pa['ftpaccess'] or $pa['miniroot']) {

                if ($row['newlayout'] == 'Y') {
                    $cname = $cname . '-' . $row['id'];
                }

                $query2->execute(array($rootid));
                $ftpport = $query2->fetchColumn();
                $ftpdata = 'ftp://' . $cname . ':' . $cftppass . '@' . $ip . ':' . $ftpport . $pserver . $currentTemplate;
            } else {
                $cftppass = '';
                $ftpport = '';
                $ftpdata = '';
            }

            $nameremoved = '';
            $premoved = '';
            $imgName = '16_ok';
            $imgAlt = 'Online';

            if ($stopped == 'Y') {
                $numplayers = 0;
                $maxplayers = 0;
                $imgName = '16_bad';
                $imgAlt = 'Stopped';
            } else if ($name == 'OFFLINE' and $stopped == 'N') {
                $numplayers = 0;
                $maxplayers = 0;
                $imgName = '16_error';
                $imgAlt = 'Crashed';
            } else {
                if ($war == 'Y' and $password == 'N') {
                    $imgName = '16_error';
                    $imgAlt = 'No Password';
                    $premoved = $sprache->premoved;
                }
                if ($brandname == 'Y' and $rSA['brandname'] != null and $rSA['brandname'] != '' and strpos(strtolower($name), strtolower($rSA['brandname'])) === false) {
                    $imgName = '16_error';
                    $imgAlt = 'No Servertag';
                    $nameremoved = $sprache->nameremoved;
                }
            }

            $table[] = array(
                'id' => $gameserverid,
                'premoved' => $premoved,
                'nameremoved' => $nameremoved,
                'server' => $address,
                'name' => (strlen($description) == 0) ? $name : $description . ' ' . $name,
                'img' => $imgName,
                'alt' => $imgAlt,
                'imgp' => $imgNameP,
                'altp' => $imgAltP,
                'numplayers' => $numplayers,
                'maxplayers' => $maxplayers,
                'map' => $map,
                'cname' => $cname,
                'cftppass' => $cftppass,
                'ip' => $ip,
                'ftpport' => $ftpport,
                'port' => $port,
                'shorten' => $currentTemplate,
                'gameShorten' => $shorten,
                'ftpdata' => $ftpdata,
                'updatetime' => $updatetime,
                'stopped' => $stopped,
                'pro' => $pro,
                'upload' => $upload,
                'minram' => $row['minram'],
                'maxram' => $row['maxram'],
                'taskset' => $row['taskset'],
                'ramLimited' => $row['ramLimited'],
                'coreCount' => $coreCount,
                'cores' => $cores
                // 'ftpAllowed' => $ftpAllowed
            );
        }
    }

    $template_file = 'userlist.tpl';
 
 
