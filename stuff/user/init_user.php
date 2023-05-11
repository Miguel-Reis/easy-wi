<?php

 

if (!isset($user_id)) {
    header('Location: login.php');
    die;
}

$userInclude = true;

$pa = User_Permissions($user_id);

$query = $sql->prepare("SELECT ((UNIX_TIMESTAMP(`lastcheck`)-UNIX_TIMESTAMP(`oldcheck`))/60)-((UNIX_TIMESTAMP()-UNIX_TIMESTAMP(`lastcheck`))/60) AS `nextRunInMinutes` FROM `lendsettings` LIMIT 1");
$query->execute();
$statusTime = ceil($query->fetchColumn());
$gsprache->help_home = str_replace('%n%', $statusTime, $gsprache->help_home);
$gsprache->help_sidebar = str_replace('%n%', $statusTime, $gsprache->help_sidebar);

# https://github.com/easy-wi/developer/issues/2
if (isset($_SESSION['sID'])) {

    $substituteAccess = array('wv' => array(), 'gs' => array(), 'db' => array(), 'vo' => array(), 'vd' => array(), 'vs' => array(), 'ro' => array());

    $query = $sql->prepare("SELECT `oID`,`oType` FROM `userdata_substitutes_servers` WHERE `sID`=?");
    $query->execute(array($_SESSION['sID']));
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $substituteAccess[$row['oType']][] = $row['oID'];
    }

    $query = $sql->prepare("SELECT `loginName`, `name`,`vname`,`lastlogin`,`show_help_text` FROM `userdata_substitutes` WHERE `sID`=? LIMIT 1");
    $query->execute(array($_SESSION['sID']));
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $great_name = $row['name'];
        $great_vname = $row['vname'];
        $lastlogin = $row['lastlogin'];
        $userWantsHelpText = $row['show_help_text'];

        $great_user = ($row['name'] != '' and $row['vname'] != '') ? trim ($row['vname'] . ' ' . $row['name']) : $row['loginName'];
    }

    $gscount = count($substituteAccess['gs']);
    $vhostcount = count($substituteAccess['wv']);
    $voicecount = count($substituteAccess['vo']);
    $tsdnscount = count($substituteAccess['vd']);
    $dbcount = count($substituteAccess['db']);
    $rootcount = count($substituteAccess['ro']);
    $virtualcount = count($substituteAccess['vs']);

} else {

    $query = $sql->prepare("SELECT `cname`,`name`,`vname`,`lastlogin`,`show_help_text` FROM `userdata` WHERE `id`=? LIMIT 1");
    $query->execute(array($user_id));
    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
        $great_name = $row['name'];
        $great_vname = $row['vname'];
        $lastlogin = $row['lastlogin'];
        $userWantsHelpText = $row['show_help_text'];

        $great_user = ($row['name'] != '' or $row['vname'] != '') ? trim ($row['vname'] . ' ' . $row['name']) : $row['cname'];
    }

    $query = $sql->prepare("SELECT COUNT(g.`id`) AS `amount` FROM `gsswitch` g INNER JOIN `rserverdata` r ON g.`rootID`=r.`id` WHERE r.`active`='Y' AND g.`active`='Y' AND g.`userid`=? LIMIT 1");
    $query->execute(array($user_id));
    $gscount = $query->fetchColumn();

    $query = $sql->prepare("SELECT COUNT(`webVhostID`) AS `amount` FROM `webVhost` WHERE `active`='Y' AND `userID`=? LIMIT 1");
    $query->execute(array($user_id));
    $vhostcount = $query->fetchColumn();
    
    if (!isset($reseller_id)) {
        $reseller_id = 0;
    }

	if (isset($admin_id) and $admin_id==$reseller_id) {
		$resellerid = 0;
	} else if (isset($reseller_id)) {
		$resellerid = $reseller_id;
	} else {
		$resellerid = 0;
	}
}

if (isset($lastlogin) and $lastlogin != null and $lastlogin != '0000-00-00 00:00:00') {
    $great_last = ($user_language == 'de') ? date('d.m.Y H:m:s', strtotime($lastlogin)) : $lastlogin;
} else {
    $great_last = ($user_language == 'de') ? 'Niemals' : 'Never';
}

# https://github.com/easy-wi/developer/issues/61
# basic modules array. available at any time to anyone
$what_to_be_included_array = array('lo' => 'userpanel_logdata.php', 'ti' => 'userpanel_tickets.php');


$easywiModules = array('ws' => true, 'gs' => true, 'ip' => true, 'my' => true, 'ro' => true, 'ti' => true, 'le' => true, 'vo' => true);
$customModules = array('ws' => array(), 'gs' => array(), 'mo' => array(), 'my' => array(), 'ro' => array(), 'ti' => array(), 'us' => array(), 'vo' => array());
$customFiles = array();

$query = $sql->prepare("SELECT * FROM `modules` WHERE `type` IN ('U','C')");
$query2 = $sql->prepare("SELECT `text` FROM `translations` WHERE `type`='mo' AND `transID`=? AND `lang`=? LIMIT 1");
$query->execute();
while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

    if ($row['active'] == 'Y' and $row['type'] == 'U' and is_file(EASYWIDIR . '/stuff/custom_modules/' . $row['file'])) {
        $query2->execute(array($row['id'], $user_language));
        $name = $query2->fetchColumn();

        if (strlen($name) == 0) {
            $query2->execute(array($row['id'], $rSA['language']));
            $name = $query2->fetchColumn();
        }

        if (strlen($name) == 0) {
            $name = $row['file'];
        }

        $customModules[$row['sub']][$row['get']] = $name;
        $customFiles[$row['get']] = $row['file'];

    } else if ($row['type'] == 'C' and $row['active'] == 'N') {
        $easywiModules[$row['get']] = false;
    }
}

# modules meant only for user only
if (isset($_SESSION['sID'])) {
    $what_to_be_included_array['se'] = 'userpanel_substitutes_own.php';
} else {
    $what_to_be_included_array['su'] = 'userpanel_substitutes.php';
    $what_to_be_included_array['se'] = 'global_userdata.php';
}

# modules based on count. No servers, no modules
if ($gscount > 0 and $easywiModules['gs'] === true) {
    $what_to_be_included_array['gs'] = 'userpanel_gserver.php';
    $what_to_be_included_array['gt'] = 'global_gserver_file_templates.php';
    $what_to_be_included_array['fd'] = 'userpanel_fdl.php';
    $what_to_be_included_array['ao'] = 'userpanel_ao.php';
    $what_to_be_included_array['ca'] = 'userpanel_restartcalendar.php';
    $what_to_be_included_array['pr'] = 'userpanel_protectionmode.php';
    $what_to_be_included_array['bu'] = 'userpanel_backup.php';
    $what_to_be_included_array['ms'] = 'userpanel_migration.php';
    $what_to_be_included_array['ls'] = 'xtreamlist.php';
}

if ($vhostcount > 0 and $easywiModules['ws'] === true) {
    $what_to_be_included_array['wv'] = 'userpanel_web_vhost.php';
}

if ($easywiModules['ip'] === true) {
    $what_to_be_included_array['ip'] = 'imprint.php';
}
