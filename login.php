<?php

/**
 * File: login.php.
 * Author: Ulrich Block
 * Contact: <ulrich.block@easy-wi.com>
 *
 * This file is part of Easy-WI.
 *
 * Easy-WI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Easy-WI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Easy-WI.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Diese Datei ist Teil von Easy-WI.
 *
 * Easy-WI ist Freie Software: Sie koennen es unter den Bedingungen
 * der GNU General Public License, wie von der Free Software Foundation,
 * Version 3 der Lizenz oder (nach Ihrer Wahl) jeder spaeteren
 * veroeffentlichten Version, weiterverbreiten und/oder modifizieren.
 *
 * Easy-WI wird in der Hoffnung, dass es nuetzlich sein wird, aber
 * OHNE JEDE GEWAEHELEISTUNG, bereitgestellt; sogar ohne die implizite
 * Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
 * Siehe die GNU General Public License fuer weitere Details.
 *
 * Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
 * Programm erhalten haben. Wenn nicht, siehe <http://www.gnu.org/licenses/>.
 */

$s = preg_split('/\//',$_SERVER['SCRIPT_NAME'],-1,PREG_SPLIT_NO_EMPTY);
$ewInstallPath = '';
if (count($s)>1) {
    unset($s[(count($s) - 1)]);
    $ewInstallPath = implode('/', $s) . '/';
}
define('EASYWIDIR', dirname(__FILE__));

if (is_dir(EASYWIDIR . '/install')) {
    die('Please remove the "install" folder');
}

include(EASYWIDIR . '/stuff/methods/vorlage.php');
include(EASYWIDIR . '/stuff/methods/class_validator.php');
include(EASYWIDIR . '/third_party/password_compat/password.php');
include(EASYWIDIR . '/stuff/methods/functions.php');
include(EASYWIDIR . '/stuff/methods/functions_social_auth.php');
include(EASYWIDIR . '/stuff/settings.php');
include(EASYWIDIR . '/stuff/keyphrasefile.php');

if ((!isset($ui->get['w']) and isset($ui->post['username'])) or (isset($ui->get['w']) and $ui->get['w'] != 'pr')) {
    $logininclude = true;
}

if ($ui->ismail('email', 'post')) {
    $fullday = date('Y-m-d H:i:s', strtotime('+1 day'));

    $query = $sql->prepare("SELECT `id` FROM `badips` WHERE `badip`=? LIMIT 1");
    $query->execute(array($loguserip));
    $rowcount = $query->rowCount();

    if ($rowcount == 0) {
        $query = $sql->prepare("INSERT INTO `badips` (`bantime`, `failcount`, `reason`, `badip`) VALUES (?, '1', 'bot', ?)");
    } else {
        $query = $sql->prepare("UPDATE `badips` SET `bantime`=?, `failcount`=failcount+1, `reason`='bot' WHERE `badip`=? LIMIT 1");
    }

    $query->execute(array($fullday, $loguserip));
}
$default_language = $rSA['language'];
$sprache = getlanguagefile('login', $default_language, 0);
$vosprache = getlanguagefile('voice', $default_language, 0);

if ($ui->st('w', 'get') == 'lo') {
    if (isset($ui->server['HTTP_REFERER'])) {
        $refstring = explode('/', substr(str_replace(array('http://' . $ui->domain('HTTP_HOST', 'server'), 'https://' . $ui->domain('HTTP_HOST', 'server'), '//'), array('', '', '/'), strtolower($ui->server['HTTP_REFERER'])), strlen($ewInstallPath)));
        $referrer = (isset($refstring[1])) ? explode('?', $refstring[1]) : '';
    } else {
        $referrer[0] = 'login.php';
    }

    if (isset($_SESSION['resellerid'], $_SESSION['adminid'], $_SESSION['oldid'], $_SESSION['oldresellerid']) && !isset($_SESSION['userid']) && $_SESSION['resellerid'] != 0 && $referrer[0] == 'admin.php') {
        $_SESSION['adminid'] = $_SESSION['oldid'];
        $_SESSION['resellerid'] = $_SESSION['oldresellerid'];

        if ($_SESSION['oldresellerid'] != 0 && $_SESSION['oldid'] == $_SESSION['oldresellerid']) {
            $_SESSION['oldresellerid'] = 0;
            $_SESSION['oldid'] = $_SESSION['oldadminid'];
            unset($_SESSION['oldadminid']);
        }

        redirect('admin.php');
    } elseif (isset($_SESSION['adminid'], $_SESSION['userid']) && $referrer[0] == 'userpanel.php') {
        unset($_SESSION['userid']);
        redirect('admin.php');
    } else {
        $target = ($pageurl ?? '') . '/' . $ewInstallPath . (empty($target) ? 'login.php' : '/login.php');
        session_unset();
        session_destroy();
        redirect($target);
    }
} elseif ($ui->st('w', 'get') == 'ba') {
    $serviceProviders = getServiceProviders();
    $sus = $sprache->banned;
    $include = 'login.tpl';
} elseif ($ui->st('w', 'get') == 'up') {
    $serviceProviders = getServiceProviders();
    $sus = ($ui->escaped('error', 'get')) ? 'External Auth failed: ' . htmlentities(base64_decode(urldecode($ui->escaped('error', 'get')))) : $sprache->bad_up;
    $include = 'login.tpl';
} else if ($ui->st('w', 'get') == 'pr') {

    $token = '';

    if (($ui->ismail('um', 'post') || $ui->username('um', 50, 'post')) && !$ui->w('gamestring', 32, 'get')) {
        # https://github.com/easy-wi/developer/issues/43
        $send = true;
        $text = $sprache->send;

        $query = $sql->prepare("SELECT `id`,`cname`,`logintime`,`lastlogin` FROM `userdata` WHERE `cname`=? OR `mail`=? ORDER BY `lastlogin` DESC LIMIT 1");
        $query->execute(array($ui->username('um', 50, 'post'), $ui->ismail('um', 'post')));

        while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
            $userid = $row['id'];
            $md5 = md5($userid . $row['logintime'] . $row['cname'] . $row['lastlogin'] . mt_rand());

            $folders = explode('/', $ui->server['SCRIPT_NAME']);
            $amount = count($folders) - 1;
            $i = 0;
            $path = '';

            while ($i < $amount) {
                $path .= $folders[$i] . '/';
                $i++;
            }

            $webhostdomain = (isset($ui->server['HTTPS'])) ? 'https://' . $ui->server['HTTP_HOST'] . $path : 'http://' . $ui->server['HTTP_HOST'] . $path;
            $link = $webhostdomain . 'login.php?w=pr&amp;gamestring=' . $md5;
            $htmllink = '<a href="' . $link . '">' . $link . '</a>';

            $query2 = $sql->prepare("UPDATE `userdata` SET `token`=? WHERE `id`=? LIMIT 1");
            $query2->execute(array($md5, $userid));

            sendmail('emailpwrecovery', $userid, $htmllink, '');
        }
    }

    } else if ($ui->password('password1', 255, 'post') && $ui->password('password2', 255, 'post') && $ui->w('token', 32, 'get')) {
        if ($ui->password('password1', 255, 'post') == $ui->password('password2', 255, 'post')) {
            $query = $sql->prepare("SELECT `id`,`cname` FROM `userdata` WHERE `token`=? LIMIT 1");
            $query->execute(array($ui->w('token', 32, 'get')));
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $text = $sprache->passwordreseted;
                $newHash = passwordCreate($row['cname'], $ui->password('password1', 255, 'post'));
    
                if (is_array($newHash)) {
                    $query2 = $sql->prepare("UPDATE `userdata` SET `token`='',`security`=?,`salt`=? WHERE `id`=? LIMIT 1");
                    $query2->execute(array($newHash['hash'], $newHash['salt'], $row['id']));
                } else {
                    $query2 = $sql->prepare("UPDATE `userdata` SET `token`='',`security`=? WHERE `id`=? LIMIT 1");
                    $query2->execute(array($newHash, $row['id']));
                }
            }

        } else if ($ui->password('password1', 255, 'post') != $ui->password('password2', 255, 'post')) {
            // https://github.com/easy-wi/developer/issues/43
            $token = '&amp;gamestring=' . $ui->w('token', 32, 'get');
            $text = $sprache->pwnomatch;
        } elseif ($ui->w('gamestring', 32, 'get')) {
        $token = '&amp;token=' . $ui->w('gamestring', 32, 'get');
        $recover = false;
        $randompass = passwordgenerate(10);
    
        $query = $sql->prepare("SELECT 1 FROM `userdata` WHERE `token`=? LIMIT 1");
        $query->execute(array($ui->w('gamestring', 32, 'get')));
    
        if ($query->rowCount() > 0) {
            $recover = true;
        }
    }

    $include = 'passwordrecovery.tpl';

} else {

    if (!isset($include) and !isset($passwordCorrect) and !$ui->username('username', 255, 'post') and !$ui->ismail('username', 255, 'post') and !$ui->password('password', 255, 'post') and !isset($_SESSION['sessionid'])) {

        $serviceProviders = getServiceProviders();

        $include = 'login.tpl';

    } else if (!isset($include) and (isset($passwordCorrect) or (($ui->username('username', 255, 'post') or $ui->ismail('username', 'post')) and $ui->password('password', 255, 'post') and !isset($_SESSION['sessionid'])))) {

        $password = $ui->password('password', 255, 'post');

        if (isset($ewCfg['captcha']) and $ewCfg['captcha'] == 1) {

            if (md5($ui->w('captcha', 4, 'post')) != $_SESSION['captcha']) {
                $halfhour = date('Y-m-d H:i:s', strtotime('+30 minutes'));

                $query = $sql->prepare("SELECT `id` FROM `badips` WHERE `badip`=? LIMIT 1");
                $query->execute(array($loguserip));
                $rowcount = $query->rowCount();

                $query=($rowcount==0) ? $sql->prepare("INSERT INTO `badips` (`bantime`,`failcount`,`reason`,`badip`) VALUES (?,'1','password',?)") : $sql->prepare("UPDATE `badips` SET `bantime`=?, `failcount`=`failcount`+1, `reason`='password' WHERE `badip`=? LIMIT 1");
                $query->execute(array($halfhour, $loguserip));

                redirect('login.php?w=ca&r=lo');
            }
        }

        $salt = '';

        $query = $sql->prepare("SELECT `id`,`accounttype`,`cname`,`active`,`security`,`resellerid`,`mail`,`salt`,`externalID` FROM `userdata` WHERE `cname`=? OR `mail`=? ORDER BY `lastlogin` DESC LIMIT 1");
        $query->execute(array($ui->username('username', 255, 'post'), $ui->ismail('username', 'post')));
        while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

            $username = $row['cname'];
            $id = $row['id'];
            $active = $row['active'];
            $mail = $row['mail'];
            $externalID = $row['externalID'];
            $resellerid = $row['resellerid'];
            $accounttype = $row['accounttype'];

            $passwordCorrect = passwordCheck($password, $row['security'], $row['cname'], $row['salt']);

            if ($passwordCorrect !== true and $passwordCorrect !== false) {
                if (is_array($passwordCorrect)) {
                    $query2 = $sql->prepare("UPDATE `userdata` SET `security`=?,`salt`=? WHERE `id`=? LIMIT 1");
                    $query2->execute(array($passwordCorrect['hash'], $passwordCorrect['salt'], $id));
                } else {
                    $query2 = $sql->prepare("UPDATE `userdata` SET `security`=? WHERE `id`=? LIMIT 1");
                    $query2->execute(array($passwordCorrect, $id));
                }
            }
        }

        # https://github.com/easy-wi/developer/issues/2
        if (!isset($active)) {
            $query = $sql->prepare("SELECT * FROM `userdata_substitutes` WHERE `loginName`=? LIMIT 1");
            $query->execute(array($ui->username('username', 255, 'post')));
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $mail = '';
                $externalID = 0;
                $sID = $row['sID'];
                $id = $row['userID'];
                $username = $row['loginName'];
                $active = $row['active'];
                $resellerid = $row['resellerID'];
        
                $accounttype = 'v';
        
                $passwordCorrect = passwordCheck($password, $row['passwordHashed'], $row['loginName'], $row['salt']);
        
                if ($passwordCorrect !== true && $passwordCorrect !== false) {
                    if (is_array($passwordCorrect)) {
                        $query = $sql->prepare("UPDATE `userdata_substitutes` SET `passwordHashed`=?,`salt`=? WHERE `sID`=? LIMIT 1");
                        $query->execute(array($passwordCorrect['hash'], $passwordCorrect['salt'], $sID));
                    } else {
                        $query = $sql->prepare("UPDATE `userdata_substitutes` SET `passwordHashed`=? WHERE `sID`=? LIMIT 1");
                        $query->execute(array($passwordCorrect, $sID));
                    }
                }
            }
        }        

        if (!isset($sID) && isset($active) && $active == 'Y' && isset($passwordCorrect) && $passwordCorrect === false) {
            $authLookupID = ($resellerid == $id) ? 0 : $resellerid;
        
            $query = $sql->prepare("SELECT `active`,`ssl`,`user`,`domain`,AES_DECRYPT(`pwd`,?) AS `decryptedPWD`,`file` FROM `api_external_auth` WHERE `resellerID`=? LIMIT 1");
            $query->execute(array($aeskey, $authLookupID));
        
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $activeAuth = $row['active'];
                $portAuth = ($row['ssl'] == 'Y') ? 443 : 80;
                $userAuth = urlencode($row['user']);
                $pwdAuth = urlencode($row['decryptedPWD']);
                $domainAuth = $row['domain'];
                $fileAuth = $row['file'];
        
                $xml = new DOMDocument('1.0', 'utf-8');
                $element = $xml->createElement('user');
        
                $key = $xml->createElement('username', $username);
                $element->appendChild($key);
        
                $key = $xml->createElement('pwd', $password);
                $element->appendChild($key);
        
                $key = $xml->createElement('mail', $mail);
                $element->appendChild($key);
        
                $key = $xml->createElement('externalID', $externalID);
                $element->appendChild($key);
        
                $xml->appendChild($element);
        
                $postXML = urlencode(base64_encode($xml->saveXML()));
            }
        
            if (isset($activeAuth) && $activeAuth == 'Y') {
                $reply = webhostRequest($domainAuth, $ui->escaped('HTTP_HOST', 'server'), $fileAuth, array('authPWD' => $pwdAuth, 'userAuth' => $userAuth, 'postXML' => $postXML), $portAuth);
        
                $xmlReply = @simplexml_load_string($reply);
        
                if ($xmlReply && isset($xmlReply->success) && $xmlReply->success == 1 && $xmlReply->user == $username) {
                    $passwordCorrect = true;
                    $newHash = passwordCreate($username, $password);
        
                    if (is_array($newHash)) {
                        $query = $sql->prepare("UPDATE `userdata` SET `security`=?,`salt`=? WHERE `id`=? LIMIT 1");
                        $query->execute(array($newHash['hash'], $newHash['salt'], $id));
                    } else {
                        $query = $sql->prepare("UPDATE `userdata` SET `security`=? WHERE `id`=? LIMIT 1");
                        $query->execute(array($newHash, $id));
                    }
                } elseif ($xmlReply && strlen($xmlReply->error) > 0) {
                    $externalAuthError = $xmlReply->error;
                } else {
                    $externalAuthError = $reply;
                }
            }
        }

        if (isset($active, $id, $resellerid) and $active == 'Y' and isset($passwordCorrect) and $passwordCorrect) {

            $sessionCookieParameter = session_get_cookie_params();

            session_unset();
            session_destroy();
            session_set_cookie_params($sessionCookieParameter['lifetime'], $sessionCookieParameter['path'], $sessionCookieParameter['domain'], ($ui->escaped('HTTPS', 'server') == 'on'), true);
            session_start();

            # https://github.com/easy-wi/developer/issues/2
            if (isset($sID)) {
                $query = $sql->prepare("SELECT `logintime`,`language` FROM `userdata_substitutes` WHERE `sID`=? LIMIT 1");
                $query->execute(array($sID));
                while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $logintime = $row['logintime'];
                    $_SESSION['language'] = $row['language'];
                }

                $query = $sql->prepare("UPDATE `userdata_substitutes` SET `lastlogin`=?,`logintime`=? WHERE `sID`=? LIMIT 1");
                $query->execute(array($logintime, $logdate, $sID));

            } else if (isset($id)) {
                $query = $sql->prepare("SELECT `logintime`,`language` FROM `userdata` WHERE `id`=? LIMIT 1");
                $query->execute(array($id));
                while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                    $logintime = $row['logintime'];
                    $_SESSION['language'] = $row['language'];
                }

                $query = $sql->prepare("UPDATE `userdata` SET `lastlogin`=?,`logintime`=? WHERE `id`=? LIMIT 1");
                $query->execute(array($logintime, $logdate, $id));

            } else {
                redirect('login.php');
            }

            if (!isset($accounttype) or !isset($resellerid)  or ($accounttype == 'r' and $resellerid < 1)) {
                redirect('login.php');
            }

            $_SESSION['resellerid'] = $resellerid;

            $query = $sql->prepare("DELETE FROM `badips` WHERE `badip`=?");
            $query->execute(array($loguserip));

            if (isanyadmin($id) or rsellerpermisions($id)) {
                $_SESSION['adminid'] = $id;

                if (isset($_SESSION['adminid']) and is_numeric($_SESSION['adminid'])) {
                    $admin_id = $_SESSION['adminid'];
                }

            } else if (isanyuser($id)) {
                $_SESSION['userid'] = $id;

                if (isset($_SESSION['userid']) and is_numeric($_SESSION['userid'])) {
                    $user_id = $_SESSION['userid'];
                }

                if (isset($sID)) {
                    $_SESSION['sID'] = $sID;
                }
            }

            $ref = '';

            if ($ui->url('HTTP_REFERER', 'server')) {
                $ref = $ui->url('HTTP_REFERER', 'server');
            } else if ($ui->domain('HTTP_REFERER', 'server')) {
                $ref = $ui->domain('HTTP_REFERER', 'server');
            }

            $referrer = explode('/', strtolower(str_replace(array('http://', 'https://'), '', $ref)));

            if (isset($referrer[1]) && $referrer[1] == 'login.php') {
                $topanel = true;
            }
            
            if (!isset($user_id) && !isset($admin_id)) {
                header('Location: login.php&r=lo');
            } else if (isset($user_id)) {
                redirect('userpanel.php');
            } else if (isset($admin_id)) {
                $folders = explode('/', $ui->server['SCRIPT_NAME']);
                $amount = count($folders) - 1;
                $path = implode('/', array_slice($folders, 0, $amount));
            
                $webhostdomain = (isset($ui->server['HTTPS'])) ? 'https://' . $ui->server['HTTP_HOST'] . $path : 'http://' . $ui->server['HTTP_HOST'] . $path;
            
                $query = $sql->prepare("UPDATE `settings` SET `paneldomain`=? WHERE `resellerid`=0 LIMIT 1");
                $query->execute(array($webhostdomain));
            
                /* PHP 8 Workaround
                $params = @json_decode(licenceRequest(true));
                */
            
                if (isanyadmin($admin_id) || rsellerpermisions($admin_id)) {
                    redirect('admin.php');
                } else {
                    redirect('login.php&r=lo');
                }
            }
            

        } else if (!isset($passwordCorrect) || $passwordCorrect === false) {
            $halfhour = date('Y-m-d H:i:s', strtotime('+30 minutes'));
        
            $query = $sql->prepare("SELECT `id` FROM `badips` WHERE `badip`=? LIMIT 1");
            $query->execute(array($loguserip));
            $rowcount = $query->rowCount();
        
            $query = ($rowcount == 0) ? $sql->prepare("INSERT INTO `badips` (bantime,failcount,reason,badip) VALUES (?,'1','password',?)") : $sql->prepare("UPDATE `badips` SET `bantime`=?,`failcount`=`failcount`+1, `reason`='password' WHERE `badip`=? LIMIT 1");
            $query->execute(array($halfhour, $loguserip));
        
            if (isset($externalAuthError)) {
                redirect('login.php?w=up&error=' . urlencode(base64_encode($externalAuthError)) . '&r=lo');
            } else {
                redirect('login.php?w=up&r=lo');
            }
        } else if (isset($active) && $active == 'N') {
            redirect('login.php?w=su&r=lo');
        } else {
            redirect('login.php?w=up&r=lo');
        }

    } else if (!isset($include) and $ui->escaped('username', 'post') and $ui->escaped('password', 'post')) {
        redirect('login.php?w=up&r=lo');

    } else if(!isset($include)) {
        redirect('login.php?w=lo');
    }
}

if (isset($include) && isset($template_to_use)) {
    $filePaths = [
        EASYWIDIR . '/template/' . $template_to_use . '/standalone/' . $include,
        EASYWIDIR . '/template/' . $template_to_use . '/' . $include,
        EASYWIDIR . '/template/default/standalone/' . $include,
        EASYWIDIR . '/template/default/cms/' . $include,
        EASYWIDIR . '/template/default/' . $include,
        EASYWIDIR . '/template/' . $include
    ];

    foreach ($filePaths as $filePath) {
        if (is_file($filePath)) {
            include($filePath);
            break;
        }
    }
}


$sql = null;