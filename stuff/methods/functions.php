<?php
/**
 * File: functions.php.
 * Author: Ulrich Block
 * Author: Daniel Rodriguez Baumann
 * Date: 03.10.12
 * Time: 17:09
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

use PHPMailer\PHPMailer\PHPMailer;


if (!defined('EASYWIDIR')) {
    define('EASYWIDIR', '');
}

if (!function_exists('passwordgenerate')) {

    function passwordgenerate($length) {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';
        $charCount = strlen($characters);
        $password = '';
    
        for ($i = 0; $i < $length; $i++) {
            $randomIndex = mt_rand(0, $charCount - 1);
            $password .= $characters[$randomIndex];
        }
    
        return $password;
    }

    function passwordhash($username, $password, $salt = false) {
        $usernamePart = substr($username, 0, strlen($username) / 2 + 1);
        $passwordPart = substr($password, 0, strlen($password) / 2 + 1);

        $usernameFallback = isset($usernamePart[1]) ? $usernamePart[1] : $usernamePart[0];
        $passwordFallback = isset($passwordPart[1]) ? $passwordPart[1] : $passwordPart[0];

        $hashInput = $usernamePart[0] . md5($passwordPart[0] . ($salt ? $salt : '') . $usernameFallback) . $passwordFallback;
        return hash('sha512', sha1($hashInput));
    }

    function createHash($name, $pwd, $saltOne, $saltTwo = 'ZPZw$[pkJF!;SHdl', $iterate = 1000) {
        $namePart = substr($name, 0, strlen($name) / 2 + 1);
        $pwdPart = substr($pwd, 0, strlen($pwd) / 2 + 1);
    
        $nameFallback = isset($namePart[1]) ? $namePart[1] : $namePart[0];
        $pwdFallback = isset($pwdPart[1]) ? $pwdPart[1] : $pwdPart[0];
    
        if (isset($namePart[1]) && isset($pwdPart[1])) {
            $hash = '';
            for ($i = 0; $i <= $iterate; $i++) {
                $hash = hash('sha512', $namePart[0] . $saltOne . $pwdPart[0] . $hash . $nameFallback . $saltTwo . $pwdFallback);
            }
    
            return $hash;
        }
    
        return false;
    }

    function passwordCheck($password, $storedHash, $username = '', $salt = '') {
        global $aeskey;
    
        // Check if PHP supports the crypt function properly
        if (defined('CRYPT_BLOWFISH') && CRYPT_BLOWFISH) {
            if (password_verify($password, $storedHash)) {
                return true;
            }
    
            if (preg_match('/^[a-f0-9]{32}$/i', $storedHash) && md5($password) === $storedHash) {
                return password_hash($password, PASSWORD_DEFAULT);
            }
    
            if (preg_match('/^[a-f0-9]{40}$/i', $storedHash) && sha1($password) === $storedHash) {
                return password_hash($password, PASSWORD_DEFAULT);
            }
    
            if (preg_match('/^[a-f0-9]{128}$/i', $storedHash) && createHash($username, $password, $salt, $aeskey) === $storedHash) {
                return password_hash($password, PASSWORD_DEFAULT);
            }
    
        } else {
            $newSalt = md5(mt_rand() . date('Y-m-d H:i:s:u'));
    
            if (createHash($username, $password, $salt, $aeskey) === $storedHash) {
                return true;
            }
    
            if (preg_match('/^[a-f0-9]{32}$/i', $storedHash) && md5($password) === $storedHash) {
                return array('hash' => createHash($username, $password, $newSalt, $aeskey), 'salt' => $newSalt);
            }
    
            if (preg_match('/^[a-f0-9]{40}$/i', $storedHash) && sha1($password) === $storedHash) {
                return array('hash' => createHash($username, $password, $newSalt, $aeskey), 'salt' => $newSalt);
            }
    
            if (preg_match('/^[a-f0-9]{128}$/i', $storedHash) && passwordhash($username, $password) === $storedHash) {
                return createHash($username, $password, $salt, $aeskey);
            }
        }
    
        return false;
    }
    

    function passwordCreate($username, $password) {
        global $aeskey;
    
        if (defined('CRYPT_BLOWFISH') && CRYPT_BLOWFISH) {
            return password_hash($password, PASSWORD_DEFAULT);
        } else {
            $newSalt = md5(mt_rand() . strtotime('now'));
            return array('hash' => createHash($username, $password, $newSalt, $aeskey), 'salt' => $newSalt);
        }
    }    

    function szrp($value) {
        $szrm = array(
            'ä' => 'ae', 'ö' => 'oe', 'ü' => 'ue', 'Ä' => 'Ae',
            'Ö' => 'Oe', 'Ü' => 'Ue', 'ß' => 'ss', 'á' => 'a',
            'à' => 'a', 'Á' => 'A', 'À' => 'A', 'é' => 'e',
            'è' => 'e', 'É' => 'E', 'È' => 'E', 'ó' => 'o',
            'ò' => 'o', 'Ó' => 'O', 'Ò' => 'O', 'ú' => 'u',
            'ù' => 'u', 'Ú' => 'U', 'Ù' => 'U'
        );
    
        $filteredValue = preg_replace('/[^a-zA-Z0-9]+/', '-', $value);
        $lowercaseValue = strtolower($filteredValue);
        return strtr($lowercaseValue, $szrm);
    }
    

    function removeDoubleSlashes($value) {
        return preg_replace('#([^:])//+#', '$1/', $value);
    }
    
    function redirect($value, $sendHTTP301 = false) {
        $target = removeDoubleSlashes($value);
    
        if (substr($target, -9) === 'login.php' && session_status() === PHP_SESSION_ACTIVE) {
            session_unset();
            session_destroy();
        }
    
        header('Location: ' . $target, true, $sendHTTP301 ? 301 : 302);
        die('Please allow redirection or manually navigate to ' . $value);
    }
    

    function listDirs($dir) {
        $selectLanguages = array();
    
        if (is_dir($dir)) {
            $dirs = scandir($dir);
    
            foreach ($dirs as $row) {
                if (smallLettersCheck($row, 2)) {
                    $selectLanguages[] = $row;
                }
            }
        }
    
        return $selectLanguages;
    }
    
    function getLanguages($value) {
        $languages = listDirs('languages/' . $value . '/');
    
        if (empty($languages)) {
            $languages = listDirs('languages/default/');
        }
        if (empty($languages)) {
            $languages = listDirs('languages/');
        }
    
        return $languages;
    }
    

    function cleanFsockOpenRequest($string, $start, $stop) {
        $length = strlen($string);
    
        $startPos = 0;
        $stopPos = $length - 1;
    
        while ($startPos < $length && substr($string, $startPos, 1) !== $start) {
            $startPos++;
        }
    
        while ($stopPos >= 0 && substr($string, $stopPos, 1) !== $stop) {
            $stopPos--;
        }
    
        if ($startPos > $stopPos) {
            return '';
        }
    
        return substr($string, $startPos, $stopPos - $startPos + 1);
    }

    function serverAmount($resellerid) {
        global $sql, $user_language, $rSA;
    
        $gsCountQuery = $sql->prepare("SELECT COUNT(g.`id`) AS `amount` FROM `gsswitch` g LEFT JOIN `userdata` u ON g.`userid`=u.`id` LEFT JOIN `userdata` r ON g.`resellerid`= r.`id` WHERE g.`active`='Y' AND u.`active`='Y' AND (r.`active`='Y' OR r.`active` IS NULL)");
        $gsCountQuery->execute();
        $gsCount = (int) $gsCountQuery->fetchColumn();
    
        $voCountQuery = $sql->prepare("SELECT COUNT(v.`id`) AS `amount` FROM `voice_server` v LEFT JOIN `voice_masterserver` m ON v.`masterserver`=m.`id` LEFT JOIN `userdata` u ON v.`userid`=u.`id` LEFT JOIN `userdata` r ON v.`resellerid`= r.`id` WHERE v.`active`='Y' AND m.`active`='Y' AND u.`active`='Y' AND (r.`active`='Y' OR r.`active` IS NULL)");
        $voCountQuery->execute();
        $voCount = (int) $voCountQuery->fetchColumn();
    
        $count = $gsCount + $voCount;
    
        $sprache = getlanguagefile('licence', $user_language, $resellerid);
        $s = $sprache->unlimited;
        $mG = $s;
        $mVo = $s;
        $lG = 10;
        $lVo = 10;
        $lD = 10;
        $left = $s;
    
        if ($resellerid != 0) {
            $resellerDataQuery = $sql->prepare("SELECT `maxgserver`, `maxvoserver`, `maxdedis` FROM `resellerdata` WHERE `resellerid`=? LIMIT 1");
            $resellerDataQuery->execute(array($resellerid));
            while ($row = $resellerDataQuery->fetch(PDO::FETCH_ASSOC)) {
                $mG = $row['maxgserver'];
                $mVo = $row['maxvoserver'];
            }
    
            $gsCountQuery = $sql->prepare("SELECT COUNT(g.`id`) AS `amount` FROM `gsswitch` g LEFT JOIN `userdata` u ON g.`userid`=u.`id` WHERE g.`resellerid`=? AND g.`active`='Y' AND u.`active`='Y'");
            $gsCountQuery->execute(array($resellerid));
            $gsCount = (int) $gsCountQuery->fetchColumn();
    
            $voCountQuery = $sql->prepare("SELECT COUNT(v.`id`) AS `amount` FROM `voice_server` v LEFT JOIN `voice_masterserver` m ON v.`masterserver`=m.`id` LEFT JOIN `userdata` u ON v.`userid`=u.`id` LEFT JOIN `userdata` r ON v.`resellerid`= r.`id` WHERE v.`resellerid`=? AND v.`active`='Y' AND m.`active`='Y' AND u.`active`='Y'");
            $voCountQuery->execute(array($resellerid));
            $voCount = (int) $voCountQuery->fetchColumn();
        }

        return array(
            'left' => $left,
            'count' => $count,
            'gsCount' => $gsCount,
            'voCount' => $voCount,
            'mG' => $mG,
            'mVo' => $mVo,
            'lG' => $lG,
            'lVo' => $lVo,
            'lD' => $lD,
            'p' => 'Y',
            'b' => 'Y',
            't' => 'g',
            'u' => 'U',
            'c' => 'B',
            'v' => $rSA['version']
        );
    }

    function getusername($userid) {
        global $sql;
        $query = $sql->prepare("SELECT `cname` FROM `userdata` WHERE `id`=? LIMIT 1");
        $query->execute(array($userid));
        $cname = $query->fetchColumn();
        return ($cname !== false) ? $cname : 'User deleted';
    }

    function rsellerpermisions($userid) {
        global $sql;
        $query = $sql->prepare("SELECT `userid` FROM `userpermissions` WHERE `userid`=? AND (`addvserver`='Y' OR `modvserver`='Y' OR `delvserver`='Y' OR `vserversettings`='Y' OR `vserverhost`='Y' OR `resellertemplates`='Y' OR `usevserver`='Y' OR `root`='Y' OR `traffic`='Y') LIMIT 1");
        $query->execute(array($userid));
        $colcount = $query->rowCount();
    
        if ($colcount == 0) {
            $query = $sql->prepare("SELECT g.`id` FROM `userdata_groups` u LEFT JOIN `usergroups` g ON u.`groupID`=g.`id` WHERE u.`userID`=? AND (`addvserver`='Y' OR `modvserver`='Y' OR `delvserver`='Y' OR `vserversettings`='Y' OR `vserverhost`='Y' OR `resellertemplates`='Y' OR `usevserver`='Y' OR `root`='Y' OR `traffic`='Y') LIMIT 1");
            $query->execute(array($userid));
            $colcount = $query->rowCount();
        }
    
        return $colcount;
    }
    
    function isanyadmin($userid) {
        global $sql;
    
        $query = $sql->prepare("SELECT `accounttype` FROM `userdata` WHERE `id`=? AND `accounttype` IN ('a', 'r') LIMIT 1");
        $query->execute(array($userid));
        $accountType = $query->fetchColumn();
    
        return ($accountType == 'a' or $accountType == 'r');
    }

    function isanyuser($userid) {
        global $sql;
    
        $query = $sql->prepare("SELECT COUNT(*) FROM `userdata` WHERE `id`=? AND `accounttype`='u'");
        $query->execute(array($userid));
    
        return ($query->fetchColumn() > 0);
    }
    

    function language($user_id) {
        global $sql, $ui;
    
        if (isset($_SESSION['language'])) {
            return $_SESSION['language'];
        }
    
        $query = $sql->prepare("SELECT `language` FROM `userdata` WHERE `id`=? LIMIT 1");
        $query->execute([$user_id]);
        $language = $query->fetchColumn();
    
        if (!$language || !is_dir(EASYWIDIR . '/languages/' . $language)) {
            $lang_detect = isset($ui->server['HTTP_ACCEPT_LANGUAGE']) ? substr($ui->server['HTTP_ACCEPT_LANGUAGE'], 0, 2) : 'uk';
            $language = is_dir(EASYWIDIR . '/languages/' . $lang_detect) ? $lang_detect : 'en';
        }
    
        $query = $sql->prepare("UPDATE `userdata` SET `language`=? WHERE `id`=? LIMIT 1");
        $query->execute([$language, $user_id]);
        $_SESSION['language'] = $language;
    
        return $language;
    }
    
    

    function getlanguagefile($filename, $user_language, $reseller_id) {

        global $sql;

        $query = $sql->prepare("SELECT `language`,`template` FROM `settings` WHERE `resellerid`=? LIMIT 1");
        $query->execute(array($reseller_id));
    
        $row = $query->fetch(PDO::FETCH_ASSOC);
        $default_language = $row['language'];
        $template = $row['template'];
    
        $paths_to_check = [
            EASYWIDIR . '/languages/' . $template . '/' . $user_language . '/' . $filename . '.xml',
            EASYWIDIR . '/languages/' . $template . '/' . $default_language . '/' . $filename . '.xml',
            EASYWIDIR . '/languages/default/' . $user_language . '/' . $filename . '.xml',
            EASYWIDIR . '/languages/default/' . $default_language . '/' . $filename . '.xml',
            EASYWIDIR . '/languages/' . $user_language . '/' . $filename . '.xml',
            EASYWIDIR . '/languages/' . $default_language . '/' . $filename . '.xml'
        ];
    
        foreach ($paths_to_check as $path) {
            if (file_exists($path)) {
                return simplexml_load_file($path);
            }
        }
    
        return new stdClass;
    }
    
    function ipstoarray($value) {
        $ips_array = array();
    
        if (isips($value)) {
            foreach (explode("\r\n", $value) as $exip) {
                if (isips($exip)) {
                    $exploded_ip = explode('.', $exip);
                    if (isset($exploded_ip[3]) && is_numeric($exploded_ip[3])) {
                        $ips_array[] = $exip;
                    } else if (isset($exploded_ip[3])) {
                        $range = explode('/', $exploded_ip[3]);
                        $start = $range[0];
                        $end = isset($range[1]) ? $range[1] : $start;
    
                        for ($i = $start; $i <= $end; $i++) {
                            $ips_array[] = $exploded_ip[0] . '.' . $exploded_ip[1] . '.' . $exploded_ip[2] . '.' . $i;
                        }
                    }
                }
            }
        }
    
        natsort($ips_array);
    
        return $ips_array;
    }

    function webhostdomain($resellerid) {

        global $sql;

        $paneldomain = '';

        $query = $sql->prepare("SELECT `paneldomain` FROM `settings` WHERE `resellerid`=? LIMIT 1");
        $query->execute(array($resellerid));
        while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
            $paneldomain = $row['paneldomain'];
        }

        if (!filter_var($paneldomain, FILTER_VALIDATE_URL)) {
            $query = $sql->prepare("SELECT `paneldomain` FROM `settings` WHERE `resellerid`=0 LIMIT 1");
            $query->execute();
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $paneldomain = $row['paneldomain'];
            }
        }

        return $paneldomain;
    }

    /**
     * Send with the help of template a email.
     * @param unknown $template
     * @param unknown $userid
     * @param unknown $server
     * @param unknown $shorten
     * @param array $connectInfo
     * @return boolean
     */
    function sendmail($template, $userid, $server, $shorten, $connectInfo = array()) {

        global $sql, $rSA, $ui;

        $urlhost='';

        if (!isset($aeskey)) {
            include(EASYWIDIR . '/stuff/keyphrasefile.php');
        }
        if (!class_exists('PHPMailer')) {

            include(EASYWIDIR . '/third_party/phpmailer6/PHPMailer.php');
            include(EASYWIDIR . '/third_party/phpmailer6/SMTP.php');
        }

        if ($template == 'emailnewticket') {
            $writerid = $shorten[1];
            $topicid = $shorten[2];
            $shorten = $shorten[0];
        }

        //Load costomer
        $query = $sql->prepare("SELECT * FROM `userdata` WHERE `id`=? LIMIT 1");
        $query->execute(array($userid));
        while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
            $lastname = $row['name'];
            $firstname = $row['vname'];
            $fullname = (empty($row['vname']) or empty($row['name'])) ? $row['mail'] : $row['vname'] . ' ' . $row['name'];
            $cname = $row['cname'];
            $salutation = ($row['salutation'] == 1) ? 'Sehr geehrter Herr': 'Sehr geehrte Frau';
            $salutation = (empty($row['vname']) or empty($row['name'])) ? 'Hallo' : $salutation;
            $usermail = $row['mail'];
            $username = (empty($row['vname']) or empty($row['name'])) ? $row['cname'] : $row['vname'] . ' ' . $row['name'];
            $resellerid = $row['resellerid'];

            $email_id = $row['id'];
            $email_creationTime = $row['creationTime'];
            $email_active = $row['active'];
            $email_cname = $cname;
            $email_name = $lastname;
            $email_vname = $firstname;
            $email_birthday = $row['birthday'];
            $email_mail = $usermail;
            $email_phone = $row['phone'];
            $email_fax = $row['fax'];
            $email_handy = $row['handy'];
            $email_country = $row['country'];
            $email_city = $row['city'];
            $email_cityn = $row['cityn'];
            $email_street = $row['street'];
            $email_streetn = $row['streetn'];
            $userLanguage = $row['language'];
            $email_lastlogin = $row['lastlogin'];
        }

        if ($template != 'contact' and $template != 'easy-wi-update' and (!isset($resellerid) or !isset($email_country))) {
            return false;
        }

        $dataTemplate = array();

        // Will not be set in case of console execution
        if (isset($ui->server['HTTP_HOST'])) {
            $email_urlhost = (isset($ui->server['HTTPS'])) ? 'https://' . $ui->server['HTTP_HOST'] . '/login.php' : 'http://' . $ui->server['HTTP_HOST'] . '/login.php';
        } else {
            $email_urlhost = $rSA['paneldomain'] . '/login.php';
        }

        $password = $shorten;

        //Sprache des Admins
        $resellerLanguage = $rSA['language'];

        //Load E-Mail template data
        $loaddatatemplatequery = $sql->prepare("SELECT * FROM `settings_email_template` WHERE `email_setting_name`=? AND `reseller_id`=? AND `language`=? LIMIT 1");
        $loaddatatemplatequery->execute(array($template, $resellerid, $email_country));

        //default language 'de'
        if ($loaddatatemplatequery->rowCount() <= 0){
            $loaddatatemplatequery = $sql->prepare("SELECT * FROM `settings_email_template` WHERE `email_setting_name`=? AND `reseller_id`=? AND `language`='de' LIMIT 1");
            $loaddatatemplatequery->execute(array($template, $resellerid));
        }

        while ($row = $loaddatatemplatequery->fetch(PDO::FETCH_ASSOC)) {
            foreach ($row as $k => $v) {
                $dataTemplate[$k] = $v;
            }
        }


        if ($template == 'emailnewticket' and isset($writerid)) {

            $query = $sql->prepare("SELECT `vname`,`name`,`cname` FROM `userdata` WHERE `id`=? LIMIT 1");
            $query->execute(array($writerid));
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $username = ($row['vname'] . ' ' . $row['name'] == ' ') ? $row['cname'] : $row['vname'] . ' ' . $row['name'];
            }

            $query = $sql->prepare("SELECT `topic` FROM `ticket_topics` WHERE `id`=? LIMIT 1");
            $query->execute(array($topicid));
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                $topicname = $row['topic'];
            }

            if(isset($topicname)){
                $topic = '#' . $shorten . ' | ' . $topicname;
            }else{
                $topic = '#' . $shorten;
            }


        } else if (isset($dataTemplate['subject'])) {
            //Topic/Subject
            $topic = $dataTemplate['subject'];
        } else if ($template != 'contact' and $template != 'easy-wi-update') {
            return false;
        }

        if (!isset($resellerid) or $resellerid == $userid) {

            $resellersid = 0;

            if (!isset($resellerid)) {
                $resellerid = 0;
            }

        } else {
            $resellersid = $resellerid;
        }

        $query = $sql->prepare("SELECT `email_setting_value` FROM `settings_email` WHERE `reseller_id`=? AND `email_setting_name`=? LIMIT 1");
        $query->execute(array($resellersid, 'email_settings_type'));
        $email_settings_type = $query->fetchColumn();

        if ($email_settings_type and $email_settings_type != 'N') {

            $query->execute(array($resellersid, 'email'));
            $resellermail = $query->fetchColumn();
            $resellerstimezone =  (!isset($rSA['timezone']) or $rSA['timezone'] == null) ? 0 : $rSA['timezone'];

            //Date of Email
            $maildate = date('Y-m-d H:i:s', strtotime("$resellerstimezone hour"));

            //Create E-Mail Body
            if ($template == 'contact') {
                $startMail = true;
                $topic = 'You\'ve been contacted by ' . $userid .'.';
                $mailBody = $server;
                $usermail = $resellermail;

            } else if ($template == 'easy-wi-update') {
                $startMail = true;
                $topic = 'An Easy-Wi update has been released';
                $mailBody = $server;
            } else {

                if ($resellerid == $userid) {
                    $resellermail = $resellersmail;
                }

                //Variablen
                $noreply='(This is an automated mail. Please do not reply to it since the account is configured to send only.)';
                $emailfooter ='';
                $emailregards ='';
                $ip = '';
                $port = '';
                if(isset($server) && isip($server, "ip4")){
                    list($ip, $port) = explode(":", $server);
                }

                $keys = array('%emailfooter%','%emailregards%','%noreply%','%topic%','%id%','%creationTime%','%active%','%salutation%','%cname%','%fullname%','%name%','%vname%','%birthday%','%mail%','%email%','%phone%','%fax%','%handy%','%country%','%city%','%cityn%','%street%','%streetn%','%language%','%lastlogin%','%urlhost%','%password%','%server%','%username%','%date%','%shorten%','%ip%','%port%','%port2%','%port3%','%port4%','%port5%','%ports%');
                $replacements = array($emailfooter, $emailregards, $noreply, $topic, $email_id, $email_creationTime, $email_active, $salutation, $email_cname, $fullname, $email_name, $email_vname, $email_birthday, $email_mail, $email_mail, $email_phone, $email_fax, $email_handy, $email_country, $email_city, $email_cityn, $email_street, $email_streetn, $userLanguage, $email_lastlogin, $email_urlhost, $password, $server, $username, $maildate, $shorten, $ip, $port);

                //More IP Adress
                if (is_array($connectInfo) and count($connectInfo) > 0 and isset($connectInfo['ip'])) {

                    //%ip%
                    $replacements[] = $connectInfo['ip'];
                    //%port%......
                    $ports = array();

                    if ((isset($connectInfo['port']))) {
                        $ports[] = $connectInfo['port'];
                        $replacements[] = $connectInfo['port'];
                    } else {
                        $replacements[] = '';
                    }

                    //%ports%
                    for ($i = 2; $i < 6; $i++) {
                        if (isset($connectInfo["port{$i}"])) {
                            $ports[] = $connectInfo["port{$i}"];
                            $replacements[] = $connectInfo["port{$i}"];
                        } else {
                            $replacements[] = '';
                        }
                    }

                    $replacements[] = implode(', ', $ports);

                } else {
                    for ($i = 0; $i < 7; $i++) {
                        $replacements[] = '';
                    }
                }

                $mailtext = $dataTemplate['email_body'];
                $mailBody = str_replace($keys, $replacements, $mailtext);

                if (isset($usermail) and $usermail != 'ts3@import.mail' and ismail($usermail)) {
                    $startMail = true;
                }
            }

            //Create E-Mail Object and send this
            if (isset($startMail) and isset($topic)) {

                $mail = new PHPMailer();
                $mail->CharSet = 'UTF-8';
                $mail->setFrom($resellermail);
                $mail->addAddress($usermail);

                if (!empty($dataTemplate['bccmailing'])) {
                    $mail->addBCC($dataTemplate['bccmailing']);
                }

                if (!empty($dataTemplate['ccmailing'])) {
                    $mail->addCC($dataTemplate['ccmailing']);
                }

                $mail->Subject = $topic;
                $mail->msgHTML($mailBody);

                if ($email_settings_type == 'S') {

                    $mail->isSMTP();

                    $query = $sql->prepare("SELECT `email_setting_value` FROM `settings_email` WHERE `reseller_id`=? AND `email_setting_name`=? LIMIT 1");
                    $query->execute(array($resellersid, 'email_settings_host'));
                    $mail->Host = $query->fetchColumn();
                    $query->execute(array($resellersid, 'email_settings_port'));
                    $mail->Port = $query->fetchColumn();
                    $query->execute(array($resellersid, 'email_settings_ssl'));
                    $email_settings_ssl = $query->fetchColumn();

                    if ($email_settings_ssl == 'T') {
                        $mail->SMTPSecure = 'tls';
                    } else if ($email_settings_ssl == 'S') {
                        $mail->SMTPSecure = 'ssl';
                    }

                    $mail->SMTPAuth = true;
                    $query->execute(array($resellersid, 'email_settings_user'));
                    $mail->Username = $query->fetchColumn();
                    $query->execute(array($resellersid, 'email_settings_password'));
                    $mail->Password = $query->fetchColumn();

                    $smtpConnect = $mail->smtpConnect(array(
                        'ssl' => array(
                            'verify_peer' => false,
                            'verify_peer_name' => false,
                            'allow_self_signed' => true
                        )
                    ));

                } else {
                    $smtpConnect = true;
                }

                if ($smtpConnect and $mail->send()) {

                    $query = $sql->prepare("INSERT INTO `mail_log` (`uid`,`topic`,`date`,`resellerid`) VALUES (?,?,NOW(),?)");
                    $query->execute(array($userid, $topic, ($resellerid == $userid) ? $resellersid : $resellerid));

                    return true;
                }
            }

            return false;
        }

        return true;
    }


    function IncludeTemplate($use, $file, $location = 'admin') {
        $paths = [
            EASYWIDIR . "/template/{$use}/{$location}/{$file}",
            EASYWIDIR . "/template/{$use}/{$file}",
            EASYWIDIR . "/template/default/{$location}/{$file}",
            EASYWIDIR . "/template/default/{$file}",
            EASYWIDIR . "/template/default/custom_modules{$file}",
            EASYWIDIR . "/template/{$file}",
        ];
    
        foreach ($paths as $path) {
            if (is_file($path) && preg_match('/^(.*)\.[\w]{1,}$/', $file)) {
                return $path;
            }
        }
    
        return false;
    }
    

    function returnButton ($templateToUse, $template, $what, $do, $id, $description = '') {

        ob_start();

        include(IncludeTemplate($templateToUse, $template, 'ajax'));

        return ob_get_clean();
    }

    function User_Permissions($id) {

        global $sql;
    
        $pa = array('defaultgroup' => false, 'active' => false, 'root' => false, 'miniroot' => false, 'settings' => false, 'log' => false, 'ipBans' => false, 'updateEW' => false, 'feeds' => false, 'jobs' => false, 'apiSettings' => false, 'cms_settings' => false, 'cms_pages' => false, 'cms_news' => false, 'cms_comments' => false, 'mysql_settings' => false, 'mysql' => false, 'user' => false, 'user_users' => false, 'userGroups' => false, 'userPassword' => false, 'roots' => false, 'masterServer' => false, 'gserver' => false, 'eac' => false, 'gimages' => false, 'addons' => false, 'restart' => false, 'gsResetting' => false, 'modfastdl' => false, 'fastdl' => false, 'useraddons' => false, 'usersettings' => false, 'ftpaccess' => false, 'tickets' => false, 'usertickets' => false, 'addvserver' => false, 'modvserver' => false, 'delvserver' => false, 'usevserver' => false, 'vserversettings' => false, 'resellertemplates' => false, 'vserverhost' => false, 'lendserver' => false, 'lendserverSettings' => false, 'voicemasterserver' => false, 'voiceserver' => false, 'voiceserverStats' => false, 'voiceserverSettings' => false, 'ftpbackup' => false);
    
        $query = $sql->prepare("SELECT `accounttype`, g.* FROM `userdata_groups` a INNER JOIN `usergroups` g ON g.`id`=a.`groupID` INNER JOIN `userdata` u ON u.`id`=a.`userID` WHERE u.`id`=?");
        $query->execute(array($id));
        $array = $query->fetchAll(PDO::FETCH_ASSOC);
    
        foreach ($array as $row) {
            if (($row['accounttype'] == 'u' and $row['miniroot'] == 'Y') or ($row['accounttype'] != 'u' and $row['root'] == 'Y')) {
                foreach ($row as $key => $value) {
                    $pa[$key] = true;
                }
            } else {
                foreach ($row as $key => $value) {
                    if ((isset($pa[$key]) and $pa[$key] === false) or !isset($pa[$key])) {
                        $pa[$key] = ($value == 'Y') ? true : false;
                    }
                }
            }
        }
    
        return $pa;
    }

    function array_value_exists($key, $value, $array) {
        return isset($array[$key]) && $array[$key] === $value;
    }

    function updateJobs($localID, $resellerID, $jobPending = 'Y') {
        global $sql;
    
        $updateGsswitch = $sql->prepare("UPDATE `gsswitch` SET `jobPending`=? WHERE `userid`=? AND `resellerid`=?");
        $updateGsswitch->execute(array($jobPending, $localID, $resellerID));
    
        $updateExternalDbs = $sql->prepare("UPDATE `mysql_external_dbs` SET `jobPending`=? WHERE `uid`=? AND `resellerid`=?");
        $updateExternalDbs->execute(array($jobPending, $localID, $resellerID));
    
        $updateVoiceServer = $sql->prepare("UPDATE `voice_server` SET `jobPending`=? WHERE `userid`=? AND `resellerid`=?");
        $updateVoiceServer->execute(array($jobPending, $localID, $resellerID));
    
        $updateVoiceDns = $sql->prepare("UPDATE `voice_dns` SET `jobPending`=? WHERE `userID`=? AND `resellerID`=?");
        $updateVoiceDns->execute(array($jobPending, $localID, $resellerID));
    }
    

    function updateStates($action, $type = null) {
        global $sql;
    
        $typeQuery = ($type != null) ? " AND `type`='$type'" : '';
    
        $selectQuery = $sql->prepare("SELECT `type`, `affectedID` FROM `jobs` WHERE (`status` IS NULL OR `status`=1) AND `action`=? $typeQuery GROUP BY `type`, `affectedID`");
        $selectQuery->execute(array($action));
    
        while ($row = $selectQuery->fetch(PDO::FETCH_ASSOC)) {
            $type = $row['type'];
            $affectedID = $row['affectedID'];
    
            $selectMaxJobID = $sql->prepare("SELECT MAX(`jobID`) AS `maxJobID` FROM `jobs` WHERE `type`=? AND `affectedID`=? AND `action`=? $typeQuery");
            $selectMaxJobID->execute(array($type, $affectedID, $action));
    
            $maxJobIDRow = $selectMaxJobID->fetch(PDO::FETCH_ASSOC);
            $maxJobID = $maxJobIDRow['maxJobID'];
    
            if ($type == null) {
                $updateJobs = $sql->prepare("UPDATE `jobs` SET `status`='2' WHERE (`status` IS NULL OR `status`=1) AND `type`=? AND `affectedID`=? AND `jobID`!=?");
                $updateJobs->execute(array($type, $affectedID, $maxJobID));
            } else {
                $updateJobs = $sql->prepare("UPDATE `jobs` SET `status`='2' WHERE (`status` IS NULL OR `status`=1) AND `userID`=? AND `jobID`!=?");
                $updateJobs->execute(array($affectedID, $maxJobID));
            }
        }
    }
    

    function CopyAdminTable ($tablename, $id, $reseller_id, $limit, $where='') {

        global $sql;

        $query = $sql->prepare("SELECT * FROM `$tablename` WHERE `resellerid`=? " . $where . " " .$limit);
        $query->execute(array($reseller_id));
        while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

            $keys = array();
            $questionmarks = array();
            $intos = array();

            foreach ($row as $key=>$value) {
                if ($key != 'id' and $key != 'resellerid'){
                    $keys[]="`".$key."`";
                    $questionmarks[] = '?';
                    $intos[] = $value;
                }
            }

            $keys[] = "`resellerid`";
            $intos[] = $id;
            $questionmarks[] = '?';
            $into = 'INSERT INTO `' . $tablename . '` (' . implode(',', $keys) . ') VALUES (' . implode(',', $questionmarks) . ')';
            $query2 = $sql->prepare("$into");
            $query2->execute($intos);
        }
    }

    function dataExist($value, $array) {
        if(isset($array[$value]) && isset($array[$array[$value]]) && $array[$array[$value]]) {
            return true;
        }
        return false;
    }

    function webhostRequest ($domain, $useragent, $file, $postParams = '', $port = 80) {

        $domain = str_replace(array('https://', 'http://'),'', $domain);

        if ($port == 443) {
            $domain = 'ssl://' . $domain;
        }

        if (isdomain($domain)) {
            $fp = @fsockopen($domain, $port, $errno, $errstr, 10);
        } else {
            $errstr = $domain . ' is no domain';
        }

        if (isset($fp) and $fp) {

            if (is_array($postParams) and count($postParams) > 0) {
                $postData = '';
                $i = 0;

                foreach ($postParams as $key=>$value) {
                    if ($i == 0){
                        $postData .= $key . '=' . $value;
                    } else {
                        $postData .= '&' . $key . '=' . $value;
                    }
                    $i++;
                }

                $send = "POST /${file} HTTP/1.1\r\n";

            } else {

                if (strlen($file) == 0) {
                    $file = '/';
                }
                $send = "GET ${file} HTTP/1.1\r\n";
            }

            $send .= "Host: ${domain}\r\n";
            $send .= "User-Agent: ${useragent}\r\n";
            $send .= "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n";

            if (isset($postData) and is_array($postParams) and count($postParams) > 0) {
                $send .= "Content-Length: " . strlen($postData) . "\r\n";
            }
            $send .= "Connection: Close\r\n\r\n";

            if (isset($postData) and is_array($postParams) and count($postParams)>0) {
                $send .= $postData;
            }

            fwrite($fp, $send);

            $buffer = '';
            while (!feof($fp)) {
                $buffer .= fgets($fp, 4096);
            }

            fclose($fp);

            $ex = explode("\r\n\r\n", $buffer);

            if (strpos($ex[0], '404') !== false) {
                return 'file not found: ' . $domain . '/' . $file;

            } else if (isset($ex[1])) {
                return $ex[1];

            } else {
                $errstr = 'Error: no response. Header is: ' . $ex[0];
            }
        }
        return 'Error: Could not connect to host ' . $domain . ' and port ' . $port . ' (' . $errstr . ')';
    }

    function checkPorts ($send, $used) {

        foreach ($send as $port) {
            if (!port($port) or in_array($port, $used)) {
                return false;
            }
        }

        return true;
    }

    function usedPorts ($ips) {

        global $sql;

        if (!is_array($ips)) {
            $ips = array($ips);
        }

        $portsArray = array();

        foreach ($ips as $serverIP) {

            $ports = array();

            $query = $sql->prepare("SELECT `port`,`port2`,`port3`,`port4`,`port5` FROM `gsswitch` WHERE `serverip`=? ORDER BY `port`");
            $query->execute(array($serverIP));
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                if (port($row['port'])){
                    $ports[] = $row['port'];
                }
                if (port($row['port2'])){
                    $ports[] = $row['port2'];
                }
                if (port($row['port3'])){
                    $ports[] = $row['port3'];
                }
                if (port($row['port4'])){
                    $ports[] = $row['port4'];
                }
                if (port($row['port5'])){
                    $ports[] = $row['port5'];
                }
            }

            $query = $sql->prepare("SELECT `port` FROM `voice_server` WHERE `ip`=?");
            $query->execute(array($serverIP));
            while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
                if (port($row['port'])){
                    $ports[] = $row['port'];
                }
            }

            $ports = array_unique($ports);
            asort($ports);

            $portsArray[count($ports)] = array('ip' => $serverIP, 'ports' => $ports);
        }

        $bestIP = current($portsArray);

        return array('ip' => $bestIP['ip'], 'ports' => $bestIP['ports']);
    }

    function array2xml($array, $xml){

        foreach($array as $key => $value){

            if (is_numeric($key)) {
                $key = 'key' . $key;
            }

            if (is_array($value)){
                array2xml($value, $xml->addChild($key));

            } else {
                $xml->$key = $value;
            }
        }
        return $xml->asXML();
    }

    function yesNo($check) {
        global $ui;
        return $ui->active($check, 'post') == 'Y' ? 'Y' : 'N';
    }

    function returnPlainArray ($arr, $key) {
        $return = array();

        if (is_array($arr) and !is_array($key)) {
            foreach ($arr as $v) {
                $return[] = $v[$key];
            }
        }

        return $return;
    }

    function licenceRequest($return = false, $boolreturn = false) {
        global $sql, $ui, $rSA;

        $developer = (isset($rSA['developer'])) ? $rSA['developer'] : 'N';
        $user_agent = isset($ui->server['HTTP_HOST']) ? $ui->server['HTTP_HOST'] : $rSA['paneldomain'];
        $host = "https://api.github.com/repos/easy-wi/developer/" . (($developer == 'Y') ? 'tags' : 'releases/latest');
        $header = [
            "Accept: application/vnd.github.v3+json",
            "User-Agent: " . $user_agent
        ];

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $host);
        curl_setopt($curl, CURLOPT_HEADER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
        $respones = curl_exec($curl);
        $request_info = curl_getinfo($curl);
        curl_close($curl);

        list($header, $content) = parseHeaders($respones);
        if($request_info["http_code"] == 200){
            $json = json_decode($content);

            if (($developer == 'N' and is_object($json) and property_exists($json, 'tag_name') or ($developer == 'Y' and is_array($json) and isset($json[0]) and is_object($json[0]) and property_exists($json[0], 'name')))) {
                $version = ($developer == 'Y') ? $json[0]->name : $json->tag_name;
                $rSA['version'] = $version;
                $apiResponse = array('v' => $version);

                $query = $sql->prepare("UPDATE `settings` SET `version`=? WHERE `resellerid`=0 LIMIT 1");
                $query->execute(array($version));
            }


            return ($return == true) ? $json : $boolreturn;

        }else{
            return false;
        }
    }

    function token ($check = false) {

        global $ui, $_SESSION;

        if ($check == false) {

            $token = md5(mt_rand());
            $tokenLifeTime = '+40 minutes';

            if ($ui->id('id', 10, 'get') and $ui->smallletters('d', 10, 'get')) {
                $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')][$ui->id('id', 10, 'get')] = array('t' => $token,'d' => strtotime($tokenLifeTime));

            } else if (!$ui->id('id', 10, 'get') and $ui->smallletters('d', 10, 'get')) {
                $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')] = array('t' => $token,'d' => strtotime($tokenLifeTime));

            } else if ($ui->id('id', 10, 'get') and !$ui->smallletters('d', 10, 'get')) {
                $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->id('id', 10, 'get')] = array('t' => $token,'d' => strtotime($tokenLifeTime));

            } else {
                $_SESSION[$ui->smallletters('w', 10, 'get')] = array('t' => $token,'d' => strtotime($tokenLifeTime));
            }

            return $token;

        } else {

            if (isset($_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')][$ui->id('id', 10, 'get')]['t']) and $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')][$ui->id('id', 10, 'get')]['t'] == $ui->w('token', 32, 'post') and $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')][$ui->id('id', 10, 'get')]['d'] >= strtotime('now')) {
                return deleteOldToken(true, $ui->smallletters('w', 10, 'get'), $ui->smallletters('d', 10, 'get'), $ui->id('id', 10, 'get'));
            }

            if (isset($_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')]['t']) and $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')]['t'] == $ui->w('token', 32, 'post') and $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->smallletters('d', 10, 'get')]['d'] >= strtotime('now')) {
                return deleteOldToken(true, $ui->smallletters('w', 10, 'get'), $ui->smallletters('d', 10, 'get'));
            }

            if (isset($_SESSION[$ui->smallletters('w', 10, 'get')][$ui->id('id', 10, 'get')]['t']) and $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->id('id', 10, 'get')]['t'] == $ui->w('token', 32, 'post') and $_SESSION[$ui->smallletters('w', 10, 'get')][$ui->id('id', 10, 'get')]['d'] >= strtotime('now')) {
                return deleteOldToken(true, $ui->smallletters('w', 10, 'get'),'', $ui->id('id', 10, 'get'));
            }

            if (isset($_SESSION[$ui->smallletters('w', 10, 'get')]['t']) and $_SESSION[$ui->smallletters('w', 10, 'get')]['t'] == $ui->w('token', 32, 'post') and $_SESSION[$ui->smallletters('w', 10, 'get')]['d'] >= strtotime('now')) {
                return deleteOldToken(true, $ui->smallletters('w', 10, 'get'));
            }

            return false;
        }
    }

    function deleteOldToken ($returnCode, $w = '', $d = '', $id = '') {

        global $_SESSION;

        if ($w != 'sID') {
            if ($id != '' and $d != '') {
                unset($_SESSION[$w][$d][$id]);

            } else if ($id == '' and $d != '') {
                unset($_SESSION[$w][$d]);

            } else if ($id != '' and $d == '') {
                unset($_SESSION[$w][$id]);

            } else if ($id == '' and $d == '') {
                unset($_SESSION[$w]);
            }
        }

        foreach ($_SESSION as $k => $v) {

            if (wpreg_check($k, 4) and $k != 'sID' and ((isset($_SESSION[$k]['t']) and $_SESSION[$k]['d'] < strtotime('now')) or (is_array($_SESSION[$k]) and count($_SESSION[$k]) == 0))) {
                unset($_SESSION[$k]);

            } else if (wpreg_check($k, 4) and is_array($_SESSION[$k]) and count($_SESSION[$k]) > 0) {

                foreach ($_SESSION[$k] as $k2=>$v2) {
                    if (wpreg_check($k2, 4) and ((isset($_SESSION[$k][$k2]['t']) and $_SESSION[$k][$k2]['d'] < strtotime('now')) or (is_array($_SESSION[$k][$k2]) and count($_SESSION[$k][$k2]) == 0))) {
                        unset($_SESSION[$k][$k2]);

                    } else if (wpreg_check($k2, 4) and is_array($_SESSION[$k][$k2]) and count($_SESSION[$k][$k2]) > 0) {
                        foreach ($_SESSION[$k][$k2] as $k3 => $v3) {

                            if (isid($k3, 4) and ((isset($_SESSION[$k][$k2][$k3]['t']) and $_SESSION[$k][$k2][$k3]['d'] < strtotime('now')) or (is_array($_SESSION[$k][$k2][$k3]) and count($_SESSION[$k][$k2][$k3]) == 0))) {
                                unset($_SESSION[$k][$k2][$k3]);
                            }
                        }
                    }
                }
            }
        }

        return $returnCode;
    }

    function customColumns($item, $id = 0, $action = false, $api = false) {

        global $sql, $user_language, $default_language;

        $return = array();

        if ($id !== null) {

            $query = $sql->prepare("SELECT * FROM `custom_columns_settings` WHERE `item`=? AND `active`='Y'");
            $query->execute(array($item));

            if ($action == false) {
                $query2 = $sql->prepare("SELECT `text` FROM `translations` WHERE `type`='cc' AND `transID`=? AND `lang`=? LIMIT 1");
                $query3 = $sql->prepare("SELECT `var` FROM `custom_columns` WHERE `customID`=? AND `itemID`=? LIMIT 1");
                while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

                    $text = '';

                    $query2->execute(array($row['customID'], $user_language));
                    while ($row2 = $query2->fetch(PDO::FETCH_ASSOC)) {
                        $text = $row2['text'];
                    }

                    if (empty($text)) {

                        $query2->execute(array($row['customID'], $default_language));
                        while ($row2 = $query2->fetch(PDO::FETCH_ASSOC)) {
                            $text = $row2['text'];
                        }
                    }

                    $type = ($row['type'] == 'I') ? 'number' : 'text';
                    $query3->execute(array($row['customID'], $id));
                    $value = ($id == 0) ? '' : $query3->fetchColumn();

                   $return[] = array('customID' => $row['customID'], 'menu' => $text, 'name' => $row['name'], 'length' => $row['length'], 'type' => $row['type'], 'input' => "<input id='inputCustom-${row['customID']}' type='${type}' name='${row['name']}' maxlength='${row['length']}' value='${value}' >", 'value' => $value);
                }

            } else if ($action == 'save') {

                $return = 0;

                $query2 = $sql->prepare("INSERT INTO `custom_columns` (`customID`,`itemID`,`var`) VALUES (?,?,?) ON DUPLICATE KEY UPDATE `var`=VALUES(`var`)");

                if ($api == false) {

                    global $ui;

                    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

                        $var = '';

                        if ($row['type'] == 'I' and $ui->id($row['name'], $row['length'], 'post')) {
                            $var = $ui->id($row['name'], $row['length'], 'post');
                        } else if ($ui->names($row['name'], $row['length'], 'post')) {
                            $var = $ui->names($row['name'], $row['length'], 'post');
                        }

                        $query2->execute(array($row['customID'], $id, $var));

                        $return += $query2->rowCount();
                    }

                } else {

                    while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

                        $var = '';

                        if (isset($api[$row['name']])) {

                            if ($row['type'] == 'I') {
                                $var = isid($api[$row['name']], $row['length']);
                            } else if (names($api[$row['name']], $row['length'])) {
                                $var = names($api[$row['name']], $row['length']);
                            }

                            $query2->execute(array($row['customID'], $id, $var));

                            $return += $query2->rowCount();
                        }
                    }
                }

            } else if ($action == 'del') {

                $return = 0;

                $query2 = $sql->prepare("DELETE FROM `custom_columns` WHERE `customID`=? AND `itemID`=? LIMIT 1");

                while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

                    $query2->execute(array($row['customID'], $id));

                    $return += $query2->rowCount();
                }
            }

        }

        return $return;
    }

    function workAroundForValveChaos ($appID, $shorten, $toApi = true) {

        // Server to client ID mapping
        if ($toApi == true) {
            if ($appID == 90) {

                $mapping = array('cstrike' => 10, 'czero' => 80, 'dmc' => 40, 'dod' => 30, 'gearbox' => 50, 'ricochet' => 60, 'tfc' => 20);

                if (isset($mapping[$shorten])) {
                    return $mapping[$shorten];
                }
            } else {

                $mapping = array(510 => 500, 740 => 730, 4020 => 4000, 4940 => 4920, 17505 => 17500, 17510 => 17515, 17570 => 17575, 111710 => 17710, 215350 => 1250, 215360 => 1250, 222860 => 550, 229830 => 440, 232250 => 440, 232290 => 300, 232330 => 240, 232370 => 320, 258550 => 252490, 259080 => 261140, 295230 => 265630, 317670 => 224260, 332670 => 234630, 376030 => 346110);

                if (isset($mapping[$appID])) {
                    return $mapping[$appID];
                }
            }

        // Client to server mapping
        } else {

            if (in_array($appID, array(10, 20, 30, 40, 50, 60, 80))) {

                return 90;

            } else {

                $mapping = array(240 => 232330, 300 => 232290, 320 => 232370, 440 => 232250, 500 => 510, 730 => 740, 550 => 222860, 1250 => 215360, 4000 => 4020, 4920 => 4940, 17500 => 17505, 17515 => 17510, 17575 => 17570, 17710 => 111710, 215350 => 215360, 224260 => 317670, 234630 => 332670, 252490 => 258550, 261140 => 259080, 265630 => 295230, 346110 => 376030);

                if (isset($mapping[$appID])) {
                    return $mapping[$appID];
                }
            }
        }

        return $appID;
    }

# https://github.com/easy-wi/developer/issues/70
    function removePub ($string) {
        if (substr(strtolower($string), -4) == '.pub') {
            return substr($string, 0, -4);
        }
        return $string;
    }

# https://github.com/easy-wi/developer/issues/57
    function checkFtpData ($ip, $port, $user, $pwd) {

        $ftpConnection = @ftp_connect($ip, $port);

        if ($ftpConnection) {

            $ftpLogin = @ftp_login($ftpConnection, $user, $pwd);
            ftp_close($ftpConnection);

            return ($ftpLogin === true) ? true : 'login';
        }

        return 'ipport';
    }

    function ftpStringToData ($fptConnect) {

        $server = null;
        $port = null;
        $path = null;
        $user = '';
        $pwd = '';

        $fptConnect = str_replace(array('ftp://', 'ftps://'), '', $fptConnect);

        $splittedConnectionString = preg_split('/\@/', $fptConnect, -1, PREG_SPLIT_NO_EMPTY);

        $splittedConnectionStringArrayCount = count($splittedConnectionString) -1;


        if ($splittedConnectionStringArrayCount > 0) {

            $serverData = $splittedConnectionString[$splittedConnectionStringArrayCount];

            unset($splittedConnectionString[$splittedConnectionStringArrayCount]);

            @list($user, $pwd) = explode(':', implode('@', $splittedConnectionString));

            $ex = preg_split('/\//', $serverData, -1, PREG_SPLIT_NO_EMPTY);
            $portServer = $ex[0];

            $path = '';
            $i = 1;

            while ($i < count($ex)) {
                $path .= '/' . $ex[$i];
                $i++;
            }

            if ($path == '') {
                $path = '/';
            }

            @list($server, $port) = explode(':', $portServer);

            if (!$port) {
                $port = 21;
            }

        }

        return array('server' => $server, 'port' => $port, 'user' => $user, 'pwd' => $pwd, 'path' => $path);
    }

    function configureDateTables ($doNotShow = '', $defaultSorting = '0, "asc"', $ajaxSource = '') {

        global $htmlExtraInformation, $gsprache;

        if ($ajaxSource != '') {
            $ajaxSource = '"bServerSide" : true,"sAjaxSource": "' . $ajaxSource. '",';
        }

        $htmlExtraInformation['css'][] = '<link href="https://cdn.datatables.net/1.10.24/css/dataTables.bootstrap.min.css" rel="stylesheet" type="text/css">';
        $htmlExtraInformation['js'][] = '<script src="https://cdn.datatables.net/1.10.24/js/jquery.dataTables.min.js" type="text/javascript"></script>';
        $htmlExtraInformation['js'][] = '<script src="https://cdn.datatables.net/1.10.24/js/dataTables.bootstrap.min.js" type="text/javascript"></script>';
        $htmlExtraInformation['js'][] = "<script type='text/javascript'>
$(function() {
    $('#dataTable').dataTable({
        'bPaginate': true,
        'bLengthChange': true,
        'bFilter': true,
        'bSort': true,
        'aoColumnDefs': [{
            'bSortable': false,
            'aTargets': [{$doNotShow}]
        }],
        'bInfo': true,
        'bAutoWidth': false,
        'iDisplayLength' : 10,
        'aaSorting': [[{$defaultSorting}]],
        'oLanguage': {
            'oPaginate': {
                'sFirst': '{$gsprache->dataTablesFirst}',
                'sLast': '{$gsprache->dataTablesLast}',
                'sNext': '{$gsprache->dataTablesNext}',
                'sPrevious': '{$gsprache->dataTablesPrevious}'
            },
            'sEmptyTable': '{$gsprache->dataTablesEmptyTable}',
            'sInfo': '{$gsprache->dataTablesInfo}',
            'sInfoEmpty': '{$gsprache->dataTablesEmpty}',
            'sInfoFiltered': '{$gsprache->dataTablesFiltered}',
            'sLengthMenu': '{$gsprache->dataTablesMenu}',
            'sSearch': '{$gsprache->dataTablesSearch}',
            'sZeroRecords': '{$gsprache->dataTablesNoRecords}'
        },
        $ajaxSource
    });
});
</script>";

    }

    function getNumberNull($postKey) {

        global $ui;

        return $ui->port($postKey, 'post') ? $ui->port($postKey, 'post') : null;
    }

    function getUserList ($resellerID) {

        $table = array();

        global $sql;

        $query = $sql->prepare("SELECT `id`,`cname`,`vname`,`name` FROM `userdata` WHERE `resellerid`=? AND `accounttype`='u' ORDER BY `id` DESC");
        $query->execute(array($resellerID));
        while ($row = $query->fetch(PDO::FETCH_ASSOC)) {
            $table[$row['id']] = trim($row['cname'] . ' ' . $row['vname'] . ' ' . $row['name']);
        }

        return $table;
    }

    /**
     * Get the Slogan from DB
     * @param {sting} valueOfTitle
     * @return string
     */
    function getLoginHeader($valueOfTitle){
        return preg_replace('/(.+)[\s](.+)/i', '<b>${1}</b> $2', $valueOfTitle, -1, $count);
    }

    function parseHeaders($data)
    {
        list($header, $content) = explode("\r\n\r\n", $data);
        $headers =  explode("\r\n", $header);

        $head = array();
        foreach( $headers as $k=>$v )
        {
            $t = explode( ':', $v, 2 );
            if( isset( $t[1] ) )
                $head[ trim($t[0]) ] = trim( $t[1] );
            else
            {
                $head[] = $v;
                if( preg_match( "#HTTP/[0-9\.]+\s+([0-9]+)#",$v, $out ) )
                    $head['reponse_code'] = intval($out[1]);
            }
        }
        return [$head, $content];
    }

    function __debug($pre){
        echo "<pre>";
        print_r($pre);
        echo "</pre>";
    }
}