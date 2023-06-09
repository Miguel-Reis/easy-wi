<?php

/**
 * File: datatable_appmasterserver.php.
 * Author: Ulrich Block
 * Date: 14.09.14
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

if (!defined('AJAXINCLUDED')) {
    die('Do not access directly!');
}

require_once(EASYWIDIR . '/stuff/keyphrasefile.php');
require_once(EASYWIDIR . '/stuff/methods/functions_ssh_exec.php');
require_once(EASYWIDIR . '/stuff/methods/class_masterserver.php');

$query = $sql->prepare("SELECT COUNT(`id`) AS `amount` FROM `rserverdata` WHERE `resellerid`=?");
$query->execute(array($resellerLockupID));
$array['iTotalRecords'] = $query->fetchColumn();

if ($sSearch) {
    $query = $sql->prepare("SELECT COUNT(r.`id`) AS `amount` FROM `rserverdata` AS r WHERE r.`active`='Y' AND r.`resellerid`=:resellerID AND (r.`id` LIKE :search OR r.`ip` LIKE :search OR r.`description` LIKE :search OR EXISTS(SELECT 1 FROM `rservermasterg` AS m INNER JOIN `servertypes` s ON s.`id`=m.`servertypeid` WHERE m.`serverid`=r.`id` AND s.`shorten` LIKE :search))");
    $query->execute(array(':resellerID' => $resellerLockupID, ':search' => '%' . $sSearch . '%'));
    $array['iTotalDisplayRecords'] = $query->fetchColumn();

} else {
    $array['iTotalDisplayRecords'] = $array['iTotalRecords'];
}


$orderFields = array(0 => '`ip`', 1 => '`id`', 2 => '`description`');

$orderBy = isset($orderFields[$iSortCol]) ?
    (is_array($orderFields[$iSortCol]) ?
        implode(' ' . $sSortDir . ', ', $orderFields[$iSortCol]) . ' ' . $sSortDir :
        $orderFields[$iSortCol] . ' ' . $sSortDir) :
    '`id` ASC';

$query2 = $sql->prepare("SELECT DISTINCT(s.`shorten`) AS `shorten`,r.`installing`,r.`updating`,r.`installstarted` FROM `rservermasterg` r INNER JOIN `servertypes` s ON r.`servertypeid`=s.`id` WHERE r.`serverid`=? AND r.`resellerid`=?");
$query3 = $sql->prepare("SELECT r.`id`,s.`steamgame`,s.`updates`,d.`updates` AS `rupdates` FROM `rservermasterg` r INNER JOIN `rserverdata` d ON r.`serverid`=d.`id` INNER JOIN `servertypes` s ON r.`servertypeid`=s.`id` WHERE s.`shorten`=? AND r.`resellerid`=? AND d.`ip`=? LIMIT 1");
$query4 = $sql->prepare("UPDATE `rservermasterg` SET `installing`='N',`updating`='N' WHERE `id`=? LIMIT 1");

if ($sSearch) {
    $query = $sql->prepare("SELECT `id`,`ip`,`description` FROM `rserverdata` AS r WHERE `active`='Y' AND `resellerid`=:resellerID AND (`id` LIKE :search OR `ip` LIKE :search OR `description` LIKE :search OR EXISTS (SELECT 1 FROM `rservermasterg` AS m INNER JOIN `servertypes` s ON s.`id`=m.`servertypeid` WHERE m.`serverid`=r.`id` AND s.`shorten` LIKE :search)) ORDER BY $orderBy LIMIT {$iDisplayStart},{$iDisplayLength}");
    $query->execute(array(':resellerID' => $resellerLockupID, ':search' => '%' . $sSearch . '%'));
} else {
    $query = $sql->prepare("SELECT `id`,`ip`,`description` FROM `rserverdata` WHERE `active`='Y' AND `resellerid`=? ORDER BY $orderBy LIMIT {$iDisplayStart},{$iDisplayLength}");
    $query->execute(array($resellerLockupID));
}

while ($row = $query->fetch(PDO::FETCH_ASSOC)) {

    $rootServer = new masterServer($row['id'], $aeskey);

    $statusList = array();
    $sshcheck = array();

    $description = $row['description'];

    $query2->execute(array($row['id'], $resellerLockupID));

    while ($row2 = $query2->fetch(PDO::FETCH_ASSOC)) {

        $shorten = $row2['shorten'];

        if ($row2['installing'] == 'N' && $row2['updating'] == 'N') {

            $statusList[$shorten] = true;

        } else {

            $toolong = strtotime("+15 minutes", strtotime($row2['installstarted']));

            if (strtotime($logdate) > $toolong) {

                $sshcheck[] = $shorten;

                $rootServer->checkForUpdate($shorten);

            } else {
                $statusList[$shorten] = false;
            }
        }
    }


    if (count($sshcheck) > 0) {
        $checkReturn = $rootServer->getUpdateStatus();
        if ($checkReturn === false) {
            $description = 'The login data does not work';
        } else if (strlen($checkReturn) > 0) {
            $games = array();
            foreach (preg_split('/\;/', $checkReturn, -1, PREG_SPLIT_NO_EMPTY) as $status) {
                $ex = explode('=', $status);
                if (isset($ex[1])) {
                    $games[$ex[0]] = $ex[1];
                }
            }
    
            $query3->execute(array_values($sshcheck), $resellerLockupID, $rootServer->sship);
            $rows3 = $query3->fetchAll(PDO::FETCH_ASSOC);
    
            foreach ($games as $shorten => $v) {
                // Check if the shorten exists and the update is done
                $matchingRows = array_filter($rows3, function($row) use ($shorten) {
                    return $row['shorten'] === $shorten;
                });
                if (!empty($matchingRows) && in_array($v, [0, '0'])) {
                    $statusList[$shorten] = true;
                    $query4->execute(array($matchingRows[0]['id']));
                    unset($sshcheck[array_search($shorten, $sshcheck)]);
                }
            }
        }
    
        foreach ($sshcheck as $shorten) {
            $statusList[$shorten] = false;
        }
    }

    // Add Server space data - Nexus633
    // Fix Json_decode error
    $space = $rootServer->getDiskSpace("/home") ?: $rootServer->getDiskSpace("/") ?: (object) ["mount" => "unknown"];

    if ($space->mount === "unknown") {
        $spacedata = '<a href="javascript:void(0);"><span class="btn btn-danger btn-sm">unknown</span></a>';
    } else {
        $perc = (int) substr($space->perc, 0, -1);

        switch (true) {
            case ($perc <= 50):
                $btn_class = "btn-success";
                break;
            case ($perc <= 80):
                $btn_class = "btn-warning";
                break;
            default:
                $btn_class = "btn-danger";
        }

        $spacedata = sprintf(
            '<a href="javascript:void(0);"><span class="btn %s btn-sm">%s - %s / %s</span></a>',
            $btn_class,
            "{$gsprache->status_space_used} {$space->perc} - {$space->mount}",
            "{$gsprache->status_space_size} {$space->size}",
            "{$gsprache->status_space_free} {$space->avil}"
        );
    }
    $array['aaData'][] = array(
        $row['ip'], 
        $row['id'], 
        $description, 
        returnButton($template_to_use, 'ajax_admin_master_list.tpl', $statusList, '', '', ''), 
        returnButton($template_to_use, 'ajax_admin_buttons_dl.tpl', 'ma', 'dl', $row['id'], $gsprache->del) . ' ' . returnButton($template_to_use, 'ajax_admin_buttons_add.tpl', 'ma', 'ad', $row['id'], $gsprache->add), 
        $spacedata
    );
}