<?php

/**
 * File: admin.php.
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

$main = 1;
define('EASYWIDIR', dirname(__FILE__));
if (is_dir(EASYWIDIR . '/install')) {
    die('Please remove the "install" folder');
}
require_once(EASYWIDIR . '/stuff/methods/vorlage.php');
require_once(EASYWIDIR . '/stuff/methods/class_validator.php');
require_once(EASYWIDIR . '/stuff/methods/functions.php');
require_once(EASYWIDIR . '/stuff/settings.php');
require_once(EASYWIDIR . '/stuff/admin/init_admin.php');
require_once(EASYWIDIR . '/stuff/admin/adminhome.php');

// Modul is loaded. Controller is set
$w = $ui->smallletters('w', 255, 'get');

if ($w and isset($what_to_be_included_array[$w])) {
    if (is_file((EASYWIDIR . '/stuff/admin/' . $what_to_be_included_array[$w]))) {
        include(EASYWIDIR . '/stuff/admin/' . $what_to_be_included_array[$w]);
    } else if (is_file((EASYWIDIR . '/stuff/' . $what_to_be_included_array[$w]))) {
        include(EASYWIDIR . '/stuff/' . $what_to_be_included_array[$w]);
    }
} else if ($w and isset($customFiles[$w]) and is_file((EASYWIDIR . '/stuff/custom_modules/' . $customFiles[$w]))) {
    $customModule = true;
    include(EASYWIDIR . '/stuff/custom_modules/' . $customFiles[$w]);
} else {
    $template_file = 'admin_home.tpl';
}

// Existing DB connection is closed
$dbConnect = null;

// No template defined, use default
if (!isset($template_to_use)) {
    $template_to_use = 'default';
}

// No template file specified, or specified as a string
if (!isset($template_file) || is_array($template_file) || is_object($template_file)) {
    $template_file = '';
} else if (is_object($template_file)) {
    $template_file = (string) $template_file;
}

// Load header, body and footer
include(IncludeTemplate($template_to_use, 'admin_header.tpl'));
include(IncludeTemplate($template_to_use, (preg_match('/^(.*)\.tpl$/', $template_file)) ? $template_file : 'general.tpl', (isset($customModule)) ? 'custom_modules' : 'admin'));
include(IncludeTemplate($template_to_use, 'admin_footer.tpl'));