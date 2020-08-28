<?php

namespace Skyline\Admin\Ready\Controller\Management;


use Skyline\PDO\SQLite;

class AbstractContentManagementActionController extends \Skyline\Admin\Ready\Controller\AbstractGeneralAdminController
{
	public static function getContentsPDO(&$contentsDir): SQLite {
		static $PDO;
		if(!$PDO) {
			$ui = SkyGetPath("$(/)/UI");
			if(!is_dir($ui))
				throw new \RuntimeException("Configuration error: Skyline UI directory does not exist", 400);

			$contentsDir = $ui . DIRECTORY_SEPARATOR . 'Contents';
			if(!is_dir($contentsDir))
				mkdir($contentsDir);

			$sqlite = $contentsDir . DIRECTORY_SEPARATOR . "contents.sqlite";
			$PDO = new SQLite($sqlite);
		}

		return $PDO;
	}
}