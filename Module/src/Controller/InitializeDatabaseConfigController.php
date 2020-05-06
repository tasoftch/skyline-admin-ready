<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\CMS\Security\Tool\UserTool;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Translation\TranslationManager;
use TASoft\Service\ServiceManager;

class InitializeDatabaseConfigController extends AbstractConfigurationActionController
{
	/**
	 * @route literal /config-user-system-db-init
	 */
	public function configureUserSystemDatabaseAction() {
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");

		$sm = ServiceManager::generalServiceManager();
		$trial = NULL;
		$driverName = NULL;

		try {
			/** @var \PDO $trial */
			$trial = $sm->get( $sm->getParameter("pdo.primary") );
			$serviceName = $sm->getParameter("pdo.primary");
			$driverName = $trial->getAttribute(\PDO::ATTR_DRIVER_NAME);
		} catch (\Throwable $exception) {
			try {
				$trial = $sm->get( $sm->getParameter("pdo.secondary") );
				$serviceName = $sm->getParameter("pdo.secondary");
				$driverName = $trial->getAttribute(\PDO::ATTR_DRIVER_NAME);
			} catch (\Throwable $exception) {
				$serviceName = "";
			}
		}

		$ok = 0;
		if(is_file($file = "vendor/skyline-admin/pdo-initialisation/SQL/User-System/create.$driverName.sql")) {
			$ok = 1;

			$problem = 0;
			if(isset($_POST["init-db"])) {
				$this->verifyCSRF();

				$usr = $_POST["username"];
				if(!$usr)
					$problem = 1;
				else {
					$pwrd = $_POST["password"];
					if(!$pwrd) {
						$problem = 2;
					} else {
						if($pwrd != $_POST["passwordv"]) {
							$problem = 3;
						} else {
							$this->stopAction(function() use ($trial, $file, $usr, $pwrd, $sm) {
								$contents = file_get_contents($file);
								//$trial->exec($contents);

								/** @var UserTool $tool */
								$tool = $sm->userTool;


								var_dump($tool);

								//header("Location: /admin/config-user-system");
							});
						}
					}
				}
			}
		}

		error_clear_last();

		$this->renderModel([
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/config', $tm->translateGlobal("Configuration"))
				->addItem("/admin/config-user-system", $tm->translateGlobal("User System"))
			->addItem("", $tm->translateGlobal("Init Database")),
			'PROBLEM' => $problem,
			'PDO' => [
				'service' => $serviceName,
				'driver' => $driverName,
				"ok" => $ok
			],
			"ROOT_USER" => [
				'name' => $_POST["username"] ?? 'admin'
			]
		]);
		$this->renderTemplate('admin-main', [
			'Content' => 'config-us-init-data-base'
		]);
	}
}