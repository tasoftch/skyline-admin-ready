<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\PDO\UserSystemInstaller;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\Admin\Tool\UserTool;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Security\Role\RoleInterface;
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
		if(UserSystemInstaller::canInit($trial)) {
			$ok = 1;

			$problem = 0;
			if(isset($_POST["init-db"])) {
				$this->verifyCSRF();

				$usr = $_POST["username"];
				if(!$usr)
					$problem = 1;
				else {
					if($_POST["email"] && !filter_var($email = $_POST["email"], FILTER_VALIDATE_EMAIL)) {
						$problem = 5;
					} else {
						$pwrd = $_POST["password"];
						if(!$pwrd) {
							$problem = 2;
						} else {
							if($pwrd != $_POST["passwordv"]) {
								$problem = 3;
							} else {
								$this->stopAction(function() use ($trial, $usr, $pwrd, $sm, $email) {
									UserSystemInstaller::init($trial);

									$uTool = new UserTool($trial, true);
									$attributes = [
										UserTool::ATTRIBUTE_EMAIL => $email,
										UserTool::ATTRIBUTE_INTERNAL => true
									];
									if(@$_POST["entitlement"] == 2) {
										$attributes[UserTool::ATTRIBUTE_ROLES] = [
											RoleInterface::ROLE_ROOT
										];
									} else {
										$attributes[UserTool::ATTRIBUTE_GROUPS] = [
											1 // Administrator Group ID
										];
									}

									$uTool->createUser($usr, $pwrd, $attributes);
									header("Location: /admin/config-user-system");
								});
							}
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
			'PROBLEM' => $problem ?? NULL,
			'PDO' => [
				'service' => $serviceName,
				'driver' => $driverName,
				"ok" => $ok
			],
			"ROOT_USER" => [
				'name' => $_POST["username"] ?? 'admin',
				'email' => $_POST["email"] ?? ''
			]
		]);
		$this->renderTemplate('admin-main', [
			'Content' => 'config-us-init-data-base'
		]);
	}
}