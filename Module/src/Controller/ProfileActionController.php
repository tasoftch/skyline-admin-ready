<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\Tool\UserTool;
use Skyline\CMS\Security\UserSystem\User;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Translation\TranslationManager;
use TASoft\Util\PDO;

/**
 * Class ProfileActionController
 * @package Skyline\Admin\Ready\Controller
 * @role SKYLINE.ADMIN
 */
class ProfileActionController extends AbstractGeneralAdminController
{

	private function applyProfile(&$problem, UserTool $tool) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		if(isset($_POST["apply-name"])) {
			$user = $this->getUser();
			if($user instanceof User) {
				/** @var PDO $PDO */
				$PDO = $this->PDO;
				$uid = $user->getId();

				try {
					$PDO->inject("UPDATE SKY_USER SET prename = ?, email = ?, surname = ? WHERE id = $uid")->send([
						$_POST["my-prename"],
						$_POST["my-email"],
						$_POST["my-surname"]
					]);
				} catch (\PDOException $exception) {
					// Email address is not unique
					$problem = $tm->translateGlobal("Email address is already in use.");
				}

			} else {
				$problem = $tm->translateGlobal("Your user is not part of the Skyline CMS's multiple user-system. So this properties can not be defined.");
			}
		}
	}

	/**
	 * @route literal /profile
	 */
	public function profileAction() {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$problem = 0;
		$PROFILE = [];

		$user = $this->getUser();
		if($user instanceof User) {
			$PROFILE = [
				'id' => $user->getId(),
				'email' => $user->getEmail(),
				'prename' => $user->getName(),
				"surname" => $user->getSurname(),
				"username" => $user->getUsername()
			];
		} else {
			$PROFILE = [
				"id" => -1,
				'username' => $user->getUsername()
			];
		}


		if($_POST) {
			$this->verifyCSRF();
			$this->applyProfile($problem, $uTool);

			if(session_status() != PHP_SESSION_ACTIVE)
				session_start();

			if(!$problem) {
				$_SESSION["updated"] = 1;
				$this->stopAction(function() {
					header("Location: " . htmlspecialchars( $_SERVER["REQUEST_URI"] ));
				});
			}
		}

		$user = $uTool->getUser();


		$this->renderModel([
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			'BREAD' => (new Breadcrumb())
				->addItem('', $tm->translateGlobal("Profile")),
			"PROBLEM" => $problem,
			'PROFILE' => $PROFILE
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'profile'
		]);
	}

	/**
	 * @route literal /settings
	 */
	public function settingsAction() {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$this->renderModel([
			'BREAD' => (new Breadcrumb())
				->addItem('', $tm->translateGlobal("Settings"))
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'settings'
		]);
	}
}