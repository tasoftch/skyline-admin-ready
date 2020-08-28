<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\Ready\Service\EmailContentsService;
use Skyline\Admin\Tool\BruteForceTool;
use Skyline\Admin\Tool\UserTool;
use Skyline\CMS\Security\Authentication\AuthenticationService;
use Skyline\CMS\Security\Authentication\AuthenticationServiceFactory;
use Skyline\CMS\Security\Identity\IdentityServiceFactory;
use Skyline\CMS\Security\Tool\PasswordResetTool;
use Skyline\Render\Template\MarkerTemplate;
use Skyline\Router\Description\RegexActionDescription;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\IdentityService;
use Skyline\Translation\TranslationManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

class AdministrationActionController extends AbstractGeneralAdminController
{
	public static $passwordResetSuccessTarget = '/admin';
	public static $membershipCreatedTarget = '/admin';

	/**
	 * @param Response $response
	 * @route literal /logout
	 */
	public function logoutAction(Response $response) {
		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$uTool->logoutIdentity();

		$this->stopAction(function() use ($response) {
			$response->sendHeaders();
			header("Location: /admin");
		});
	}

	public static function checkPW(int $conditions, $pw, ServiceManager $sm): int {
		if($conditions & 1) {
			if(!$pw)
				return 1;
		}
		if($conditions & 2) {
			if(strlen($pw) < $sm->getParameter("security.password.reset.min-length"))
				return 2;
		}
		if($conditions & 4) {
			if(!preg_match("/[0-9]+/", $pw))
				return 4;
		}
		if($conditions & 8) {
			if(!preg_match("/[A-Z]+/", $pw))
				return 8;
		}
		if($conditions & 16) {
			if(!preg_match("/[a-z]+/", $pw))
				return 16;
		}

		if($conditions >= 32) {
			$match = function($string , $special) {
				for($e=0;$e<strlen($string);$e++) {
					if(strpos($special, $string[$e]) !== false)
						return true;
				}
				return false;
			};

			if($conditions & 32) {
				$special = "+-*/?!$;:_%&@(){}[]#=";

				if(strlen($pw) < strlen($special)) {
					if(!$match($pw, $special))
						return 32;
				} else {
					if(!$match($special, $pw))
						return 32;
				}
			}
		}


		if($conditions >= 64) {
			$expander = function ($string) {
				$range = "abcdefghojklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				$fin = "";
				for($e=0;$e<strlen($string);$e++) {
					$char = $string[$e];
					if($char == '\\') {
						$fin .= $string[++$e];
						continue;
					}
					if($char == '-' && $string[$e-1] !== "") {
						if(($idx = strpos($range, $string[$e-1])) === false) {
							trigger_error("Invalid range start " . $string[$e-1], E_USER_NOTICE);
						} else {
							$end = $string[++$e];
							if(($endIDX = strpos($range, $end)) === false) {
								trigger_error("Invalid range end $end", E_USER_NOTICE);
								$e--;
							} else {
								for($idx++;$idx<=$endIDX;$idx++) {
									$fin.=$range[$idx];
								}
								continue;
							}
						}
					}
					$fin .= $char;
				}
				return $fin;
			};

			if($conditions & 64) {
				$special = $expander($sm->getParameter("security.password.reset.must-contain"));
				if(strlen($pw) < strlen($special)) {
					if(!$match($pw, $special))
						return 64;
				} else {
					if(!$match($special, $pw))
						return 64;
				}
			}

			if($conditions & 128) {
				$special = $expander($sm->getParameter("security.password.reset.must-not-contain"));
				if(strlen($pw) < strlen($special)) {
					if($match($pw, $special))
						return 128;
				} else {
					if($match($special, $pw))
						return 128;
				}
			}
		}

		return 0;
	}

	/**
	 * @route regex %^/?forgot-password/reset/(.+)$%i
	 */
	public function forgotPasswordResetAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("admin");

		$this->renderTitle("Skyline :: Ready :: " . $tm->translate("Define New Password"));
		$this->renderDescription($tm->translate("Here you can define a new password for your account."));

		if(!ServiceManager::generalServiceManager()->getParameter("security.allows-password-reset")) {
			throw new SecurityException("Password reset is not enabled in this application", 403);
		}

		/** @var PasswordResetTool $pwrt */
		$pwrt = $this->get( PasswordResetTool::SERVICE_NAME );
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		$sm = ServiceManager::generalServiceManager();

		$token = $actionDescription->getCaptures()[1];
		$error = -1;

		$MODEL = [
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			'pw_conds' => $pw_conds = $sm->getParameter("security.password.reset.conditions") * 1
		];

		if($pwrt->validatePasswordResetToken($token, $user, $error)) {
			$MODEL["OK"] = true;
			$MODEL["username"] = $user->getUsername();
		} else {
			$MODEL["username"] = '';
		}
		$MODEL["ERROR"] = $error;
		$MODEL["PROBLEM"] = 0;

		if(isset($_POST["reset-passwd"])) {
			$pw = $_POST["password"];
			$MODEL["PROBLEM"] = $this->checkPW($pw_conds, $pw, $sm);

			if(!$MODEL["PROBLEM"]) {
				$pwv = $_POST["passwordv"];
				if($pw != $pwv)
					$MODEL["PROBLEM"] = -1;
				else {
					if($pwrt->validatePasswordResetToken($token, $user) && $pwrt->updatePassword($token, $pw)) {
						/** @var UserTool $uTool */
						$uTool = $this->get(UserTool::SERVICE_NAME);
						$uTool->loginWithCredentials($user->getUsername(), $pw);

						$this->stopAction(function() {
							/** @var Response $response */
							$response = $this->response;
							$response->sendHeaders();

							header("Location: " . self::$passwordResetSuccessTarget);
						});
					} else {
						$MODEL["PROBLEM"] = -2;
					}
				}
			}
		}

		$this->renderModel($MODEL);
		$this->renderTemplate("main", [
			"Content" => 'reset-password'
		]);
	}

	/**
	 * @route literal /forgot-password/request-reset-link
	 */
	public function forgotPasswordAction() {
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("admin");

		$this->renderTitle("Skyline :: Ready :: " . $tm->translate("Forgot Password"));
		$this->renderDescription($tm->translate("You forgot your password? That's no problem. So Skyline CMS hashes passwords before storing them. Hashing means a one way direction encryption of your original password.<br>
	We can not tell you what password you've set, but we can send you an email including a reset link."));
		
		
		if(!ServiceManager::generalServiceManager()->getParameter("security.allows-password-reset")) {
			throw new SecurityException("Password reset is not enabled in this application", 403);
		}
		
		/** @var BruteForceTool $bft */
		$bft = $this->get(BruteForceTool::SERVICE_NAME);

		// Avoid attacker to send various emails to a member.
		$bft->limitAccess(3, 60);

		if(isset($_POST["reset-password"])) {
			$success = -1;

			/** @var PasswordResetTool $tool */
			$tool = $this->get(PasswordResetTool::SERVICE_NAME);
			$token = $tool->makePasswordResetToken($_POST['username']);

			if($token->isSuccessful()) {
				/** @var EmailContentsService $ecService */
				$ecService = $this->get(EmailContentsService::SERVICE_NAME);

				$mail = $ecService->renderTemplate("reset-password", [
					'User' => htmlspecialchars($_POST["username"]),
					'AppName' => ServiceManager::generalServiceManager()->getParameter("AppTitle"),
					"Date" => date("d.m.Y G:i:s"),
					"ResetLink" => $this->buildURL("Admin", '/forgot-password/reset/' . $token->getToken()),
					"TeamName" => 'Skyline CMS Admin Panel'
				]);

				$user = $token->getUser();
				if(method_exists($user, 'getEmail')) {
					$address = $user->getEmail();
					if(method_exists($user, 'getFullName'))
						$name = $user->getFullName();
					elseif(method_exists($user, 'getName') && method_exists($user, 'getSurName'))
						$name = $user->getName() . " " . $user->getSurName();
					else
						$name = $user->getUsername();

					/** @var TranslationManager $tm */
					$tm = $this->get(TranslationManager::SERVICE_NAME);
					if($this->sendAdminEmail("$name <$address>", utf8_decode( $tm->translateGlobal("Password Reset Request") ), utf8_decode($mail), $ecService->isHTMLTemplate('reset-password'))) {
						$success = 1;
					}
				}
			}
		}

		$this->renderModel([
			'SUCCESS' => $success ?? 0
		]);

		$this->renderTemplate("main", [
			"Content" => 'forgot-password'
		]);
	}

	/**
	 * @route literal /sign-in/register-new-membership
	 */
	public function registerNewMembership() {
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("admin");
		$sm = ServiceManager::generalServiceManager();

		$this->renderTitle("Skyline :: Ready :: " . $tm->translate("Register New Membership"));
		$this->renderDescription($tm->translate("Welcome to the Skyline CMS Admin panel crew. We invite you to enter your contact data and then you will get access to our administration."));

		if(!ServiceManager::generalServiceManager()->getParameter("security.allows-new-membership")) {
			throw new SecurityException("Registering for new membership is not enabled in this application", 403);
		}

		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		$VALIDATION = [
			'username' => [
				'class' => ''
			],
			'email' => ['class' => ''],
			"prename" => ['class' => ''],
			'surname' => ['class' => ''],
		];

		$invalidate = function($field, $feedback) use (&$VALIDATION, &$is_valid) {
			$is_valid = false;
			$VALIDATION[$field]["class"] = ' is-invalid';
			$VALIDATION[$field]["feedback"] = $feedback;
		};

		$verifyEmail = $sm->getParameter("security.member-ship.verify-email");
		$PROBLEM = 0;

		if(isset($_POST["apply-membership"])) {
			$getPDO = function() use ($sm) {
				if(class_exists(PDO::class) && $sm->serviceExists( 'PDO' )) {
					$PDO = $sm->get("PDO");
					return $PDO instanceof \PDO ? $PDO : NULL;
				}
				return NULL;
			};

			$this->verifyCSRF();
			$is_valid = true;
			$VALIDATION["username"]["class"] = ' is-valid';
			$VALIDATION["email"]["class"] = ' is-valid';
			$VALIDATION["prename"]["class"] = ' is-valid';
			$VALIDATION["surname"]["class"] = ' is-valid';

			/** @var AuthenticationService $as */
			$as = $this->get(AuthenticationServiceFactory::AUTHENTICATION_SERVICE);

			if(strlen($usr = $_POST["username"]) < 4) {
				$invalidate("username", $tm->translateGlobal("Username must be at least %d characters long.", NULL, 4));
			} else {
				if($as->getUserProvider()->loadUserWithToken( $usr )) {
					$invalidate("username", $tm->translateGlobal("Username already exists."));
				}
			}

			if(!strlen($email = $_POST["email"])) {
				$invalidate("email", $tm->translateGlobal("Email address is a required fieldname."));
			} else {
				if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
					$invalidate("email", $tm->translateGlobal("Email address is not valid."));
				} else {
					if($PDO = $getPDO()) {
						try {
							$stmt = $PDO->prepare("SELECT id FROM SKY_USER WHERE email = ?");
							if($stmt->execute([$email])) {
								if($stmt->fetch()) {
									$invalidate("email", 'Email address is already occupied by this application.');
								}
							}
						} catch (\PDOException $exception) {}
					}
				}
			}

			if(!$verifyEmail) {
				$PROBLEM = $this->checkPW($sm->getParameter("security.password.reset.conditions") * 1, $_POST["password"], $sm);
				if($PROBLEM)
					$is_valid = false;
				else {
					if($_POST["password"] != $_POST["passwordv"]) {
						$PROBLEM = -1;
						$is_valid = false;
					}
				}
			}
		}

		$SUCCESS = 0;

		if($is_valid) {
			/** @var UserTool $uTool */
			$uTool = $this->get(UserTool::SERVICE_NAME);
			
			if($verifyEmail) {
				$token = $uTool->makeAccountRequest($usr, $email, 'skyline-create-membership', [
					'prename' => $_POST["prename"],
					'surname' => $_POST["surname"]
				], 900);
				
				/** @var EmailContentsService $ecService */
				$ecService = $this->get(EmailContentsService::SERVICE_NAME);

				$mail = $ecService->renderTemplate("verify-member-ship", [
					'User' => htmlspecialchars( ($_POST["prename"] || $_POST["surname"]) ? trim("{$_POST["prename"]} {$_POST["surname"]}") : $_POST["username"] ),
					'AppName' => $appTitle = ServiceManager::generalServiceManager()->getParameter("AppTitle"),
					"Username" => htmlspecialchars($_POST["username"]),
					"Email" => htmlspecialchars($_POST["email"]),
					"ResetLink" => $this->buildURL("Admin", "/member-ship/activate/$token"),
					"TeamName" => 'Skyline CMS Admin Panel'
				]);

				/** @var TranslationManager $tm */
				$tm = $this->get(TranslationManager::SERVICE_NAME);
				$name = htmlspecialchars( ($_POST['prename'] || $_POST["surname"]) ? trim("{$_POST["prename"]} {$_POST["surname"]}"): $_POST["username"] );
				$address = htmlspecialchars($_POST["email"]);

				echo $mail;

				if($this->sendAdminEmail("$name <$address>", utf8_decode( $tm->translateGlobal("$appTitle :: Welcome! :: Activate your membership") ), utf8_decode($mail), $ecService->isHTMLTemplate('verify-member-ship'))) {
					$SUCCESS = 1;
				} else
					$SUCCESS = -1;
			} else {
				// Register and login
				
				$attributes = [
					UserTool::ATTRIBUTE_EMAIL => $email,
					UserTool::ATTRIBUTE_PRENAME => $_POST["prename"],
					UserTool::ATTRIBUTE_SURNAME => $_POST["surname"],
					UserTool::ATTRIBUTE_GROUPS => [
						$sm->getParameter("security.member-ship.group")
					]
				];
				
				if($uTool->createUser($usr, $_POST["password"], $attributes, true)) {
					$this->stopAction(function() {
						/** @var Response $response */
						$response = $this->response;
						$response->sendHeaders();

						header("Location: " . self::$membershipCreatedTarget);
					});
				} else
					$SUCCESS = -1;
			}
		}

		$this->renderModel([
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			"VALIDATION" => $VALIDATION,
			'verify_email' => $verifyEmail,
			'PROBLEM' => $PROBLEM,
			"SUCCESS" => $SUCCESS
		]);
		$this->renderTemplate("main", [
			"Content" => 'new-member-ship'
		]);
	}

	/**
	 * @route regex %^/?member-ship/activate/(.+)$%i
	 */
	public function activateNewMembership(RegexActionDescription $actionDescription) {
		if(!ServiceManager::generalServiceManager()->getParameter("security.allows-new-membership")) {
			throw new SecurityException("Registering for new membership is not enabled in this application", 403);
		}

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		switch (@$uTool->decodeAccountRequest($actionDescription->getCaptures()[1], 'skyline-create-membership', $username, $email, $attributes)) {
			case 0:
				error_clear_last();
				throw new SecurityException("Skyline CMS could not parse your activation link. Please make sure to copy it fully to the browser's address bar", 403);
			case -1:
				error_clear_last();
				throw new SecurityException("This activation link is not valid anymore. Please require a new membership", 403);
			default:
				break;
		}

		if($uTool->existsUsername( $username )) {
			throw new SecurityException("We are very sorry but the username you've desired was registered during your activation. Please go back and choose another username. Thank you", 403);
		}
		if($uTool->existsEmail($email))
			throw new SecurityException("We are very sorry but the email address you've desired was registered during your activation. Please go back and choose another email address. Thank you", 403);

		$sm = ServiceManager::generalServiceManager();

		$attributes = [
			UserTool::ATTRIBUTE_EMAIL => $email,
			UserTool::ATTRIBUTE_PRENAME => $attributes['prename'] ?? '',
			UserTool::ATTRIBUTE_SURNAME => $attributes["surname"] ?? '',
			UserTool::ATTRIBUTE_GROUPS => [
				$sm->getParameter("security.member-ship.group")
			]
		];

		if($uTool->createUser($username, md5(microtime()), $attributes)) {
			/** @var PasswordResetTool $pwrt */
			$pwrt = $this->get(PasswordResetTool::SERVICE_NAME);

			$token = $pwrt->makePasswordResetToken($username);
			if($token && $token->isSuccessful()) {
				$this->stopAction(function() use ($token) {
					/** @var Response $response */
					$response = $this->response;
					$response->sendHeaders();

					header("Location: " . $this->buildURL("Admin", '/forgot-password/reset/' . $token->getToken()));
				});
			} else {
				throw new SecurityException("Could not create password reset link. Please contact the application's administrator", 403);
			}
		} else
			throw new SecurityException("Could not create user. Please contact the application's administrator", 403);
	}
}