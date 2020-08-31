<?php
namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\Ready\Helper\ParameterSetupHelper;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\CMS\Security\Authentication\AuthenticationServiceFactory;
use Skyline\CMS\Security\Identity\IdentityServiceFactory;
use Skyline\Expose\ExposedSymbolsManager;
use Skyline\Kernel\Config\MainKernelConfig;
use Skyline\PDO\MySQL;
use Skyline\Security\CSRF\CSRFToken;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Security\Encoder\BCryptPasswordEncoder;
use Skyline\Security\Encoder\HttpDigestA1Encoder;
use Skyline\Security\Encoder\HttpDigestResponseEncoder;
use Skyline\Security\Encoder\MessageDigestPasswordEncoder;
use Skyline\Security\Encoder\PlaintextPasswordEncoder;
use Skyline\Security\Encoder\PlaintextSaltPasswordEncoder;
use Skyline\Security\Exception\SecurityException;
use Skyline\Security\Identity\IdentityInterface;
use Skyline\Security\Identity\Provider\Session\RememberMeIdentityProvider;
use Skyline\Translation\TranslationManager;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Service\Config\AbstractFileConfiguration;
use TASoft\Service\Container\ConfiguredServiceContainer;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

/**
 * Class ConfigurationController
 * @package Skyline\Admin\Ready\Controller
 */
class ConfigurationController extends AbstractConfigurationActionController
{
	private $encodersMap = [
		1 => MessageDigestPasswordEncoder::class,
		2 => BCryptPasswordEncoder::class,
		4 => HttpDigestA1Encoder::class,
		8 => PlaintextSaltPasswordEncoder::class,
		16 => PlaintextPasswordEncoder::class
	];

	private $providerMap = [
		1 => IdentityServiceFactory::PROVIDER_NAME_HTTP_POST,
		2 => IdentityServiceFactory::PROVIDER_NAME_SESSION,
		4 => IdentityServiceFactory::PROVIDER_NAME_REMEMBER_ME,
		8 => IdentityServiceFactory::PROVIDER_NAME_HTTP_DIGEST,
		16 => IdentityServiceFactory::PROVIDER_NAME_HTTP_BASIC,
		32 => IdentityServiceFactory::PROVIDER_NAME_ANONYMOUS
	];

	private $validatorMap = [
		1 => AuthenticationServiceFactory::VALIDATOR_CLIENT_BRUTE_FORCE,
		2 => AuthenticationServiceFactory::VALIDATOR_SERVER_BRUTE_FORCE,
		4 => AuthenticationServiceFactory::VALIDATOR_AUTO_LOGOUT,
		8 => AuthenticationServiceFactory::VALIDATOR_PERMISSION_CHANGED,
		16 => AuthenticationServiceFactory::VALIDATOR_UPDATE_LAST_LOGIN_DATE
	];




	private function getOrderedPDOIfPossible(&$serviceName = NULL): ?PDO {
		$sm = ServiceManager::generalServiceManager();
		$trial = NULL;

		try {
			$trial = $sm->get( $sm->getParameter("pdo.primary") );
			$serviceName = $sm->getParameter("pdo.primary");
		} catch (\Throwable $exception) {
			try {
				$trial = $sm->get( $sm->getParameter("pdo.secondary") );
				$serviceName = $sm->getParameter("pdo.secondary");
			} catch (\Throwable $exception) {
				$serviceName = "";
			}
		}
		error_clear_last();
		return $trial;
	}

	/**
	 * @route literal /config
	 * @menu path /config/Configuration/Overview
	 * @menu action /admin/config
	 * @menu separator after
	 */
	public function configurationAction(Request $request) {
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");

		$this->renderTitle("Skyline :: Ready :: " . $cfgName = $tm->translate("Configuration"));
		$this->renderDescription($tm->translate("Adjust initial configuration to be able to launch Skyline CMS Administration panel."));

		$security = 0;
		$general = 1;

		$sm = ServiceManager::generalServiceManager();

		if(empty($encoders = $sm->getParameter('security.password-encoders.enabled'))) {
			$security |= 1;
			$general = 0;
		}
		if(in_array(PlaintextSaltPasswordEncoder::class, $encoders) || in_array(PlaintextPasswordEncoder::class, $encoders))
			$security |= 2;
		if(empty($identities = $sm->getParameter('security.identity.order'))) {
			$security |= 4;
			$general = 0;
		}
		if(in_array(IdentityServiceFactory::PROVIDER_NAME_HTTP_BASIC, $identities))
			$security |= 8;

		$userSystem = [];


		$dataBase = 0;
		$this->getOrderedPDOIfPossible($dataBase);
		if($dataBase === "") {
			$dataBase = -1;
			$general = 0;
		}

		$enabledProviders = $sm->getParameter("security.user-providers.enabled") ?: [];
		$single = array_search(AuthenticationServiceFactory::USER_PROVIDER_INITIAL_NAME, $enabledProviders);
		$multiple = array_search(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $enabledProviders);

		if($single !== false) {
			$userSystem["single"]["ok"] = $ok = $sm->getParameter("security.initial.username") && $sm->getParameter("security.initial.password");
			$userSystem["single"]["prio"] = $single+1;
		}

		if($multiple !== false) {
			$PDO = $this->PDO;
			try {
				$userSystem["multiple"]["ok"] = $PDO->selectFieldValue("SELECT count(id) AS C FROM SKY_USER", 'C') > 0;
				$userSystem["multiple"]["prio"] = $multiple+1;
			} catch (\Throwable $exception) {
				$userSystem["multiple"]["ok"] = false;
			}
		}

		$general = $general && @( $userSystem["single"]["ok"] || $userSystem["multiple"]["ok"] );

		if($general)
			touch(SkyGetPath("$(C)") . "/config_ok");
		elseif (file_exists($f = SkyGetPath("$(C)") . "/config_ok"))
			unlink($f);

		$this->renderModel([
			'BREAD' => (new Breadcrumb())->addItem("", $cfgName),
			'security' => $security,
			'user_system' => $userSystem,
			"data_base" => $dataBase,
			'general' => $general
		]);
		$this->renderTemplate("admin-config", [
			"Content" => 'configuration'
		]);
	}

	private function getOptionsFromList(array $optionList, array $list, int &$first = NULL): int {
		$opts = 0;
		foreach($list as $item) {
			if(($opt = array_search($item, $optionList)) !== false) {
				if(NULL === $first)
					$first = $opt;
				$opts |= $opt;
			}
		}
		return $opts;
	}

	private function applySecuritySettings(&$invalid) {
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;

		if(isset($_POST['apply-encryption'])) {
			if(@empty($_POST["encoder"])) {
				$invalid = $tm->translateGlobal("To properly configure your application, you must choose at least one password encoder.");
			}elseif(!in_array($_POST["main"], $_POST["encoder"])) {
				$invalid = $tm->translateGlobal("The choosen main password encoder must be present in selected encoders list.");
			} else {
				$main = $this->encodersMap[ $_POST['main'] ] ?? NULL;
				if(!$main) {
					$invalid = $tm->translateGlobal('Specified main encoder is not available.');
					return;
				}

				$encoders = [$main];

				foreach($_POST['encoder'] as &$encoder) {
					$encoder = $this->encodersMap[ $encoder ] ?? NULL;
					if(!$encoder) {
						$invalid = $tm->translateGlobal("Specified encoder is not available.");
						return;
					}

					if(!in_array($encoder, $encoders))
						$encoders[] = $encoder;
				}

				if(in_array(HttpDigestA1Encoder::class, $encoders) && !$_POST["realm"]) {
					$invalid = $tm->translateGlobal("HTTP Digest A1 encoder requires a realm string.");
					return;
				}

				if(in_array(PlaintextSaltPasswordEncoder::class, $encoders) && !$_POST["salt"]) {
					$invalid = $tm->translateGlobal("Salted password encoder requires a salt string.");
					return;
				}

				$paramSetup = new ParameterSetupHelper();

				$paramSetup->setParameter("security.password-encoders.enabled", $encoders, false);
				$paramSetup->setParameter("security.http.digest.realm", $_POST["realm"]);
				$paramSetup->setParameter("security.password.default-salt", $_POST["salt"]);
				$paramSetup->setParameter("security.bcrypt.cost", $_POST['cost']);

				$paramSetup->store();
			}
		} elseif(isset($_POST['apply-identity'])) {
			if(@empty($_POST['identity'])) {
				$invalid = $tm->translateGlobal("To properly configure your application you must specify at least one identity provider.");
				return;
			}

			$remember_me = false;
			foreach($_POST["identity"] as &$identity) {
				$identity = $this->providerMap[$identity] ?? NULL;
				if (!$identity) {
					$invalid = $tm->translateGlobal("One of your choosen identity provider is not supported.");
					return;
				}

				if($identity == IdentityServiceFactory::PROVIDER_NAME_REMEMBER_ME) {
					$remember_me = true;
				}
			}

			$paramSetup = new ParameterSetupHelper();

			$paramSetup->setParameter("security.identity.order", $_POST['identity'], false);

			$paramSetup->setParameter("security.http.digest.realm", $_POST["realm-digest"]);
			$paramSetup->setParameter("security.http.basic.realm", $_POST["realm-basic"]);
			$paramSetup->setParameter("security.user.anonymous", $_POST["anonymous-user"]);
			$paramSetup->setParameter("security.allows-remember-me", $remember_me ? 1 : 0);

			$paramSetup->setParameter("security.http.post.tokenName", $_POST["username_field"]);
			$paramSetup->setParameter("security.http.post.credentialName", $_POST["password_field"]);
			$paramSetup->setParameter("security.http.post.rememberMeName", $_POST["remember_me_field"]);

			$paramSetup->store();
		} elseif (isset($_POST["apply-validators"])) {
			foreach($_POST["validator"] as &$validator) {
				$validator = $this->validatorMap[$validator] ?? NULL;
				if (!$validator) {
					$invalid = $tm->translateGlobal("One of your choosen validator is not supported.");
					return;
				}
			}


			$paramSetup = new ParameterSetupHelper();

			$paramSetup->setParameter("security.validators.enabled", $_POST["validator"]);

			$paramSetup->setParameter("security.brute-force.client.maximal.attempts", $_POST["cb_attempts"]);
			$paramSetup->setParameter("security.brute-force.client.blocking.interval", $_POST["cb_block_time"]);

			$paramSetup->setParameter("security.brute-force.server.maximal.attempts", $_POST["sb_attempts"]);
			$paramSetup->setParameter("security.brute-force.server.blocking.interval", $_POST["sb_block_time"]);

			$paramSetup->setParameter("security.autologout.maximal-inactive", $_POST["autologout"]);

			$paramSetup->store();
		}
	}

	/**
	 * @route literal /config-security
	 * @menu path /config/Configuration/Security
	 * @menu action /admin/config-security
	 */
	public function securityAction() {
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;

		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");

		$this->renderTitle("Skyline :: Ready :: " . $cfgName = $tm->translate("Configuration"));
		$this->renderDescription($tm->translate("Adjust initial configuration to be able to launch Skyline CMS Administration panel."));

		$sm = ServiceManager::generalServiceManager();
		$problem = 0;
		if($_POST) {
			$this->verifyCSRF();
			$this->applySecuritySettings($problem);

			if(!$problem) {
				$_SESSION["updated"] = 1;
				$this->stopAction(function() {
					header("Location: " . htmlspecialchars( $_SERVER["REQUEST_URI"] ));
				});
			}
		}


		$this->renderModel([
			'ENCODERS' => [
				'encoders' => $this->getOptionsFromList($this->encodersMap, $sm->getParameter("security.password-encoders.enabled"), $mainEncoder),
				'main' => $mainEncoder,
				'realm' => $sm->getParameter('security.http.digest.realm'),
				'salt' => $sm->getParameter("security.password.default-salt"),
				'cost' => $sm->getParameter("security.bcrypt.cost")
			],
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/config', $tm->translateGlobal("Configuration"))
				->addItem("", $tm->translateGlobal("Security")),
			"PROBLEM" => $problem,
			'PROVIDERS' => [
				'providers' => $this->getOptionsFromList($this->providerMap, $sm->getParameter("security.identity.order")),
				'realm' => $sm->getParameter('security.http.basic.realm'),
				'anonymous' => $sm->getParameter('security.user.anonymous') ?: "",
				"username_field" => $sm->getParameter("security.http.post.tokenName"),
				"password_field" => $sm->getParameter("security.http.post.credentialName"),
				"remember_me_field" => $sm->getParameter("security.http.post.rememberMeName")
			],
			"VALIDATORS" => [
				'validators' => $this->getOptionsFromList($this->validatorMap, $sm->getParameter("security.validators.enabled")),
				"cb_attempts" => $sm->getParameter("security.brute-force.client.maximal.attempts"),
				'cb_block_time' => $sm->getParameter("security.brute-force.client.blocking.interval"),
				"sb_attempts" => $sm->getParameter("security.brute-force.server.maximal.attempts"),
				'sb_block_time' => $sm->getParameter("security.brute-force.server.blocking.interval"),
				'autologout' => $sm->getParameter("security.autologout.maximal-inactive")
			]
		]);
		$this->renderTemplate("admin-config", [
			"Content" => 'config-security'
		]);
	}

	private function applyUserSettings(&$problem) {
		if(isset($_POST["initialize-db"])) {
			$this->stopAction(function() {
				header("Location: /admin/config-user-system-db-init");
			});
		}

		$applyUserInput = function($input, $paramKey) use (&$parameters) {
			if($input != '@default')
				$parameters[$paramKey] = $input;
			elseif(isset($parameters[$paramKey]))
				unset($parameters[$paramKey]);
		};

		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$sm = ServiceManager::generalServiceManager();

		$disable = function($service) {
			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}

			if(!isset($parameters["security.user-providers.enabled"]))
				$parameters["security.user-providers.enabled"] = [];

			if(( $idx = array_search($service, $parameters["security.user-providers.enabled"])) !== false)
				unset($parameters["security.user-providers.enabled"][$idx]);

			$parameters["security.user-providers.enabled"] = array_values($parameters["security.user-providers.enabled"]);

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
			return;
		};

		if(isset($_POST["disable-initial"])) {
			$disable( AuthenticationServiceFactory::USER_PROVIDER_INITIAL_NAME );
			return;
		}

		if(isset($_POST["disable-db"])) {
			$disable( AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME );
			return;
		}

		if(isset($_POST["apply-initial"]) || isset($_POST['enable-initial'])) {
			$pwd = $_POST['password'];

			$usr = $_POST['username'];
			if(!$usr) {
				$problem = $tm->translateGlobal("The username must not be empty.");
				return;
			}

			if(strlen($pwd) < 8) {
				if(!$sm->getParameter("security.initial.password") || $pwd != '') {
					$problem = $tm->translateGlobal("The minimum password length needs to be 8 characters.");
					return;
				}
			}

			if($pwd != $_POST["passwordv"]) {
				$problem = $tm->translateGlobal("Password is not verified. There might be a typo.");
				return;
			}

			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}

			if(isset($_POST['enable-initial'])) {
				if(!isset($parameters["security.user-providers.enabled"]))
					$parameters["security.user-providers.enabled"] = [];

				if(( $idx = array_search(AuthenticationServiceFactory::USER_PROVIDER_INITIAL_NAME, $parameters["security.user-providers.enabled"])) !== false)
					unset($parameters["security.user-providers.enabled"][$idx]);

				array_unshift($parameters["security.user-providers.enabled"], AuthenticationServiceFactory::USER_PROVIDER_INITIAL_NAME);
			}

			$applyUserInput($usr, 'security.initial.username');
			if($pwd) {
				$cfg = SkyMainConfig()[ MainKernelConfig::CONFIG_SERVICES ][ AuthenticationServiceFactory::AUTHENTICATION_SERVICE ][ AbstractFileConfiguration::SERVICE_INIT_CONFIGURATION ] ?? NULL;

				$enabledEncoders = $sm->mapValue( $cfg[ AuthenticationServiceFactory::ENABLED_PASSWORD_ENCODERS ] );
				$passwordEncoders = $sm->mapArray( $cfg[AuthenticationServiceFactory::PASSWORD_ENCODERS] ?? []);

				foreach($enabledEncoders as $encoderClass) {
					$encoder = $passwordEncoders[ $encoderClass ] ?? NULL;
					if(!$encoder)
						throw new SecurityException("No password encoder specified for $encoderClass", 403);

					$cnt = new ConfiguredServiceContainer("", $encoder, $sm);
					$passwordEncoder = $cnt->getInstance();
					unset($cnt);
					break;
				}

				if(isset($passwordEncoder)) {
					$options = [
						HttpDigestA1Encoder::OPTION_USER_KEY => $usr
					];
					$password = $passwordEncoder->encodePassword($pwd, $options);
					if($password) {
						$applyUserInput($password, 'security.initial.password');
					} else {
						$problem = $tm->translateGlobal("The password encoder could not encode your password.");
						return;
					}
				} else {
					$problem = $tm->translateGlobal("The authentication service is not able to find a password encoder.");
					return;
				}
			}

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
		}

		if(isset($_POST["apply-membership"])) {
			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}

			$applyUserInput(($_POST['enable-verify']??0) ? 1 : 0, 'security.member-ship.verify-email');
			$applyUserInput( $ems = ($_POST["enable-membership"] ?? 0) ? 1 : 0, 'security.allows-new-membership');
			$applyUserInput(($_POST['membership-group'] ?? 0) * 1, 'security.member-ship.group');

			if($ems && $_POST['membership-group'] * 1 < 1) {
				$problem = $tm->translateGlobal("To enable membership you must specify a group");
				return;
			}

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
		}

		if(isset($_POST["apply-passwords"])) {
			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}


			$applyUserInput($_POST['enable-reset'] ? true : false, 'security.allows-password-reset');
			$applyUserInput($_POST['pw_cond_min_length'] * 1, 'security.password.reset.min-length');

			$applyUserInput($_POST['pw_cond_must_contain'], 'security.password.reset.must-contain');
			$applyUserInput($_POST['pw_cond_must_not_contain'], 'security.password.reset.must-not-contain');

			$pw_cond_active = 0;
			foreach(($_POST["pass_reset_conds"] ?? []) as $cond)
				$pw_cond_active |= $cond;
			$applyUserInput($pw_cond_active, 'security.password.reset.conditions');

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
		}

		if(isset($_POST["enable-db"])) {
			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}

			if(!isset($parameters["security.user-providers.enabled"]))
				$parameters["security.user-providers.enabled"] = [];

			if(( $idx = array_search(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $parameters["security.user-providers.enabled"])) !== false)
				unset($parameters["security.user-providers.enabled"][$idx]);

			array_unshift($parameters["security.user-providers.enabled"], AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME);

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
		}

		if(isset($_POST["delete-db"])) {
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

			if(is_file($file = "vendor/skyline-admin/pdo-initialisation/SQL/User-System/drop.$driverName.sql")) {
				$contents = file_get_contents($file);
				$trial->exec($contents);
			} else {
				$problem = $tm->translateGlobal("No clean up sql file found for requested driver.");
			}
		}
	}

	/**
	 * @route literal /config-user-system
	 * @menu path /config/Configuration/User System
	 * @menu action /admin/config-user-system
	 */
	public function userSystemConfigAction() {
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");
		$sm = ServiceManager::generalServiceManager();

		$enabledProviders = $sm->getParameter("security.user-providers.enabled") ?: [];

		$problem = 0;
		if($_POST) {
			$this->verifyCSRF();
			$this->applyUserSettings($problem);

			if(!$problem) {
				$_SESSION["updated"] = 1;
				$this->stopAction(function() {
					header("Location: " . htmlspecialchars( $_SERVER["REQUEST_URI"] ));
				});
			}
		}

		if($PDO = $this->getOrderedPDOIfPossible($serviceName)) {
			try {
				$usersCount = $PDO->selectFieldValue("SELECT count(id) AS C FROM SKY_USER", 'C');
			} catch (\Throwable $exception) {
				$usersCount = -1;
			}

			try {
				$groupsCount = iterator_to_array($PDO->select("SELECT * FROM SKY_GROUP ORDER BY name"));
			} catch (\Throwable $exception) {
				$groupsCount = [];
			}

			try {
				$rolesCount = $PDO->selectFieldValue("SELECT count(id) AS C FROM SKY_ROLE", 'C');
			} catch (\Throwable $exception) {
				$rolesCount = -1;
			}
		}

		$this->renderModel([
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			"PROBLEM" => $problem,
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/config', $tm->translateGlobal("Configuration"))
				->addItem("", $tm->translateGlobal("User System")),
			'INIT_USER' => [
				'name' => $sm->getParameter("security.initial.username"),
				"pwd" => $sm->getParameter("security.initial.password") ? 1 : 0,
				"enabled" => array_search(AuthenticationServiceFactory::USER_PROVIDER_INITIAL_NAME, $enabledProviders)
			],
			"MUL_USER" => [
				'service' => $serviceName,
				"enabled" => array_search(AuthenticationServiceFactory::USER_PROVIDER_DATABASE_NAME, $enabledProviders),
				"usersCount" => $usersCount ?? -1,
				"groupsCount" => $groupsCount ?? [],
				"rolesCount" => $rolesCount ?? -1,
				'pass_reset' => $sm->getParameter("security.allows-password-reset"),
				'sec_mem' => $sm->getParameter("security.allows-new-membership"),
				'sec_mem_grp' => $sm->getParameter("security.member-ship.group"),
				"sec_mem_vfy" => $sm->getParameter("security.member-ship.verify-email"),
				"pass_reset_conds" => $sm->getParameter("security.password.reset.conditions"),
				"pw_cond_min_length" => $sm->getParameter("security.password.reset.min-length"),
				"pw_cond_must_contain" => $sm->getParameter("security.password.reset.must-contain"),
				"pw_cond_must_not_contain" => $sm->getParameter("security.password.reset.must-not-contain"),
			]
		]);
		$this->renderTemplate("admin-config", [
			"Content" => 'config-user-system'
		]);
	}


	private function applyDatabaseSettings(&$problem) {
		$applyUserInput = function($input, $paramKey) use (&$parameters) {
			if($input !== '@default')
				$parameters[$paramKey] = $input;
			elseif(isset($parameters[$paramKey]))
				unset($parameters[$paramKey]);
		};

		if(isset($_POST['apply-db-order'])) {
			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}

			$applyUserInput($_POST['primary'], 'pdo.primary');
			$applyUserInput($_POST['secondary'], 'pdo.secondary');

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
		}

		if(isset($_POST["apply-mysql"])) {
			$parameters = [];
			if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$parameters = require $f;
			}

			$sm = ServiceManager::generalServiceManager();
			if(
				$sm->getParameter("pdo.mysql.host") != $_POST['host'] ||
				$sm->getParameter("pdo.mysql.username") != $_POST['username'] ||
				(
					$sm->getParameter("pdo.mysql.password") != $_POST['password'] &&
					$_POST["password"] != ""
				)
			) {
				$applyUserInput(false, 'pdo.mysql.verified');
			}

			$applyUserInput($_POST['host'], 'pdo.mysql.host');
			$applyUserInput($_POST['username'], 'pdo.mysql.username');

			if($_POST['password'])
				$applyUserInput($_POST['password'], 'pdo.mysql.password');

			if($_POST['db_name'])
				$applyUserInput($_POST['db_name'], 'pdo.mysql.dataBase');


			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");
		}

		if(isset($_POST['verify-mysql'])) {
			$sm = ServiceManager::generalServiceManager();
			$host = $sm->getParameter("pdo.mysql.host");

			if($fh = @fsockopen($host, 3306, $errno, $errstr, 1.0)) {
				fclose($fh);
				$problem = 0;
				try {
					$PDO = new PDO("mysql:host=$host", $sm->getParameter("pdo.mysql.username"), $sm->getParameter("pdo.mysql.password"));

					$parameters = [];
					if($f = SkyGetPath("$(C)/parameters.addon.config.php")) {
						$parameters = require $f;
					}

					$applyUserInput(true, 'pdo.mysql.verified');

					$parameters = var_export($parameters, true);
					file_put_contents(SkyGetPath("$(C)") . "/parameters.addon.config.php", "<?php\nreturn $parameters;");

					try {
						$db = $sm->getParameter("pdo.mysql.dataBase");
						if(preg_match("/^[a-z_0-9]+$/i", $db)) {
							$PDO->exec("USE $db");
						} else {
							$problem = -5;
						}
					} catch (\Throwable $e) {
						$problem = -2;
					}
				} catch (\Throwable $exception) {
					if(preg_match("/blocked/i", $exception->getMessage()))
						$problem=-3;
					else
						$problem = -1;
				}
			} else {
				error_clear_last();
				$problem = -4;
			}
		}
	}


	/**
	 * @route literal /config-data-base
	 * @menu path /config/Configuration/Data Base
	 * @menu action /admin/config-data-base
	 */
	public function configDataBaseAction() {
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");
		$sm = ServiceManager::generalServiceManager();

		$problem = 0;

		if($_POST) {
			$this->verifyCSRF();
			$this->applyDatabaseSettings($problem);

			if(!$problem) {
				$_SESSION["updated"] = 1;
				$this->stopAction(function() {
					header("Location: " . htmlspecialchars( $_SERVER["REQUEST_URI"] ));
				});
			}
		}

		/** @var ExposedSymbolsManager $esm */
		$esm = $this->exposedSymbolsManager;

		$db_types = [];
		foreach($esm->yieldClasses("PDO", false) as $class) {
			try {
				$service = $class::SERVICE_NAME;
				if($sm->serviceExists($service))
					$db_types[$service] = $class;
			} catch (\Throwable $e) {}
		}


		try {
			$trial = $sm->get( $sm->getParameter("pdo.primary") );
			if($trial instanceof MySQL) {
				$mysql_dbs = [];
				foreach($trial->select("SHOW DATABASES") as $db) {
					$mysql_dbs[] = end($db);
				}
			}
			$selected = ['s' => 'p', 'r1' => "", 'r2' => ""];
		} catch (\Throwable $exception) {
			$selected = ['s' => 's', 'r1' => $exception->getMessage(), 'r2' => ""];

			try {
				$trial = $sm->get( $sm->getParameter("pdo.secondary") );

				if($trial instanceof MySQL) {
					$mysql_dbs = [];
					foreach($PDO->select("SHOW DATABASES") as $db) {
						$mysql_dbs[] = end($db);
					}
				}
			} catch (\Throwable $exception) {
				$selected["s"] = -1;
				$selected["r2"] = $exception->getMessage();
			}
		}


		$this->renderModel([
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			"PROBLEM" => $problem,
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/config', $tm->translateGlobal("Configuration"))
				->addItem("", $tm->translateGlobal("Database")),
			'PDO' => [
				'db_types' => $db_types,
				"db_selected" => $selected,
				'primary' => $sm->getParameter("pdo.primary"),
				'secondary' => $sm->getParameter("pdo.secondary"),
				"mysql_db" => $sm->getParameter("pdo.mysql.dataBase"),
				"mysql_host" => $sm->getParameter("pdo.mysql.host"),
				"mysql_username" => $sm->getParameter("pdo.mysql.username"),
				"mysql_pass" => $sm->getParameter("pdo.mysql.password") ? 1 : 0,
				"mysql_dbs" => $mysql_dbs ?? [],
				"mysql_ok" => $sm->getParameter("pdo.mysql.verified")
			]
		]);
		$this->renderTemplate("admin-config", [
			"Content" => 'config-data-base'
		]);
	}
}