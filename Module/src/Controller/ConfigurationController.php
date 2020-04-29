<?php
namespace Skyline\Admin\Ready\Controller;


use Skyline\CMS\Security\Exception\CSRFMissmatchException;
use Skyline\Kernel\Exception\SkylineKernelDetailedException;
use Skyline\Security\CSRF\CSRFToken;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Security\Exception\SecurityException;
use Skyline\Translation\TranslationManager;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;

class ConfigurationController extends AbstractGeneralAdminController
{
	public static $checkLocalhostByAddress = true;
	public static $checkLocalhostByIp = false;

	protected function isLocalhost(Request $request): bool {
		if(static::$checkLocalhostByAddress && static::$checkLocalhostByIp) {
			return $request->getHost() == 'localhost' && $request->getClientIp() == '127.0.0.1';
		} elseif(static::$checkLocalhostByAddress)
			return $request->getHost() == 'localhost';
		elseif(self::$checkLocalhostByIp)
			return $request->getClientIp() == '127.0.0.1';

		// Skyline does not accept configuration request by default.
		return false;
	}

	/**
	 * @route literal /config
	 */
	public function configurationAction(Request $request) {
		if(!$this->isLocalhost($request)) {
			// Configuration is only allowed in a local network.
			// You should never use it in production!

			$e = new SkylineKernelDetailedException("Configuration only allowed on localhost!", 403);
			$e->setDetails("For security reasons the configuration can not be ran on a production server. Skyline CMS only accepts the configuration request, if the host's name is localhost or 127.0.0.1\n\nIf you got Skyline CMS directly as installer, you need to reconfigure the installer.");
			throw $e;
		}
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		$sm = ServiceManager::generalServiceManager();

		$validParameterKeys = array_keys( require SkyGetPath("$(C)/parameters.config.php"));

		if($request->request->has("updateDB")) {
			$token = $csrf->getToken("skyline-config-csrf");
			if(!$csrf->isTokenValid( new CSRFToken("skyline-config-csrf", $request->request->get("skyline-config-csrf")) )) {
				throw new CSRFMissmatchException("CSRF token missmatch!", 403);
			}

			$addon = [];
			if($path = SkyGetPath("$(C)/parameters.addon.config.php")) {
				$addon = require $path;
			}

			foreach($request->request as $key => $value) {
				$key = str_replace('_', '.', $key);
				if(in_array($key, $validParameterKeys) && $value)
					$addon[$key] = $value;
			}

			file_put_contents($path, "<?php\nreturn " . var_export($addon, true) . ";");
			header("Location: " . $_SERVER["REQUEST_URI"]);
			exit();
		}

		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");

		$this->renderTitle("Skyline :: Ready :: " . $tm->translate("Configuration"));
		$this->renderDescription($tm->translate("Adjust initial configuration to be able to launch Skyline CMS Administration panel."));

		$model = [];

		$model["CSRF"] = $csrf->getToken("skyline-config-csrf");

		$model["PDO"]["primary"] = $sm->getParameter("pdo.primary");
		$model["PDO"]["secondary"] = $sm->getParameter("pdo.secondary");
		$model["PDO"]["prefix"] = $prefix = $sm->getParameter("pdo.prefix");
		$model["PDO"]["sqlite_filename"] = $sm->getParameter("pdo.sqlite.filename");
		$model["PDO"]["mysql_db"] = $sm->getParameter("pdo.mysql.dataBase");
		$model["PDO"]["mysql_username"] = $sm->getParameter("pdo.mysql.username");
		$model["PDO"]["mysql_pass"] = $sm->getParameter("pdo.mysql.password") ? 1 : 0;
		$model["PDO"]["sqlite_ok"] = is_file($sm->getParameter("pdo.sqlite.filename"));

		$model["CNT"]["ok"] = false;

		try {
			/** @var PDO $PDO */
			$PDO = $sm->get("MySQL");
			$model["PDO"]["mysql_ok"] = true;

			$dbs = [];
			foreach($PDO->select("SHOW DATABASES") as $db) {
				$dbs[] = end($db);
			}

			$model["PDO"]["mysql_dbs"] = $dbs;
			$model["CNT"]["ok"] = false;

			foreach($PDO->select("SHOW TABLES") as $table) {
				$table = end($table);
				if($table == "{$prefix}USER") {
					$model["CNT"]["ok"] = true;
					break;
				}
			}
		} catch (\Throwable $e) {
			$model["PDO"]["mysql_ok"] = false;
		}

		try {
			$model["PDO"]["instance"] = $this->PDO;
		} catch (\Throwable $e) {
			$model["PDO"]["instance"] = false;
		}

		$model["PDO"]["ok"] = $model["PDO"]["sqlite_ok"] && $model["PDO"]["mysql_ok"];

		$this->renderModel($model);
		$this->renderTemplate("admin-main", [
			"Content" => 'configuration'
		]);
	}
}