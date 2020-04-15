<?php
namespace Skyline\Admin\Ready\Controller;


use Skyline\Kernel\Exception\SkylineKernelDetailedException;
use Skyline\Security\Exception\SecurityException;
use Symfony\Component\HttpFoundation\Request;
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

		$this->renderTitle("Skyline :: Ready :: Configuration");
		$this->renderDescription("Adjust initial configuration to be able to launch Skyline CMS Administration panel.");
		
		$this->renderTemplate("admin-main", [
			"Content" => 'configuration'
		]);
	}
}