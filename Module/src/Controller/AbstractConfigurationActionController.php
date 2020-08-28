<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Kernel\Exception\SkylineKernelDetailedException;
use Skyline\Render\Info\RenderInfoInterface;
use Skyline\Router\Description\ActionDescriptionInterface;
use Symfony\Component\HttpFoundation\Request;

abstract class AbstractConfigurationActionController extends AbstractGeneralAdminController
{
	public static $checkLocalhostByAddress = true;
	public static $checkLocalhostByIp = false;

	public static $validIPAddress = "";

	public static function isLocalhost(Request $request): bool {
		 if(static::$checkLocalhostByAddress && static::$checkLocalhostByIp) {
			if( $request->getHost() == 'localhost' && $request->getClientIp() == '127.0.0.1' )
				return true;
			if(static::$validIPAddress) {
				return $request->getClientIp() == static::$validIPAddress;
			}
		} elseif(static::$checkLocalhostByAddress)
			return $request->getHost() == 'localhost';
		elseif(self::$checkLocalhostByIp)
			return $request->getClientIp() == '127.0.0.1';
		elseif(static::$validIPAddress) {
			return $request->getClientIp() == static::$validIPAddress;
		}

		// Skyline does not accept configuration request by default.
		return false;
	}

	protected function isAllowedOnLocalhostOnly(ActionDescriptionInterface $actionDescription, RenderInfoInterface$renderInfo): bool {
		return true;
	}

	public function performAction(ActionDescriptionInterface $actionDescription, RenderInfoInterface $renderInfo)
	{
		if($this->isAllowedOnLocalhostOnly($actionDescription, $renderInfo)) {
			if(!static::isLocalhost($this->getRequest())) {
				// Configuration is only allowed in a local network.
				// You should never use it in production!

				$e = new SkylineKernelDetailedException("Configuration only allowed on localhost!", 403);
				$e->setDetails("For security reasons the configuration can not be ran on a production server. Skyline CMS only accepts the configuration request, if the host's name is localhost or 127.0.0.1\n\nIf you got Skyline CMS directly as installer, you need to reconfigure the installer.");
				throw $e;
			}
		}
		parent::performAction($actionDescription, $renderInfo);
	}
}