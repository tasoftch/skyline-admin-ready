<?php

namespace Skyline\Admin\Ready\Compiler;


use Skyline\Admin\PDO\ContentsInstaller;
use Skyline\Compiler\CompilerContext;
use Skyline\PDO\SQLite;

class CreateContentsPDOCompiler extends \Skyline\Compiler\AbstractCompiler
{
	public static function getContentsPDO(CompilerContext $context): SQLite {
		static $PDO;
		if(!$PDO) {
			$ui = $context->getSkylineAppDataDirectory() . DIRECTORY_SEPARATOR . 'UI';
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

	/**
	 * @inheritDoc
	 */
	public function compile(CompilerContext $context)
	{
		$PDO = self::getContentsPDO($context);
		ContentsInstaller::init($PDO);
	}
}