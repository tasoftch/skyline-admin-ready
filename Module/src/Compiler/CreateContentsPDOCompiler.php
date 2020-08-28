<?php

namespace Skyline\Admin\Ready\Compiler;


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
		$ds = DIRECTORY_SEPARATOR;

		if(is_dir($dir = getcwd() . "{$ds}vendor{$ds}skyline-admin{$ds}pdo-initialisation{$ds}SQL{$ds}UI{$ds}Contents")) {
			$PDO = self::getContentsPDO($context);

			foreach(new \DirectoryIterator($dir) as $file) {
				if(preg_match("/^([a-z0-9_]+)\.sql$/i", $file->getBasename(), $ms)) {
					try {
						$PDO->exec("SELECT 1 FROM $ms[1]");
					} catch (\PDOException $exception) {
						$contents = file_get_contents( $file->getRealPath() );
						$PDO->exec($contents);
					}
				}
			}
		} else
			trigger_error("Package skyline-admin/pdo-initialisation not found", E_USER_WARNING);
	}
}