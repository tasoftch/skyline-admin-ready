<?php

namespace Skyline\Admin\Ready\Compiler;


use Skyline\Compiler\CompilerContext;
use Skyline\HTML\Head\LinkCSS;
use Skyline\HTML\Head\RemoteSourceLink;

class SynchronizeComponentsCompiler extends \Skyline\Compiler\AbstractCompiler
{

	/**
	 * @inheritDoc
	 */
	public function compile(CompilerContext $context)
	{
		$config = realpath($context->getSkylineAppDataDirectory() . "/Compiled/components.config.php");
		if($config) {
			$config = require $config;
			$dependencies = $config["@"] ?? [];
			$links = $config["#"] ?? [];
			unset($config["@"]);
			unset($config["#"]);

			$PDO = CreateContentsPDOCompiler::getContentsPDO($context);
			$componentMap = [];

			$linkDependencies = [];

			foreach($config as $componentName => $parts) {
				if(!$PDO->selectFieldValue("SELECT count(id) AS C FROM COMPONENT WHERE name = ?", 'C', [$componentName])) {
					$PDO->inject("INSERT INTO COMPONENT (name, internal) VALUES (?, 1)")->send([
						$componentName
					]);
					$CID = $PDO->lastInsertId("COMPONENT");

					$componentMap[$componentName] = $CID;

					foreach($parts as $partName => $partInfo) {
						if($class = $partInfo["class"] ?? NULL) {
							$arguments = $partInfo["arguments"] ?? [];

							if(count($arguments)) {
								$TYPE_ID = max(1, $PDO->selectFieldValue("SELECT id FROM COMPONENT_ITEM_TYPE WHERE className = ?", 'id', [$class]) * 1);

								$cross_origin = NULL;
								$integrity = NULL;
								$media = NULL;
								$local_file = NULL;
								$TYPE_ID = 0;


								switch ($class) {
									case RemoteSourceLink::class:
										list(,,$mime,$cross_origin, $integrity) = $arguments;
										$TYPE_ID = max(1, $PDO->selectFieldValue("SELECT id FROM COMPONENT_ITEM_TYPE WHERE className = ? AND mimeType = ?", 'id', [$class, $mime]) * 1);
										break;
									case LinkCSS::class: list(,$media,$cross_origin, $integrity) = $arguments; break;
									default:
										list(,,$cross_origin, $integrity) = $arguments;
								}

								if(!$TYPE_ID)
									$TYPE_ID = max(1, $PDO->selectFieldValue("SELECT id FROM COMPONENT_ITEM_TYPE WHERE className = ?", 'id', [$class]) * 1);

								if($target = $links[ strtolower($arguments[0]) ] ?? false) {
									$local_file = $target;
								}

								$PDO->inject("INSERT INTO COMPONENT_ITEM (component, shorthand, slug, type, cross_origin, integrity, media, local_file) VALUES ($CID, ?, ?, $TYPE_ID, ?, ?, ?, ?)")->send([
									$partName,
									$arguments[0],
									$cross_origin,
									$integrity,
									$media,
									$local_file ? 1 : 0
								]);

								$linkDependencies[$componentName] = $dependencies[$componentName] ?? [];
							}
						}
					}
				}
			}

			if($linkDependencies) {
				$inj = $PDO->inject("INSERT INTO COMPONENT_DEPENDENCY (component, dependency) VALUES (?, ?)");

				foreach($linkDependencies as $component => $dependencies) {
					if($CID = $componentMap[$component]) {
						foreach($dependencies as $dependency) {
							if($DID = $componentMap[$dependency]) {
								$inj->send([
									$CID,
									$DID
								]);
							}
						}
					}
				}
			}
		}
	}
}