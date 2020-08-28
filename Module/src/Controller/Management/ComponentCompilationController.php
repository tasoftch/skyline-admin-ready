<?php

namespace Skyline\Admin\Ready\Controller\Management;


use Skyline\Compiler\CompilerContext;
use Skyline\HTML\Head\LinkCSS;
use Skyline\HTML\Head\PostScript;
use Skyline\HTML\Head\RemoteSourceLink;
use Skyline\HTML\Head\RemoteSourceScript;
use TASoft\Service\ServiceManager;
use TASoft\Util\PDO;
use function Skyline\Admin\Ready\Controller\print_out;

class ComponentCompilationController
{
	public static function componentPreCompiler(CompilerContext $context) {
		/** @var PDO $PDO */
		$PDO = AbstractContentManagementActionController::getContentsPDO($dir);

		$path = SkyGetLocation("/", 'Config') . DIRECTORY_SEPARATOR . 'components.ui.config.php';

		$components = [];
		foreach($PDO->select("SELECT
COMPONENT.id,
       COMPONENT.name,
       shorthand,
       slug,
       className,
       mimeType,
       cross_origin,
       integrity,
       relation,
       media,
       CMP.name AS dependency
FROM COMPONENT
JOIN COMPONENT_ITEM ON COMPONENT_ITEM.component = COMPONENT.id
JOIN COMPONENT_ITEM_TYPE ON type = COMPONENT_ITEM_TYPE.id
LEFT JOIN COMPONENT_DEPENDENCY ON COMPONENT_DEPENDENCY.component = COMPONENT.id
LEFT JOIN COMPONENT AS CMP ON dependency = CMP.id
WHERE COMPONENT.internal = 0
ORDER BY COMPONENT.name") as $record) {
			$name = $record["name"];
			$sh = $record["shorthand"];

			$components[$name][$sh]['class'] = $record["className"];
			$components[$name][$sh]['slug'] = $record["slug"];
			$components[$name][$sh]['origin'] = $record["cross_origin"];
			$components[$name][$sh]['itgy'] = $record["integrity"];
			$components[$name][$sh]['media'] = $record["media"];
			$components[$name][$sh]['mime'] = $record["mimeType"];
			$components[$name][$sh]['rel'] = $record["relation"];
			$dep = $record["dependency"];
			if($dep && !in_array($dep, $components[$name]['@require'] ?? []))
				$components[$name]['@require'][] = $dep;
		}

		$contents = "<?php
/**
 * BSD 3-Clause License
 *
 * Copyright (c) 2019, TASoft Applications
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 *  Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 
 return [
 ";

		foreach($components as $name => $component) {
			$contents .= "\t'$name' => [\n";
			if(isset($component["@require"])) {
				$contents .= "\t\t'@require' => [\n";
				foreach($component["@require"] as $dep) {
					$contents .= "\t\t\t'$dep',\n";
				}
				$contents .= "\t\t],\n";
				unset($component["@require"]);
			}

			foreach($component as $shorthand => $info) {
				$contents .= "\t\t'$shorthand' => [\n";
				$contents .= "\t\t\t'class' => " . var_export($info["class"], true) . ",\n";
				$contents .= "\t\t\t'arguments' => [\n";
				$contents .= implode(",\n", static::serializeSourceArguments($info['class'], $info, "\t\t\t\t"));
				$contents .= "\n\t\t\t]\n\t\t],\n";
			}

			$contents .= "\t]\n";
		}
		$contents.="];";

		file_put_contents($path, trim($contents));
	}

	protected static function serializeSourceArguments($class, $info, string $indent) {
		$arguments[] = "$indent'{$info['slug']}'";

		$writeIntegrity = function() use ($info, &$arguments, $indent) {
			if(@$info["origin"] || @$info['itgy']) {
				$arguments[] = @$info['itgy'] ? "$indent'{$info['itgy']}'" : "{$indent}NULL";
				if($info["origin"])
					$arguments[] = "$indent'{$info['origin']}'";
			}
		};

		switch ($class) {
			case PostScript::class:
			case RemoteSourceScript::class:
				$arguments[] = "$indent'{$info['mime']}'";
				$writeIntegrity();
				break;
			case LinkCSS::class:
				$arguments[] = "$indent'{$info['media']}'";
				$writeIntegrity();
				break;
			case RemoteSourceLink::class:
				$arguments[] = "$indent'{$info['rel']}'";
				$arguments[] = "$indent'{$info['mime']}'";
				$writeIntegrity();
				break;
		}

		return $arguments;
	}

	public static function componentPostCompiler(CompilerContext $context) {
		/** @var PDO $PDO */
		$PDO = AbstractContentManagementActionController::getContentsPDO($dir);
		$PDO->exec("UPDATE COMPONENT SET modified = 0 WHERE internal = 0");
	}
}