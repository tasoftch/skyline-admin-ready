<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\Ready\Helper\ParameterSetupHelper;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\Render\Template\CallbackTemplate;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Translation\TranslationManager;
use TASoft\Service\ServiceManager;

class ProjectConfigActionController extends AbstractConfigurationActionController
{

	private function applyProjectSettings(&$problem, \DOMDocument $DOM) {
		if(isset($_POST["apply-title"])) {
			foreach($DOM->getElementsByTagName("attr") as $attr) {
				if($attr->getAttribute("name") == 'title')
					$attr->textContent = $_POST["title"];
				if($attr->getAttribute("name") == 'description')
					$attr->textContent = $_POST["description"];

				if($attr->getAttribute("name") == 'HTTPS') {
					$attr->textContent = in_array('https', $_POST["flags"]??[]) ? 1 : 0;
				}
			}

			$flags = $_POST["flags"] ?? [];

			if(($idx = array_search('https', $flags)) !== false)
				unset($flags[$idx]);

			$paramHelper = new ParameterSetupHelper();
			$FLAGS = ServiceManager::generalServiceManager()->getParameter("project.compilation.flags");

			$FLAGS[ $_SESSION['mode'] ] = $flags;

			$paramHelper->setParameter("project.compilation.flags", $FLAGS);
			$paramHelper->setParameter("project.compilation.verbose", $_POST["verbose"] ?? 32);

			$paramHelper->store();
		}

		if(isset($_POST["apply-hosts"])) {
			/** @var \DOMElement $host */
			$CORS = $DOM->getElementsByTagName("CORS")->item(0);
			while ($CORS->hasChildNodes()){
				$CORS->removeChild($CORS->childNodes->item(0));
			}

			foreach($_POST["host"] as $host) {
				if($host["name"]) {
					$hx = $DOM->createElement("host");
					$hx->setAttribute('name', $host["name"]);
					if($lb = $host["label"])
						$hx->setAttribute('label', $lb);
					if($ax = $host["accepts"]) {
						foreach(explode(",", $ax) as $axh) {
							$hx->appendChild(
								$DOM->createElement('accepts', trim($axh))
							);
						}
					}
					$CORS->appendChild($hx);
				}
			}
		}

		$DOM->formatOutput = true;
		if($_SESSION["mode"] == 0)
			$DOM->save("dev-project.xml");
		elseif($_SESSION["mode"] == 2)
			$DOM->save("live-project.xml");
	}


	/**
	 * @route literal /config-project
	 * @menu path /config/Configuration/Project
	 * @menu action /admin/config-project
	 * @menu select %^/admin/config-project%i
	 */
	public function projectAction() {
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;
		/** @var TranslationManager $tm */
		$tm = $this->translationManager;
		$tm->setDefaultGlobalTableName("configuration");

		$paramHelper = new ParameterSetupHelper();

		session_start();
		if(!isset($_GET["mode"])) {
			$sm = ServiceManager::generalServiceManager();
			$_SESSION["mode"] = $sm->getParameter("project.compilation.mode") * 1;
		} elseif($_GET["mode"] == 2) {
			$_SESSION["mode"] = 2;
		} else
			$_SESSION["mode"] = 0;

		$paramHelper = new ParameterSetupHelper();
		$paramHelper["project.compilation.mode"] = $_SESSION["mode"];


		$paramHelper->store();

		error_clear_last();

		$problem = 0;

		$dom = new \DOMDocument("1.0", 'UTF-8');
		if($_SESSION["mode"] == 0) {
			if(is_file($f =getcwd() . "/dev-project.xml")) {
				$dom->load($f);
			} else {
				$problem = -1;
			}
		} elseif($_SESSION["mode"] == 2) {
			if(is_file($f =getcwd() . "/live-project.xml")) {
				$dom->load($f);
			} else {
				$problem = -1;
			}
		}

		if($_POST) {
			$this->verifyCSRF();
			$this->applyProjectSettings($problem, $dom);

			if(!$problem) {
				$_SESSION["updated"] = 1;
				$this->stopAction(function() {
					header("Location: " . htmlspecialchars( $_SERVER["REQUEST_URI"] ));
				});
			}
		}

		if($problem == 0) {
			$elements = $dom->getElementsByTagName("attr");
			/** @var \DOMElement $element */
			foreach($elements as $element) {
				if($element->getAttribute("name") == 'title')
					$title = $element->textContent;
				if($element->getAttribute("name") == 'description')
					$description = $element->textContent;
			}
			
			$elements = $dom->getElementsByTagName("host");
			foreach($elements as $element) {
				$host = [
					'name' => $element->getAttribute("name"),
					"label" => $element->getAttribute("label")
				];
				foreach($element->getElementsByTagName("accepts") as $accept) {
					$host["accept"][] = $accept->textContent;
				}
				$hosts[] = $host;
			}
		}

		$sm = ServiceManager::generalServiceManager();
		$FLAGS = ($sm->getParameter("project.compilation.flags") ?: []);
		$FLAGS = $FLAGS[ $_SESSION['mode'] ] ?? [];

		foreach($dom->getElementsByTagName("attr") as $attr) {
			if($attr->getAttribute("name") == 'HTTPS') {
				if($attr->textContent)
					$FLAGS[] = 'https';
				break;
			}
		}

		$this->renderModel([
			'CSRF' => $csrf->getToken('skyline-admin-csrf'),
			"PROBLEM" => $problem,
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/config', $tm->translateGlobal("Configuration"))
				->addItem("", $tm->translateGlobal("Project")),
			'PROJECT' => [
				'title' => $title ?? '',
				"description" => $description ?? '',
				"mode" => $_SESSION["mode"],
				"hosts" => $hosts ?? [],
				'verbose' => $sm->getParameter("project.compilation.verbose") ?? 32
			],
			"FLAGS" => $FLAGS
		]);
		$this->renderTemplate("admin-config", [
			"Content" => 'config-project'
		]);
	}

	/**
	 * @route literal /config-project-install-defaults
	 */
	public function installDefaultsAction() {
		$xml = file_get_contents("https://packages.skyline-cms.ch/project/dev-project.xml");
		file_put_contents("./dev-project.xml", $xml);

		$xml = file_get_contents("https://packages.skyline-cms.ch/project/live-project.xml");
		file_put_contents("./live-project.xml", $xml);

		$this->stopAction(function() {
			header("Location: /admin/config-project");
		});
	}
}