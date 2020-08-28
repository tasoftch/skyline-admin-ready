<?php

namespace Skyline\Admin\Ready\Service;


use Skyline\Render\Template\MarkerTemplate;
use Skyline\Render\Template\TemplateInterface;

class EmailContentsService extends \TASoft\Service\AbstractService
{
	const SERVICE_NAME = 'emailContentsService';

	private $searchPaths = [];
	private $templates = [];
	private $isHTML = [];

	public function __construct(...$searchPaths)
	{
		foreach(array_reverse($searchPaths) as $dir) {
			if(is_dir($dir))
				$this->searchPaths[] = $dir;
		}
	}

	/**
	 * Tries to load a template from the given email template directories.
	 *
	 * @param string $templateName
	 * @return TemplateInterface|null
	 */
	public function getMarkerTemplate(string $templateName): ?TemplateInterface {
		if(!isset($this->templates[$templateName])) {
			$this->templates[$templateName] = false;

			foreach($this->searchPaths as $dir) {
				if(is_file($f = "$dir/$templateName.txt")) {
					$this->templates[$templateName] = new MarkerTemplate(file_get_contents($f));
					$this->isHTML[$templateName] = false;
					break;
				}
				if(is_file($f = "$dir/$templateName.html")) {
					$this->templates[$templateName] = new MarkerTemplate(file_get_contents($f));
					$this->isHTML[$templateName] = true;
					break;
				}
			}
		}

		return $this->templates[$templateName] ?: NULL;
	}

	/**
	 * Checks if a given template name can be delivered as HTML email
	 *
	 * @param string $templateName
	 * @return bool
	 */
	public function isHTMLTemplate(string $templateName): bool {
		return $this->isHTML[$templateName] ?? false;
	}

	/**
	 * @param string|MarkerTemplate $template
	 * @param array $model
	 * @return string
	 */
	public function renderTemplate($template, array $model = []): string {
		if(is_string($template))
			$template = $this->getMarkerTemplate($template);

		if($template instanceof TemplateInterface) {
			$cb = $template->getRenderable();
			return call_user_func($cb, $model);
		}
		return "";
	}
}