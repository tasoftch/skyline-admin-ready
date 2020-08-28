<?php

namespace Skyline\Admin\Ready\Controller\Management;

use Skyline\Admin\Ready\Helper\ComponentTypeMapper;
use Skyline\Admin\Ready\Helper\OptionLabelWithDescription;
use Skyline\CMS\Security\Tool\UserTool;
use Skyline\Compiler\CompilerContext;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\HTML\Form\Control\AbstractControl;
use Skyline\HTML\Form\Control\Button\ButtonControl;
use Skyline\HTML\Bootstrap\Form\Control\option\MultipleOptionListControl;
use Skyline\HTML\Form\Control\Button\CheckboxControl;
use Skyline\HTML\Form\Control\File\FileInputControl;
use Skyline\HTML\Form\Control\Option\OptionListControl;
use Skyline\HTML\Form\Control\Option\PopUpControl;
use Skyline\HTML\Form\Control\Option\Provider\PlainGeneratorProvider;
use Skyline\HTML\Form\Control\Text\TextAreaControl;
use Skyline\HTML\Form\Control\Text\TextFieldControl;
use Skyline\HTML\Form\FormElement;
use Skyline\HTML\Form\SecureFormElement;
use Skyline\HTML\Form\Validator\CallbackValidator;
use Skyline\HTML\Form\Validator\Condition\CallbackCondition;
use Skyline\HTML\Form\Validator\NotEmptyValidator;
use Skyline\HTML\Form\Validator\UniqueSQLColumnValidator;
use Skyline\Router\Description\RegexActionDescription;
use Skyline\Translation\TranslationManager;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Util\ValueInjector;

/**
 * Class ComponentManagementActionController
 * @package Skyline\Admin\Ready\Controller\Management
 * @role SKYLINE.ADMIN
 */
class ComponentManagementActionController extends AbstractContentManagementActionController
{
	/**
	 * @route literal /contents/components
	 * @menu path /admin/Contents/Components
	 * @menu action /admin/contents/components
	 * @menu select %^/?admin/contents/components%i
	 * @role SKYLINE.CONTENTS.EDIT.VIEW
	 */
	public function showComponentsAction() {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$PDO = $this->getContentsPDO($cdir);

		$components = [];
		$hasChanges = 0;

		foreach($PDO->select("SELECT
COMPONENT.id,
       COMPONENT.name,
       COMPONENT.internal,
       COMPONENT_ITEM.id AS cid,
       shorthand,
       slug,
       local_file,
       caption,
       icon,
       CMP.name AS dependency,
       COMPONENT.modified
FROM COMPONENT
LEFT JOIN COMPONENT_ITEM ON COMPONENT_ITEM.component = COMPONENT.id
LEFT JOIN COMPONENT_ITEM_TYPE ON type = COMPONENT_ITEM_TYPE.id
LEFT JOIN COMPONENT_DEPENDENCY ON COMPONENT_DEPENDENCY.component = COMPONENT.id
LEFT JOIN COMPONENT AS CMP ON dependency = CMP.id
ORDER BY COMPONENT.internal, COMPONENT.name COLLATE NOCASE") as $record) {
			$id = $record["id"];
			$pid = $record["cid"];

			$components[$id]['name'] = $record["name"];
			$components[$id]['internal'] = $record["internal"];
			if($components[$id]['modified'] = $record["modified"])
				$hasChanges = 1;

			if($pid) {
				$components[$id]['parts'][$pid]['shorthand'] = $record["shorthand"];
				$components[$id]['parts'][$pid]['slug'] = $record["slug"];
				$components[$id]['parts'][$pid]['local_file'] = $record["local_file"];
				$components[$id]['parts'][$pid]['caption'] = $record["caption"];
				$components[$id]['parts'][$pid]['icon'] = $record["icon"];
			}
			if($dep = $record["dependency"]) {
				if(!isset($components[$id]['dependencies']) || !in_array($dep, $components[$id]['dependencies']))
					$components[$id]['dependencies'][] = $dep;
			}
		}

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken('compile-csrf'),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('', $tm->translateGlobal("Components")),
			'COMPONENTS' => $components,
			"CHANGES" => $hasChanges,
			"CAN" => [
				'COMPILE' => $uTool->hasRole("SKYLINE.CONTENTS.COMPILE")
			]
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'components'
		]);
	}

	/**
	 * @route regex %^/?contents/components/display/(\d+)%i
	 * @role SKYLINE.CONTENTS.EDIT.VIEW
	 */
	public function displayComponentAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$PDO = static::getContentsPDO($cdir);

		$cid = $actionDescription->getCaptures()[1];

		$COMPONENT = [];
		foreach($PDO->select("SELECT
       COMPONENT.name,
       COMPONENT.internal,
       COMPONENT_ITEM.id AS cid,
       shorthand,
       slug,
       local_file,
       caption,
       icon,
       media,
       local_file,
       mimeType,
       cross_origin,
       integrity,
       CMP.name AS dependency
FROM COMPONENT
LEFT JOIN COMPONENT_ITEM ON COMPONENT_ITEM.component = COMPONENT.id
LEFT JOIN COMPONENT_ITEM_TYPE ON type = COMPONENT_ITEM_TYPE.id
LEFT JOIN COMPONENT_DEPENDENCY ON COMPONENT_DEPENDENCY.component = COMPONENT.id
LEFT JOIN COMPONENT AS CMP ON dependency = CMP.id
WHERE COMPONENT.id = $cid") as $record) {
			$pid = $record["cid"];

			$COMPONENT['name'] = $record["name"];
			$COMPONENT['internal'] = $record["internal"];
			if($pid) {
				$COMPONENT['parts'][$pid]['shorthand'] = $record["shorthand"];
				$COMPONENT['parts'][$pid]['slug'] = $record["slug"];
				$COMPONENT['parts'][$pid]['local_file'] = $record["local_file"];
				$COMPONENT['parts'][$pid]['caption'] = $record["caption"];
				$COMPONENT['parts'][$pid]['icon'] = $record["icon"];
				$COMPONENT['parts'][$pid]['mimeType'] = $record["mimeType"];
				$COMPONENT['parts'][$pid]['cross_origin'] = $record["cross_origin"];
				$COMPONENT['parts'][$pid]['media'] = $record["cross_origin"];
				$COMPONENT['parts'][$pid]['local_file'] = "";

				if($lf = $record["local_file"]) {
					$lf = explode(getcwd(), $lf);
					$COMPONENT['parts'][$pid]['local_file'] = array_pop($lf);
				}

				$COMPONENT['parts'][$pid]['integrity'] = "";
				if(($pos = strpos($int = $record["integrity"], '-')) !== false) {
					$COMPONENT['parts'][$pid]['integrity'] = substr($int, 0, $pos);
					$COMPONENT['parts'][$pid]['integrity_str'] = substr($int, $pos+1);
				}
			}

			if($dep = $record["dependency"]) {
				if(!isset($COMPONENT['dependencies']) || !in_array($dep, $COMPONENT['dependencies']))
					$COMPONENT['dependencies'][] = $dep;
			}
		}


		if(!$COMPONENT) {
			$this->stopAction(function() {
				header("Location: /admin/contents/components");
			});
		}

		$this->renderModel([
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('/admin/contents/components', $tm->translateGlobal("Components"))
				->addItem('', $tm->translateGlobal("Display %s", NULL, $COMPONENT['name'])),
			'COMPONENT' => $COMPONENT
		]);

		$this->renderTemplate("admin-main", [
			"Content" => 'component-display'
		]);
	}

	/**
	 * @route regex %^/?contents/components/edit/(\d+)%i
	 * @role SKYLINE.CONTENTS.EDIT
	 */
	public function editComponent(RegexActionDescription $actionDescription, Request $request) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$PDO = $this->getContentsPDO($cdir);

		$CID = $actionDescription->getCaptures()[1];

		$form = new FormElement("");

		$textField = new TextFieldControl("nname", 'nname');
		$textField->addValidator(new NotEmptyValidator());
		$textField->addValidator(new CallbackValidator(function($value) use ($PDO, $CID) {
			return $PDO->selectFieldValue("SELECT count(id) AS C FROM COMPONENT WHERE name = ? AND id != $CID", 'C', [$value]) ? false : true;
		}));
		$form->appendElement($textField);

		$textView = new TextAreaControl('desc', 'desc');
		$form->appendElement($textView);

		$options = new MultipleOptionListControl('dependencies', 'dependencies');
		$options->setOptionProvider(new PlainGeneratorProvider(
			array_map(function($record) {
				if($record["description"])
					$record["label"] = new OptionLabelWithDescription($record["label"], $record["description"]);
				return $record;
			}, iterator_to_array($PDO->select("SELECT description, name AS label, id FROM COMPONENT WHERE id != $CID ORDER BY name COLLATE NOCASE")))
		));
		$options->optionListClass = 'form-group';
		$options->optionItemClass = 'form-check';

		$form->appendElement($options);

		$form->setActionControl( new ButtonControl("apply-information") );

		$COMPONENT = ['name' => '', 'id' => 0];
		if($CID > 0) {
			foreach($PDO->select("SELECT
       COMPONENT.name,
       COMPONENT.description,
       COMPONENT.internal,
       COMPONENT_ITEM.id AS cid,
       shorthand,
       slug,
       local_file,
       caption,
       icon,
       media,
       local_file,
       mimeType,
       cross_origin,
       integrity,
       dependency
FROM COMPONENT
LEFT JOIN COMPONENT_ITEM ON COMPONENT_ITEM.component = COMPONENT.id
LEFT JOIN COMPONENT_ITEM_TYPE ON type = COMPONENT_ITEM_TYPE.id
LEFT JOIN COMPONENT_DEPENDENCY ON COMPONENT_DEPENDENCY.component = COMPONENT.id
WHERE COMPONENT.id = $CID") as $record) {
				if($record['internal'])
					break;

				$pid = $record["cid"];

				$COMPONENT['id'] = $CID;
				$COMPONENT['name'] = $record["name"];
				$COMPONENT['description'] = $record["description"];

				if($pid) {
					$COMPONENT['parts'][$pid]['shorthand'] = $record["shorthand"];
					$COMPONENT['parts'][$pid]['slug'] = $record["slug"];
					$COMPONENT['parts'][$pid]['local_file'] = $record["local_file"];
					$COMPONENT['parts'][$pid]['caption'] = $record["caption"];
					$COMPONENT['parts'][$pid]['icon'] = $record["icon"];
					$COMPONENT['parts'][$pid]['mimeType'] = $record["mimeType"];
					$COMPONENT['parts'][$pid]['cross_origin'] = $record["cross_origin"];
					$COMPONENT['parts'][$pid]['media'] = $record["media"];
					$COMPONENT['parts'][$pid]['local_file'] = "";

					if($lf = $record["local_file"]) {
						$lf = explode(getcwd(), $lf);
						$COMPONENT['parts'][$pid]['local_file'] = array_pop($lf);
					}

					$COMPONENT['parts'][$pid]['integrity'] = "";
					if(($pos = strpos($int = $record["integrity"], '-')) !== false) {
						$COMPONENT['parts'][$pid]['integrity'] = substr($int, 0, $pos);
						$COMPONENT['parts'][$pid]['integrity_str'] = substr($int, $pos+1);
					}
				}


				if($dep = $record["dependency"]) {
					if(!isset($COMPONENT['dependencies']) || !in_array($dep, $COMPONENT['dependencies']))
						$COMPONENT['dependencies'][] = $dep;
				}
			}


			if(!$COMPONENT['id']) {
				$this->stopAction(function() {
					header("Location: /admin/contents/components");
				});
			}
		}


		$state = $form->prepareWithRequest($request);
		if($state == FormElement::FORM_STATE_VALID) {
			$this->verifyCSRF();

			$data = $form->getData();

			$PDO->transaction(function() use (&$CID, $data, $PDO) {
				if($CID == 0) {
					$PDO->inject("INSERT INTO COMPONENT (name, description) VALUES (?, ?)")->send([
						$data["nname"],
						$data["desc"]
					]);

					$CID = $PDO->lastInsertId("COMPONENT");
				} else {
					$PDO->inject("UPDATE COMPONENT SET name = ?, description = ? WHERE id = $CID")->send([
						$data["nname"],
						$data["desc"]
					]);
				}

				$PDO->exec("DELETE FROM COMPONENT_DEPENDENCY WHERE component = $CID");

				if($deps = $data["dependencies"] ?? 0) {
					$inj = $PDO->inject("INSERT INTO COMPONENT_DEPENDENCY (component, dependency) VALUES ($CID, ?)");

					foreach($deps as $dep) {
						$inj->send([$dep]);
					}
				}

				$PDO->exec("UPDATE COMPONENT SET modified = 1 WHERE id = $CID");
			});

			$this->stopAction(function() use ($CID) {
				header("Location: /admin/contents/components/edit/$CID");
			});
		} elseif($state == FormElement::FORM_STATE_NONE) {
			$form->setData([
				'nname' => $COMPONENT['name'],
				'desc' => $COMPONENT["description"]??'',
				'dependencies' => $COMPONENT["dependencies"] ?? ''
			]);
		}

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('/admin/contents/components', $tm->translateGlobal("Components"))
				->addItem('', $tm->translateGlobal($CID ? "Edit %s" : 'Create New Component', NULL, $COMPONENT['name'])),
			'COMPONENT' => $COMPONENT,
			"FORMULA" => $form
		]);

		$this->renderTemplate("admin-main", [
			"Content" => 'component-edit'
		]);
	}

	/**
	 * @route regex %^/?contents/components/add-(local|remote)/(\d+)%i
	 * @role SKYLINE.CONTENTS.EDIT
	 */
	public function addLocalComponentAction(RegexActionDescription $actionDescription, Request $request) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$PDO = static::getContentsPDO($cdir);

		$CID = $actionDescription->getCaptures()[2];
		$LOCAL = strtolower($actionDescription->getCaptures()[1]) == 'local';

		$COMPONENT = $PDO->selectOne("SELECT id, name FROM COMPONENT WHERE id = $CID");
		if(!$COMPONENT['id']) {
			$this->stopAction(function() {
				header("Location: /admin/contents/components");
			});
		}

		$form = new FormElement("", 'POST', '', true);
		$list = new PopUpControl("src-kind", 'src-kind');
		$EDITING = $LOCAL ? 1 : 2;

		$list->setOptionProvider(new PlainGeneratorProvider(
			$PDO->select("SELECT caption AS label, id FROM COMPONENT_ITEM_TYPE WHERE editable & $EDITING = $EDITING")
		));
		$list->addValidator(new NotEmptyValidator());
		$form->appendElement($list);


		$fieldMap = [];
		foreach ($PDO->select("SELECT DISTINCT item, field FROM COMPONENT_ITEM_TYPE_FIELD_Q") as $record) {
			$fieldMap[ (int) $record["item"] ][] = (int) $record["field"];
		}


		$useURIValidationCondition = new CallbackCondition(function() use ($list, $fieldMap) {
			return in_array(2, $fieldMap[$list->getValue()] ?? [2]);
		});
		$useURLValidationCondition = new CallbackCondition(function() use ($list, $fieldMap) {
			return !in_array(2, $fieldMap[$list->getValue()] ?? [2]);
		});


		$textField = new TextFieldControl("shorthand", 'shorthand');
		$textField->addValidator(new NotEmptyValidator());
		$textField->addValidator(new CallbackValidator(function($VALUE) use($PDO, $CID) {
			// Check if shorthand is unique by the given component
			return $PDO->selectFieldValue("SELECT count(id) AS C FROM COMPONENT_ITEM WHERE shorthand = ? AND component = $CID", 'C', [$VALUE]) ? false : true;
		}));
		$form->appendElement($textField);

		$uriTextField = new TextFieldControl("uri", 'uri');
		$uriTextField->addValidator(new NotEmptyValidator($useURIValidationCondition));
		$uriTextField->addValidator( (new CallbackValidator(function($VALUE) use (&$path) {
			if(!$path)
				$path = SkyGetLocation("/", 'Components');
			return !is_dir( $path . DIRECTORY_SEPARATOR . $VALUE );
		}, $useURIValidationCondition))->setValidatorName('is_dir') );
		$uriTextField->addValidator( new CallbackValidator(function($VALUE) use($PDO) {
			// Check if shorthand is unique by the given component
			return $PDO->selectFieldValue("SELECT count(id) AS C FROM COMPONENT_ITEM WHERE slug = ?", 'C', ["/Public/" . $VALUE]) ? false : true;
		}, $useURIValidationCondition) );
		$form->appendElement($uriTextField);

		$textField = new PopUpControl("cross_origin", 'cross_origin');
		$textField->setOption('anonymous', $tm->translateGlobal("Anonymous"));
		$textField->setOption('use-credentials', $tm->translateGlobal("With Credentials"));
		$textField->setNullPlaceholder($tm->translateGlobal("None"));

		$form->appendElement($textField);

		$textField = new TextFieldControl("media", 'media');
		$textField->setPlaceholder($tm->translateGlobal("All"));
		$form->appendElement($textField);

		$textField = new TextFieldControl("integrity", 'integrity');
		$textField->setPlaceholder($tm->translateGlobal("ex: sha384-....."));
		$form->appendElement($textField);

		$list = new PopUpControl('integrity_enc', 'integrity_enc');
		$list->setOptionProvider(new PlainGeneratorProvider(iterator_to_array((function() {
			foreach(hash_algos() as $algo) {
				if(preg_match("/^(md|sha)/i", $algo))
					yield ['label' => $algo, 'id' => $algo];
			}
		})())));
		$form->appendElement($list);

		$file_input = new FileInputControl('local_file', 'local_file');
		$form->appendElement($file_input);

		$textField = new TextFieldControl("url", 'url');
		$textField->addValidator(new NotEmptyValidator($useURLValidationCondition));
		$form->appendElement($textField);

		$list = new MultipleOptionListControl("options_local", 'options_local');
		$list->setOption('igty', new OptionLabelWithDescription(
			$tm->translateGlobal("Generate Integrity"),
			$tm->translateGlobal("Create integrity hash after adding the source to your application.")
		));
		$list->setOption('srch', new OptionLabelWithDescription(
			$tm->translateGlobal("Search Existing File"),
			$tm->translateGlobal("Tries to find an existing file under the passed URI instead of uploading.")
		));
		$form->appendElement($list);

		$list = new MultipleOptionListControl("options_remote", 'options_remote');
		$list->setOption('vfy', new OptionLabelWithDescription(
			$tm->translateGlobal("Check URL"),
			$tm->translateGlobal("Checks, if the passed URL returns a response that can be included in your application.")
		));
		$list->setOption('chitgy', new OptionLabelWithDescription(
			$tm->translateGlobal("Check Integrity"),
			$tm->translateGlobal("Checks, if the integrity checksum matches.")
		));
		$form->appendElement($list);

		$form->setActionControl( new ButtonControl("create") );

		$URL_CODE = 0;
		if(($state = @$form->prepareWithRequest($request)) == FormElement::FORM_STATE_VALID) {
			$data = $form->getData();
			if($LOCAL) {
				$validator = NULL;
				$validatorf = NULL;

				$data["url"] = '/Public/' . $data["uri"];

				if($data["options_local"] && in_array('srch', $data["options_local"])) {
					$dir = SkyGetLocation("/", "Components");
					if(!is_file( $dir . DIRECTORY_SEPARATOR . $data["uri"] ))
						$validator = (new CallbackValidator(function(){}))->setValidatorName('invalid-uri-not-exists');
					else {
						$type = ComponentTypeMapper::findComponentTypeFromExtension($data["url"], false);

						if($type)
							$data["src-kind"] = $type;
					}
				} else {
					if(isset($_FILES["local_file"]) && ($file = $_FILES["local_file"]) && $file['error'] == 0) {
						$dir = SkyGetLocation("/", "Components");
						if(is_file( $target = $dir . DIRECTORY_SEPARATOR . $data["uri"] ))
							$validator = (new CallbackValidator(function(){}))->setValidatorName('invalid-uri-exists');
						else {
							$type = ComponentTypeMapper::findComponentTypeFromContent( $file["type"] );
							if(!$type)
								$type = ComponentTypeMapper::findComponentTypeFromExtension($data["url"]);

							if(!$type) {
								$validatorf = (new CallbackValidator(function(){}))->setValidatorName('invalid-type');
							} else {
								if($data["src-kind"] == 12)
									$data["src-kind"] = $type;

								mkdir(dirname($target), 0777, true);

								if(!move_uploaded_file($file["tmp_name"], $target)) {
									$validatorf = (new CallbackValidator(function(){}))->setValidatorName('copy-error');
								} else {
									if($data["options_local"] && in_array('igty', $data["options_local"])) {
										$algo = $data["integrity_enc"];
										$data["integrity"] = "$algo-" . base64_encode( hash_file($algo, $target, true) );
									}
								}
							}
						}
					} else {
						$validatorf = (new CallbackValidator(function(){}))->setValidatorName('expecting-file');
					}
				}

				if($validator) {
					$vi = new ValueInjector($uriTextField, AbstractControl::class);
					$vi->valid = false;
					$vi->stoppedValidator = $validator;
					goto form_continue;
				}

				if($validatorf) {
					$vi = new ValueInjector($file_input, AbstractControl::class);
					$vi->valid = false;
					$vi->stoppedValidator = $validatorf;
					goto form_continue;
				}
			} else {
				$data["url"] = 'https://' . $data["url"];
				$ctx = stream_context_create([
					'http' => [
						'method' => 'HEAD'
					]
				]);

				if($data["src-kind"] == 13) {
					// Remote icon
					$headers = @get_headers($data["url"], 1, $ctx);
					$type = ComponentTypeMapper::findComponentTypeFromContent($headers["Content-Type"]??"", false);
					if(!$type)
						$type = ComponentTypeMapper::findComponentTypeFromExtension($data["url"], false);

					if($type)
						$data["src-kind"] = $type;
				}

				if($data["options_remote"] && in_array('vfy', $data["options_remote"])) {
					if(!@$headers)
						$headers = @get_headers($data["url"], 1, $ctx);

					$validator = NULL;

					if(preg_match("/(\d{3})\s*(.+)$/i", @$headers[0], $ms)) {
						$URL_CODE = $ms[0];
						if($ms[1] != 200)
							$validator = (new CallbackValidator(function(){}))->setValidatorName('invalid-url-code');
						elseif (in_array('chitgy', $data["options_remote"]) && ($itgy = $data["integrity"])) {
							foreach(hash_algos() as $algo) {
								if(stripos($itgy, $algo) === 0) {
									$hash = substr($itgy, strlen($algo)+1);
									break;
								}
							}
							if(isset($hash)) {
								$contents = file_get_contents( $data["url"]);
								$ref = base64_encode(hash($algo, $contents, true));

								if($hash != $ref) {
									$validator = (new CallbackValidator(function(){}))->setValidatorName('invalid-url-itgy');
								}
							}
						}
					} else
						$validator = (new CallbackValidator(function(){}))->setValidatorName('invalid-url');

					if($validator) {
						$vi = new ValueInjector($textField, AbstractControl::class);
						$vi->valid = false;
						$vi->stoppedValidator = $validator;
						goto form_continue;
					}
				}
			}

			error_clear_last();

			$type = max(1, $data["src-kind"] * 1);

			$PDO->inject("INSERT INTO COMPONENT_ITEM (component, shorthand, slug, type, cross_origin, integrity, media, local_file) VALUES ($CID, ?, ?, $type, ?, ?, ?, ?)")->send([
				$data["shorthand"],
				$data["url"],
				$data["cross_origin"]=='none'?NULL:$data["cross_origin"],
				$data["integrity"],
				$data["media"],
				$LOCAL && !(isset($data["options_local"]) && in_array('srch', $data["options_local"])) ? 1 : 0
			]);

			$this->stopAction(function() use ($CID)  {
				$PDO->exec("UPDATE COMPONENT SET modified = 1 WHERE id = $CID");
				header("Location: /admin/contents/components/edit/$CID");
			});

			form_continue:

		} elseif($state == FormElement::FORM_STATE_NONE) {
			$data = [
				"integrity_enc" => 'sha384'
			];

			if(isset($_POST["file-hash"]) && $hash = $_POST["file-hash"]) {
				/** @var \SplFileInfo $file */
				foreach(new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $cmpLoc = SkyGetLocation('/', 'Components') ) ) as $file) {
					if(md5($file->getPathname()) == $hash) {
						unset($hash);
						break;
					}
				}

				if(!isset($hash)) {
					$uri = explode("$cmpLoc/", $file->getPathname());
					$uri = array_pop($uri);
					$data["uri"] = $uri;
					$data["options_local"] = ['srch'];

					$ext = explode(".", $uri);
					$ext = array_pop($ext);
					switch (strtolower($ext)) {
						case 'jpg':
						case 'gif':
						case 'jpeg':
						case 'png':
						case 'ico':
							$data["src-kind"] = 12;
							break;
						case 'css':
							$data["src-kind"] = 2;
							break;
						case 'js':
							$data["src-kind"] = 4;
							break;
					}
				}
			}

			if(isset($_POST["read-html"])) {
				$html = $_POST["read-html"];

				if(preg_match("/^\s*<\s*(link|script)\s*/i", $html, $ms)) {
					$html = substr($html, strlen($ms[0]));

					if(preg_match_all("/(\w+)=(?:\"|')([^\"']+)(?:\"|')/i", $html, $mms)) {
						$attrs = [];
						for($e=0;$e<count($mms[1]);$e++) {
							$attrs[ $mms[1][$e] ] = $mms[2][$e];
						}

						if(isset($attrs["id"]))
							$data["shorthand"] = $attrs['id'];
						elseif(isset($attrs["name"]))
							$data["shorthand"] = $attrs['name'];

						if(isset($attrs['crossorigin']))
							$data["cross_origin"] = $attrs["crossorigin"];
						if(isset($attrs['media']))
							$data["media"] = $attrs["media"];
						if(isset($attrs['integrity']))
							$data["integrity"] = $attrs["integrity"];

						$REMOTE = 0;
						$u = $attrs["href"] ?? $attrs["src"];

						if(preg_match("%^https?://%i", $u, $sss)) {
							$REMOTE = 1;
							$data["url"] = substr($u, strlen($sss[0]));
						} elseif(preg_match("%^/?public/%i", $u, $sss)) {
							$data["url"] = substr($u, strlen($sss[0]));
						}

						if(strtolower($ms[1]) == 'link') {
							$rel = $attrs["rel"];
							switch (strtolower($rel)) {
								case 'icon':
								case 'shorthand':
								case 'shorthand icon':
									$data["src-kind"] = $REMOTE ? 13 : 12;
									break;
								case 'stylesheet':
									$data["src-kind"] = $REMOTE ? 3 : 2;
									break;
							}
						} elseif(strtolower($ms[1]) == 'script') {
							$data["src-kind"] = $REMOTE ? 5 : 4;
						}
					}
				}
			}

			$form->setData($data);
		}
		error_clear_last();

		$mfs = ini_get("upload_max_filesize");
		if(preg_match("/^\s*(\d+)\s*(m|k|g)\s*$/i", $mfs, $ms)) {
			$u = ['m' => 1024*1024, 'g' => 1024*1024*1024, 'k' => 1024];
			$mfs = $ms[1] * ($u[ strtolower($ms[2]) ] ?? 1);
		}

		/** @var UserTool $uTool */
		$uTool = $this->get(UserTool::SERVICE_NAME);

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('/admin/contents/components', $tm->translateGlobal("Components"))
				->addItem('/admin/contents/components/edit/'.$CID, $tm->translateGlobal("Edit %s", NULL, $COMPONENT["name"]))
				->addItem('', $title = (
					$LOCAL ?
						$tm->translateGlobal("Add Local"):
						$tm->translateGlobal("Add Remote")
				)),
			'COMPONENT' => $COMPONENT,
			"FORMULA" => $form,
			"TITLE" => $title,
			"FIELD_MAP" => $fieldMap,
			'MAX_FILE_SIZE' => $mfs,
			'SRC_DESC' => (function() use ($PDO, $EDITING) {
				$map = [];
				foreach($PDO->select("SELECT description, id FROM COMPONENT_ITEM_TYPE WHERE editable & $EDITING = $EDITING") as $record) {
					$map[ $record['id'] ] = $record['description'];
				}
				return $map;
			})(),
			"LOCAL" => $LOCAL,
			"URL_CODE" => $URL_CODE,
			"CAN" => [
				"DELETE" => $uTool->hasRole("SKYLINE.CONTENTS.DELETE")
			]
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'component-add-local'
		]);
	}

	/**
	 * @route regex %^/?contents/components/(\d+)/remove-source/(\d+)%i
	 * @role SKYLINE.CONTENTS.DELETE
	 */
	public function removeSourceAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$PDO = $this->getContentsPDO($cdir);

		$SID = $actionDescription->getCaptures()[2];
		$CID = $actionDescription->getCaptures()[1];

		$PDO->transaction(function() use ($SID, $PDO, $CID) {
			if($record = $PDO->selectOne("SELECT slug, local_file FROM COMPONENT_ITEM WHERE COMPONENT_ITEM.id = $SID")) {
				// TODO: Remove assigned file
				if($record["local_file"]) {
					$dir = SkyGetLocation("/", 'Components');
					$slug = explode("/Public/", $record["slug"]);
					$slug = array_pop($slug);

					unlink($tg = ($dir . DIRECTORY_SEPARATOR . $slug));

					foreach(new \DirectoryIterator(dirname($tg)) as $file) {
						if($file->getBasename() == '.' || $file->getBasename() == '..')
							continue;
						$empty = 1;
					}

					if(!isset($empty))
						rmdir(dirname($tg));
				}
			}

			$PDO->exec("DELETE FROM COMPONENT_ITEM WHERE id = $SID");
			$PDO->exec("UPDATE COMPONENT SET modified = 1 WHERE id = $CID");
		});

		$this->stopAction(function() use ($CID) {
			header("Location: /admin/contents/components/edit/$CID");
		});
	}

	/**
	 * @route regex %^/?contents/components/add\-from\-file/(\d+)%i
	 * @role SKYLINE.CONTENTS.EDIT
	 */
	public function componentDirectoryLookupAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$PDO = static::getContentsPDO($cdir);

		$CID = $actionDescription->getCaptures()[1];
		$COMPONENT = $PDO->selectOne("SELECT id, name FROM COMPONENT WHERE id = $CID");
		if(!$COMPONENT['id']) {
			$this->stopAction(function() {
				header("Location: /admin/contents/components");
			});
		}


		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('/admin/contents/components', $tm->translateGlobal("Components"))
				->addItem('/admin/contents/components/edit/'.$CID, $tm->translateGlobal("Edit %s", NULL, $COMPONENT["name"]))
				->addItem('', $tm->translateGlobal("Lookup Directory")),
			"COMPONENT" => $COMPONENT,
			"SRC" => SkyGetLocation("/", 'Components')
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'component-lookup-file'
		]);
	}
}