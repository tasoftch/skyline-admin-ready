<?php

namespace Skyline\Admin\Ready\Controller\Management;


use Skyline\Admin\Ready\Helper\OptionLabelWithDescription;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\HTML\Bootstrap\Form\Control\option\MultipleOptionListControl;
use Skyline\HTML\Form\Control\Button\ActionButtonControl;
use Skyline\HTML\Form\Control\Option\PopUpControl;
use Skyline\HTML\Form\Control\Option\Provider\PlainGeneratorProvider;
use Skyline\HTML\Form\Control\Text\TextAreaControl;
use Skyline\HTML\Form\Control\Text\TextFieldControl;
use Skyline\HTML\Form\FormElement;
use Skyline\HTML\Form\Validator\CallbackValidator;
use Skyline\HTML\Form\Validator\NotEmptyValidator;
use Skyline\HTML\Form\Validator\UniqueSQLColumnValidator;
use Skyline\Kernel\Exception\SkylineKernelDetailedException;
use Skyline\PDO\SQLite;
use Skyline\Router\Description\RegexActionDescription;
use Skyline\Translation\TranslationManager;
use Symfony\Component\HttpFoundation\Request;
use TASoft\Util\Record\RecordTransformerAdapter;
use TASoft\Util\Record\StackByTransformer;

/**
 * Class ContentManagementController
 * @package Skyline\Admin\Ready\Controller
 * @role SKYLINE.ADMIN
 */
class LayoutManagementActionController extends AbstractContentManagementActionController
{
	/**
	 * @route literal /contents/layouts
	 * @menu path /admin/Contents/Layouts
	 * @menu action /admin/contents/layouts
	 * @menu select %^/?admin/contents/layouts%i
	 * @role SKYLINE.CONTENTS.EDIT.VIEW
	 */
	public function listLayoutsAction() {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$PDO = $this->getContentsPDO($contentsDir);

		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('', $tm->translateGlobal("Layouts")),
			"LAYOUTS" => (new RecordTransformerAdapter(
				new StackByTransformer(["id"], ['component']),
				$PDO->select("SELECT
    LAYOUT.id,
       LAYOUT.name,
       LAYOUT.description,
       slug,
       title,
       TC.name AS category,
       COMPONENT.name AS component
FROM LAYOUT
LEFT JOIN TEMPLATE_CATEGORY TC on LAYOUT.category = TC.id
LEFT JOIN TEMPLATE_COMPONENT ON template = LAYOUT.id
LEFT JOIN COMPONENT ON TEMPLATE_COMPONENT.component = COMPONENT.id
ORDER BY LAYOUT.name")
			))()
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'layouts'
		]);
	}

	/**
	 * @route regex %^/?contents/layouts/add/(.+)%i
	 * @role SKYLINE.CONTENTS.EDIT
	 */
	public function addLayoutAction(RegexActionDescription $actionDescription) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);

		$PDO = self::getContentsPDO($contentsDir);

		try {
			$fn = basename( urldecode( $actionDescription->getCaptures()[1] ));
			$PDO->inject("INSERT INTO LAYOUT (name, slug) VALUES (?, ?)")->send([
				$fn,
				$slug = strtolower( preg_replace("/[^a-z0-9_\-]/i", '-', $fn) )
			]);

			$lid = $PDO->lastInsertId("LAYOUT");
			$this->stopAction(function() use ($lid) {
				header("Location: /admin/contents/layouts/edit/$lid");
			});
		} catch (\PDOException $exception) {
			$e = new SkylineKernelDetailedException($tm->translateGlobal("Layout exists"), 403);
			$e->setDetails($tm->translateGlobal("The name %s is already in use for a layout.", NULL, htmlspecialchars($slug)));
			throw $e;
		}
	}

	/**
	 * @route regex %^/?contents/layouts/edit/(\d+)%i
	 * @role SKYLINE.CONTENTS.EDIT
	 */
	public function setupLayoutAction(RegexActionDescription $actionDescription, Request $request) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);


		$PDO = self::getContentsPDO($contentsDir);



		$LAYOUT = iterator_to_array(
			(new RecordTransformerAdapter(
				new StackByTransformer(['id'], ['component']),
				$PDO->select("SELECT * FROM LAYOUT LEFT JOIN TEMPLATE_COMPONENT ON template = LAYOUT.id WHERE id = :lay OR slug = :lay", ['lay' => $actionDescription->getCaptures()[1]])
			))()
		)[0];

		if(!$LAYOUT) {
			$this->stopAction(function() {
				header("Location: /admin/contents/layouts");
			});
		}


		$form = new FormElement("");

		$textField = new TextFieldControl("lname", 'lname');
		$textField->addValidator( new NotEmptyValidator() );
		$form->appendElement($textField);

		$textField = new TextFieldControl("slug", 'slug');
		$textField->addValidator(new NotEmptyValidator());
		$textField->addValidator(
			(new UniqueSQLColumnValidator($PDO, 'LAYOUT', 'slug'))
				->setIgnoredFields(['id' => $LAYOUT['id']])
		);
		$form->appendElement($textField);

		$textField = new TextFieldControl("ltitle", 'ltitle');
		$textField->setPlaceholder( $tm->translateGlobal("Page Title") );
		$form->appendElement($textField);

		$textView = new TextAreaControl("ldescription", 'ldescription');
		$textView->setPlaceholder( $tm->translateGlobal("Page Description") );
		$textView->setRows(3);
		$form->appendElement($textView);


		$category = new PopUpControl("gcat", 'gcat');
		$category->setNullPlaceholder($tm->translateGlobal("No category"));
		$category->setOptionProvider(new PlainGeneratorProvider($PDO->select("SELECT id, name AS label FROM TEMPLATE_CATEGORY WHERE selectable = 1 order by name")));
		$form->appendElement($category);

		$form->addActionControl(new ActionButtonControl("apply-meta"));

		$state = $form->prepareWithRequest($request);
		if($state == FormElement::FORM_STATE_VALID) {
			$this->verifyCSRF();
			$data = $form->getData();

			$PDO->inject("UPDATE LAYOUT SET name = ?, slug = ?, title = ?, description = ?, category = ? WHERE id = ?")->send([
				$data['lname'],
				$data["slug"],
				$data["ltitle"],
				$data['ldescription'],
				$data['gcat'] * 1,
				$LAYOUT['id']
			]);

			$this->stopAction(function() {
				header("Location: ". $_SERVER["REQUEST_URI"] );
			});
		} elseif($state == FormElement::FORM_STATE_NONE) {
			$form->setData([
				'lname' => $LAYOUT["name"],
				'ltitle' => $LAYOUT['title'],
				'ldescription' => $LAYOUT['description'],
				'slug' => $LAYOUT['slug'],
				'gcat' => $LAYOUT["category"]
			]);
		}

		$form2 = new FormElement("");
		$options = new MultipleOptionListControl("components", 'components');
		foreach($PDO->select("SELECT id, name, description FROM COMPONENT ORDER BY name") as $record) {
			if($record["description"])
				$options->setOption($record["id"], new OptionLabelWithDescription($record["name"], $record["description"]));
			else
				$options->setOption($record["id"], $record["name"]);
		}
		$form2->appendElement($options);
		$form2->addActionControl(new ActionButtonControl("apply-components"));

		$state = $form2->prepareWithRequest($request);
		if($state == FormElement::FORM_STATE_VALID) {
			$this->verifyCSRF();
			$data = $form2->getData();

			$lid = $LAYOUT['id']*1;

			$PDO->exec("DELETE FROM TEMPLATE_COMPONENT WHERE template = $lid");
			$inj = $PDO->inject("INSERT INTO TEMPLATE_COMPONENT (template, component) VALUES ($lid, ?)");

			array_walk($data['components'], function($A) use ($inj) {
				$inj->send([$A]);
			});

			$this->stopAction(function() {
				header("Location: ". $_SERVER["REQUEST_URI"] );
			});
		} elseif($state == FormElement::FORM_STATE_NONE) {
			$form2->setData([
				'components' => $LAYOUT["component"] ?: []
			]);
		}


		$this->renderModel([
			'CSRF' => $this->makeCSRFToken(),
			"FORMULA" => $form,
			'FORMULA2' => $form2,
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/contents/layouts', $tm->translateGlobal("Contents"))
				->addItem('', $tm->translateGlobal("Edit Layout")),
			"LAYOUT" => $LAYOUT
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'layout-edit'
		]);
	}


	/**
	 * @route regex %^/?contents/layouts/(\d+)/add-cat/(.+)$%i
	 * @role SKYLINE.CONTENTS.EDIT
	 */
	public function addCategoryAction(RegexActionDescription $actionDescription) {
		list(,$lid, $catName) = $actionDescription->getCaptures();
		$catName = base64_decode($catName);

		$PDO = self::getContentsPDO($contentsDir);
		$PDO->inject("INSERT INTO TEMPLATE_CATEGORY (name) VALUES (?)")->send([$catName]);
		$sid= $PDO->lastInsertId("TEMPLATE_CATEGORY");

		$PDO->exec("UPDATE LAYOUT SET category = $sid WHERE id = $lid");

		$this->stopAction(function() use ($lid) {
			header("Location: /admin/contents/layouts/edit/$lid");
		});
	}
}