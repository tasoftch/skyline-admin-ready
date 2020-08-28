<?php

namespace Skyline\Admin\Ready\Controller;

use Skyline\Admin\Ready\Controller\Management\AbstractContentManagementActionController;

/**
 * Class EditorActionController
 * @package Skyline\Admin\Ready\Controller
 * @role SKYLINE.ADMIN
 */
class EditorActionController extends AbstractGeneralAdminController
{
	/**
	 * @route literal /editor/init
	 */
	public function initEditorAction() {
		$symbol = $_GET["symbol"] ?? NULL;

		$PDO = AbstractContentManagementActionController::getContentsPDO($dir);

		$stop = function() {
			$this->stopAction(function() {
				if($return = $_GET["returnURI"] ?? NULL) {
					header("Location: " . $return);
				} else {
					echo "Could not complete request.";
				}
			});
		};

		switch (strtoupper( $_GET["mode"] ?? 'LAYOUT' )) {
			case 'LAYOUT':
				$SYMBOL = $PDO->selectOne('SELECT * FROM LAYOUT WHERE slug = ?', [$symbol]);
				break;
			default:
				$SYMBOL = NULL;
		}

		if(!$SYMBOL) {
			$stop();
		}

		var_dump($SYMBOL);
		$this->renderTemplate('admin-main', [
			'Content' => 'editor-bridge'
		]);
	}

	/**
	 * @route literal /editor/run
	 */
	public function showEditorAction() {

		$this->renderTemplate('admin-main', [
			'Content' => 'editor'
		]);
	}
}