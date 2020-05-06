<?php
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
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
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

namespace Skyline\Admin\Ready\Controller;


use Skyline\Application\Controller\AbstractActionController;
use Skyline\CMS\Security\Controller\SecurityActionControllerInterface;
use Skyline\CMS\Security\SecurityTrait;
use Skyline\Kernel\Exception\SkylineKernelDetailedException;
use Skyline\Render\Info\RenderInfoInterface;
use Skyline\Router\Description\ActionDescriptionInterface;
use Skyline\Security\CSRF\CSRFToken;
use Skyline\Security\CSRF\CSRFTokenManager;
use Skyline\Translation\TranslationManager;

abstract class AbstractGeneralAdminController extends AbstractActionController implements SecurityActionControllerInterface
{
	use SecurityTrait;


	public function prepareActionForChallenge(ActionDescriptionInterface $actionDescription, RenderInfoInterface $renderInfo, $challengeInfo)
	{
		$uiConf = SkyGetPath("$(/)/UI/config.php");

		if(!$uiConf && $_SERVER["REQUEST_URI"] != '/admin/config' && $_SERVER["REQUEST_URI"] != '/config') {
			header("Location: /admin/config");
			exit();
		}

		$this->setupRenderInfo($renderInfo, function() {
			$this->renderTitle("Skyline :: Ready :: Identification");
			$this->renderDescription("Please identify yourself to get access to the Skyline CMS Administration panel.");
		});
	}

	protected function verifyCSRF() {
		/** @var CSRFTokenManager $csrf */
		$csrf = $this->CSRFManager;

		$token = new CSRFToken('skyline-admin-csrf', $_POST['skyline-admin-csrf'] ?? "");
		if(!$csrf->isTokenValid($token)) {
			/** @var TranslationManager $tm */
			$tm = $this->translationManager;

			$e = new SkylineKernelDetailedException($tm->translateGlobal("CSRF Token Missmatch"), 403);
			$e->setDetails($tm->translateGlobal("The request is not valid because of the csrf token"));
			throw $e;
		}
	}
}