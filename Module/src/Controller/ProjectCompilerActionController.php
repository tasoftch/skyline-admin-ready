<?php

namespace Skyline\Admin\Ready\Controller;


use Skyline\Admin\Ready\Compiler\Logger\OnlineLogger;
use Skyline\Compiler\CompilerConfiguration;
use Skyline\Compiler\CompilerContext;
use Skyline\Compiler\CompilerFactoryInterface;
use Skyline\Compiler\CompilerInterface;
use Skyline\Compiler\Context\Code\Pattern;
use Skyline\Compiler\Context\Code\PatternExcludingSourceCodeManager;
use Skyline\Compiler\Factory\CompleteWithPackagesCompilersFactory;
use Skyline\Compiler\Project\Attribute\Attribute;
use Skyline\Compiler\Project\Attribute\AttributeCollection;
use Skyline\Compiler\Project\Attribute\CompilerContextParameterCollection;
use Skyline\Compiler\Project\Loader\LoaderInterface;
use Skyline\Compiler\Project\MutableProjectInterface;
use Skyline\HTML\Bootstrap\Breadcrumb;
use Skyline\HTML\Bootstrap\Form\Control\option\MultipleOptionListControl;
use Skyline\HTML\Form\Control\Button\ActionButtonControl;
use Skyline\HTML\Form\Control\Option\PopUpControl;
use Skyline\HTML\Form\FormElement;
use Skyline\Translation\TranslationManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;
use TASoft\Collection\DependencyCollection;
use TASoft\Service\ServiceManager;

/**
 * Class ProjectCompilerActionController
 * @package Skyline\Admin\Ready\Controller
 * @role SKYLINE.ADMIN
 */
class ProjectCompilerActionController extends AbstractGeneralAdminController
{
	const OUTPUT_BUFFER = 1024;

	const DEV_PROJECT_CONFIG_FILE = 'dev-project.xml';
	const LIVE_PROJECT_CONFIG_FILE = 'live-project.xml';

	/**
	 * @route literal /project/compile
	 * @role SKYLINE.CONTENTS.COMPILE
	 */
	public function compileProjectAction(Request $request) {
		/** @var TranslationManager $tm */
		$tm = $this->get(TranslationManager::SERVICE_NAME);
		$sm = ServiceManager::generalServiceManager();

		if(session_status() != PHP_SESSION_ACTIVE)
			session_start();

		$_SESSION["compile"] = $_POST;

		$this->renderModel([
			'COMPILATION' => [
				'MODE' => $md = $sm->getParameter("project.compilation.mode"),
				"FLAGS" => $sm->getParameter("project.compilation.flags")[$md] ?? []
			],
			'CSRF' => $this->makeCSRFToken("compile-csrf"),
			'BREAD' => (new Breadcrumb())
				->addItem('/admin/', $tm->translateGlobal("Admin"))
				->addItem('', $tm->translateGlobal("Compile")),
		]);
		$this->renderTemplate("admin-main", [
			"Content" => 'compilation'
		]);
	}

	/**
	 * @route literal /project/compile/run
	 * @role SKYLINE.CONTENTS.COMPILE
	 */
	public function compilerRunnerAction() {
		if(session_status() != PHP_SESSION_ACTIVE)
			session_start();

		$csrf = $this->makeCSRFToken("compile-csrf");

		$_POST = $_SESSION["compile"];

		$response = new StreamedResponse(function() use ($csrf) {
			ini_set("output_buffering", 0);
			echo "<link rel='stylesheet' media='all' href='/Public/Skyline/Stylesheets/skyline.core.min.css'>";

			printf("<pre class='p-1' style='white-space: normal'>Start Compilation at %s<br>", date("d.m.Y G:i:s"));
			if($csrf == @$_POST["compile-csrf"]) {
				printf("Authorization: <span class='text-success'>Authorized.</span><br>");

				$ctx = $this->setupCompilerContext();
				if(!$ctx)
					goto failed;

				if(isset($_POST["compile"])) {
					foreach($ctx->getCompilers() as $compiler) {
						$depCollection = new DependencyCollection(false);
						$depCollection->setAcceptsDuplicates(false);

						foreach($ctx->getCompilers() as $compiler) {
							if($compiler instanceof CompilerInterface) {
								$id = $compiler->getCompilerID();
								$deps = $compiler->getDependsOnCompilerIDs();
								if($deps)
									$depCollection->add($id, $compiler, $deps);
								else
									$depCollection->add($id, $compiler);
							}
							elseif($compiler instanceof CompilerFactoryInterface) {
								$compiler->registerCompilerInstances($depCollection, $ctx);
							}
						}
					}

					$requiredCompilerNames = [];
					$INCLUDE = ($_POST["include"] ?? []) ?: ['dependencies', 'depends'];

					foreach($_POST["compile"] ?? [] as $compiler) {
						if(in_array('dependencies', $INCLUDE)) {
							$dependencies = $depCollection->getRecursiveDependencies($compiler);
							if($dependencies) {
								$requiredCompilerNames = array_merge($requiredCompilerNames, array_keys($dependencies));
							}
						}

						if(in_array('depends', $INCLUDE)) {
							$dependencies = $depCollection->getRecursiveDepends($compiler);
							if($dependencies) {
								$requiredCompilerNames = array_merge($requiredCompilerNames, array_keys($dependencies));
							}
						}

						$requiredCompilerNames[] = $compiler;
					}

					$cHandler = function(CompilerInterface $compiler) use ($requiredCompilerNames) {
						if( in_array($compiler->getCompilerID(), $requiredCompilerNames) ) {
							print_out("<hr><strong class='text-success'>%s</strong><br>", $compiler->getCompilerName());
							return true;
						}
						return false;
					};
				} else {
					$cHandler = function(CompilerInterface $compiler) {
						print_out("<hr><strong class='text-success'>%s</strong><br>", $compiler->getCompilerName());
						return true;
					};
				}

				if($pre = $_POST["pre-compiler"] ?? false) {
					if(!is_callable($pre))
						$pre = base64_decode( $pre );
					if(is_callable($pre)) {
						print_out("<hr><strong class='text-primary'>Run pre-compiler</strong><br><em>$pre</em><br>");
						call_user_func($pre, $ctx);
					} else
						print_out("<hr><span class='text-warning'><b>Warning: </b>The pre-compiler <kbd>$pre</kbd> is not callable.</span><br>");
				}

				if($ctx->compile( $cHandler )) {
					if($pre = $_POST["post-compiler"] ?? false) {
						if(!is_callable($pre))
							$pre = base64_decode( $pre );
						if(is_callable($pre)) {
							print_out("<hr><strong class='text-primary'>Run post-compiler</strong><br><em>$pre</em><br>");
							call_user_func($pre, $ctx);
						} else
							print_out("<hr><span class='text-warning'><b>Warning: </b>The post-compiler <kbd>$pre</kbd> is not callable.</span><br>");
					}
				} else {
					goto failed;
				}


			} else {
				printf("Authorization: <span class='text-danger'>Not Authorized.</span><br>");
				goto failed;
			}


			echo "<hr><p class='alert alert-success'>Compilation was successful.</p>";
			goto cleanup;

			failed:
			echo "<hr><p class='alert alert-danger'>Compilation failed.</p>";

			cleanup:
			$href = $_POST["returnURI"] ?? '/admin';
			echo "<a href='$href' class='btn btn-outline-primary' target='_parent'>Go back…</a>";
			error_clear_last();
		});

		$this->renderResponse($response);
	}

	protected function setupCompilerContext() {
		$sm = ServiceManager::generalServiceManager();

		$dev = $sm->getParameter("project.compilation.mode");
		if($dev == 0)
			$pf = static::DEV_PROJECT_CONFIG_FILE;
		else
			$pf = static::LIVE_PROJECT_CONFIG_FILE;



		if(is_file($pf)) {
			$exts = explode(".", $pf);
			$ext = array_pop($exts);

			$loaderClassName = "Skyline\\Compiler\\Project\\Loader\\" . strtoupper($ext);

			if(!class_exists($loaderClassName)) {
				print_out("<div class='alert alert-danger'>Skyline CMS Compiler can not load *.$ext project configuration files. Use another one or install the required project loader</div>");
				return;
			}

			/** @var LoaderInterface $loader */
			$loader = new $loaderClassName( $pf );
			$project = $loader->getProject();

			if(!($project instanceof MutableProjectInterface)) {
				print_out("<div class='alert alert-danger' >Could not load project instance</div>");
				return;
			}

			print_out("Project: <span class='text-success'>$pf</span> <em class='text-muted'>(Loaded With: %s)</em><br>", get_class($loader));
			unset($loader);

			/** @var CompilerContextParameterCollection $ctxAttr */
			$ctxAttr = $project->getAttribute("context");
			if(!($ctxAttr instanceof CompilerContextParameterCollection))
				$ctxAttr = new CompilerContextParameterCollection("context");

			$ctxClass = $ctxAttr->getContextClass();
			/** @var CompilerContext $context */
			$context = new $ctxClass($project);
			$context->setContextParameters( $ctxAttr );

			$flags = $sm->getParameter("project.compilation.flags")[$dev] ?? [];

			$context->getConfiguration()[CompilerConfiguration::COMPILER_ZERO_LINKS] = in_array('zero', $flags);
			$context->getConfiguration()[CompilerConfiguration::COMPILER_TEST] = in_array('test', $flags);
			$context->getConfiguration()[CompilerConfiguration::COMPILER_DEBUG] = in_array('debug', $flags);
			$context->getConfiguration()[CompilerConfiguration::COMPILER_WITH_PDO] = in_array('with-pdo', $flags);

			if($excludedPathItems = $project->getAttribute("excluded")) {
				if($excludedPathItems instanceof AttributeCollection)
					$excludedPathItems = $excludedPathItems->getAttributes();
				else {
					$excludedPathItems = explode(",", $excludedPathItems->getValue());
					foreach($excludedPathItems as $idx => &$value) {
						$value = new Attribute($idx, trim($value));
					}
				}
				$ce = new PatternExcludingSourceCodeManager($context);
				foreach($excludedPathItems as $item) {
					$ce->addPattern( new Pattern( $item->getValue() ) );
				}
				$context->setSourceCodeManager($ce);
			}

			if(!($factories = $ctxAttr->getCompilerFactories())) {
				$factories[] = CompleteWithPackagesCompilersFactory::class;
			}

			foreach($factories as $factory) {
				if(is_string($factory))
					$factory = new $factory;

				if($factory instanceof CompilerFactoryInterface || $factory instanceof CompilerInterface)
					$context->addCompiler($factory);
			}

			$context->setLogger( new OnlineLogger( $verbose =  $sm->getParameter("project.compilation.verbose") ?: 32 ) );

			switch ($verbose) {
				case OnlineLogger::VERBOSITY_QUIET:
					print_out("<strong>Verbosity: </strong><span class='text-success'>Quiet</span><br>");
					break;
				case OnlineLogger::VERBOSITY_NORMAL:
					print_out("<strong>Verbosity: </strong><span class='text-success'>Normal</span><br>");
					break;
				case OnlineLogger::VERBOSITY_VERBOSE:
					print_out("<strong>Verbosity: </strong><span class='text-success'>Verbose</span><br>");
					break;
				case OnlineLogger::VERBOSITY_VERY_VERBOSE:
					print_out("<strong>Verbosity: </strong><span class='text-success'>Very Verbose</span><br>");
					break;
				case OnlineLogger::VERBOSITY_DEBUG:
					print_out("<strong>Verbosity: </strong><span class='text-success'>Debug</span><br>");
					break;
			}

			return $context;
		} else {
			print_out("<div class='alert alert-danger'>No project compilation configuration is available.<br>Please <a href='/admin/config-project' target='_parent'>configure</a> your project first.</div>");
			return;
		}
	}
}

function print_out($format, ...$args) {
	$format = vsprintf($format, $args);
	$buf = ProjectCompilerActionController::OUTPUT_BUFFER - strlen($format);
	if($buf > 0)
		$format .= str_repeat(' ', $buf);
	echo $format;
	ob_flush();
	flush();
}