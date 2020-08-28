<?php
namespace Skyline\Admin\Ready\Compiler\Logger;

use Throwable;
use Skyline\Compiler\Context\Logger\LoggerInterface;
use function Skyline\Admin\Ready\Controller\print_out;


class OnlineLogger implements LoggerInterface
{
	private $verbosity = self::VERBOSITY_NORMAL;

	/**
	 * OnlineLogger constructor.
	 * @param int $verbosity
	 */
	public function __construct(int $verbosity)
	{
		$this->verbosity = $verbosity;
	}


	public function logText($message, $verbosity = self::VERBOSITY_NORMAL, $context = NULL, ...$args)
	{
		if($verbosity <= $this->verbosity)
			print_out($message . "<br>" . PHP_EOL, ...$args);
	}

	public function logNotice($message, $context = NULL, ...$args)
	{
		print_out("<span class='text-secondary'><b>Notice: </b>" . $message . "</span><br>" . PHP_EOL, ...$args);
	}

	public function logWarning($message, $context = NULL, ...$args)
	{
		print_out("<span class='text-warning'><b>Warning: </b>" . $message . "</span><br>" . PHP_EOL, ...$args);
	}

	public function logError($message, $context = NULL, ...$args)
	{
		print_out("<span class='text-danger'><b>Error: </b>" . $message . "</span><br>" . PHP_EOL, ...$args);
	}

	public function logException(Throwable $exception)
	{
		print_out("<span class='text-danger'><b>Fatal: </b>" . $exception->getMessage() . "</span><br>" . PHP_EOL);
	}
}