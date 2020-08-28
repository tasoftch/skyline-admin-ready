<?php

namespace Skyline\Admin\Ready\Helper;


class ParameterSetupHelper implements \ArrayAccess
{
	private $parameterFilename;
	private $parameters;
	private $hasChanges = false;

	public function __construct(string $parameterFilename = '$(C)/parameters.addon.config.php')
	{
		$this->parameterFilename = $parameterFilename;
	}

	private function _loadParameters() {
		if(NULL === $this->parameters) {
			if($f = SkyGetPath($this->parameterFilename)) {
				$this->parameters = require $f;
			} else
				throw new \RuntimeException("Can not open parameter storage. No such file or directory");
		}
	}

	/**
	 * @return array
	 */
	public function getParameters(): array
	{
		$this->_loadParameters();
		return $this->parameters;
	}

	/**
	 * @return string
	 */
	public function getParameterFilename(): string
	{
		return $this->parameterFilename;
	}

	/**
	 * @param $paramKey
	 * @return mixed|null
	 */
	public function getParameter($paramKey) {
		$this->_loadParameters();
		return $this->parameters[$paramKey] ?? NULL;
	}

	/**
	 * @param $paramKey
	 * @param $value
	 * @param bool $parseDefault
	 * @return static
	 */
	public function setParameter($paramKey, $value, bool $parseDefault = true) {
		$this->_loadParameters();
		if($parseDefault) {
			if($value === '@default') {
				$this->offsetUnset($paramKey);
				return $this;
			}
		}

		if($this->getParameter($paramKey) !== $value) {
			$this->parameters[$paramKey] = $value;
			$this->hasChanges = true;
		}

		return $this;
	}

	/**
	 * @param null $path
	 * @return static
	 */
	public function store($path = NULL) {
		if($this->hasChanges()) {
			if($path == NULL)
				$path = $this->parameterFilename;
			$parameters = $this->parameters;

			ksort($parameters);

			$parameters = var_export($parameters, true);
			file_put_contents(SkyGetPath($path), "<?php\nreturn $parameters;");
			$this->hasChanges = false;
		}
		return $this;
	}

	/**
	 * @return bool
	 */
	public function hasChanges(): bool
	{
		return $this->hasChanges;
	}

	public function offsetExists($offset)
	{
		$this->_loadParameters();
		return isset($this->parameters[$offset]);
	}

	public function offsetGet($offset)
	{
		return $this->getParameter($offset);
	}

	public function offsetSet($offset, $value)
	{
		$this->setParameter($offset, $value);
	}

	public function offsetUnset($offset)
	{
		$this->_loadParameters();
		if(isset($this->parameters[$offset])) {
			unset($this->parameters[$offset]);
			$this->hasChanges = true;
		}
	}
}