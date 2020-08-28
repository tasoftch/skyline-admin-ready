<?php

namespace Skyline\Admin\Ready\Helper;


class OptionLabelWithDescription
{
	private $label;
	private $description;

	/**
	 * OptionEntry constructor.
	 * @param $id
	 * @param $label
	 * @param $description
	 */
	public function __construct($label, $description = "")
	{
		$this->label = $label;
		$this->description = $description;
	}

	/**
	 * @return mixed
	 */
	public function getLabel()
	{
		return $this->label;
	}

	/**
	 * @return string
	 */
	public function getDescription(): string
	{
		return $this->description;
	}

	public function __toString()
	{
		if($this->getDescription())
			return sprintf("%s<br><em class='text-muted' style='font-size: 90%%'>%s</em>", $this->getLabel(), $this->getDescription());
		return $this->getLabel();
	}
}