<?php

namespace Skyline\Admin\Ready\Helper;


abstract class ComponentTypeMapper
{
	private static $mapping = [
		// Icons
		'ico' => 8,
		'png' => 9,
		'jpg' => 10,
		'jpeg' => 11,
		'image/vnd.microsoft.icon' => 8,
		'image/png' => 9,
		'image/jpg' => 10,
		'image/jpeg' => 11,

		// CSS
		'css' => [2, 3],
		'text/css' => [2, 3],
		'text/x-css' => [2, 3],

		// Javascript
		'js' => [4, 5, 6, 7],
		'application/javascript' => [4, 5, 6, 7],
		'application/x-javascript' => [4, 5, 6, 7],
	];

	/**
	 * @param null $contentType
	 * @param bool $local
	 * @param bool $pre
	 * @return int|null
	 */
	public static function findComponentTypeFromContent(string $contentType, bool $local = true, bool $pre = true): ?int {
		$d = static::$mapping[ strtolower($contentType) ] ?? NULL;
		return self::_resolveResult($d, $local, $pre);
	}

	/**
	 * @param string $uriOrExtension
	 * @param bool $local
	 * @param bool $pre
	 * @return int|null
	 */
	public static function findComponentTypeFromExtension(string $uriOrExtension, bool $local = true, bool $pre = true): ?int {
		$ext = explode(".", $uriOrExtension);
		$ext = array_pop($ext);

		$d = static::$mapping[ strtolower($ext) ] ?? NULL;
		return self::_resolveResult($d, $local, $pre);
	}

	private static function _resolveResult($result, bool $local = true, bool $pre = true): ?int {
		if(NULL === $result)
			return NULL;
		if(is_numeric($result))
			return $result;
		if(is_array($result)) {
			@list($localPre, $remotePre, $localPost, $remotePost) = $result;
			if($local) {
				return $pre ? $localPre : $localPost;
			} else {
				return $pre ? $remotePre : $remotePost;
			}
		}
	}
}