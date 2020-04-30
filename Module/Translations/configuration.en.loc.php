<?php

use Skyline\PDO\MySQL;
use Skyline\PDO\SQLite;

return [
	// Configuration Panel
	'Configuration' => 'Configuration',
	"Adjust initial configuration to be able to launch Skyline CMS Administration panel." => "Adjust initial configuration to be able to launch Skyline CMS Administration panel.",
	
	// Page info
	'Your Skyline CMS Administration panel is not yet ready to use. Please go through the following steps to configure the application.' => 'Your Skyline CMS Administration panel is not yet ready to use. Please go through the following steps to configure the application.',

	// Section Database
	'Database' => 'DataBase',

	"<p>Skyline uses a database to store users, credentials, access control information, contents and more.</p>
<p>It is designed to choose from two database sources: MySQL and SQLite. If Skyline is not able to connect to the primary source, it will choose the secondary.</p>
<p>Here you can specify the order and the connection information.</p>
<p class='text-danger'>The password is never transmitted to this page. So an empty field does not mean no password.</p>"
	=>
		'<p>Skyline uses a database to store users, credentials, access control information, contents and more.</p>
<p>It is designed to choose from two database sources: MySQL and SQLite. If Skyline is not able to connect to the primary source, it will choose the secondary.</p>
<p>Here you can specify the order and the connection information.</p>
<p class=\'text-danger\'>The password is never transmitted to this page. So an empty field does not mean no password.</p>',

	'password entered' => 'password entered',
	'empty password' => 'empty password',

	"Primary" => "Primary",
	"Secondary" => 'Secondary',

	"MySQL" => "MySQL / Maria DB",
	"SQLite" => "SQLite",

	"SQLite Filename" => 'SQLite Filename',
	"File does not exist." => "File does not exist.",

	"Username and/or password and/or database is not correct." => 'Username and/or password and/or database is not correct.',

	"DB Name" => 'DB Name',

	"No connection to database possible." => "No connection to database possible.",
	SQLite::class => 'SQLite database selected',
	MySQL::class => 'MYSQL database server selected',

	"Contents" => "Contents"
];