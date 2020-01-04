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

use Skyline\Compiler\CompilerContext;
use Skyline\Component\Config\AbstractComponent;
use Skyline\Component\Config\CSSComponent;
use Skyline\Component\Config\IconComponent;
use Skyline\Component\Config\JavaScriptPostLoadComponent;
use Skyline\Component\Config\OpenDirectoryComponent;

$skylineLogo64 = __DIR__ . '/Components/Images/Logo/skyline-256.png';
$skylineCoreJS = __DIR__ . "/Components/js/skyline-core.js";


return [
    "Ready" => [
        "icon" => new IconComponent(
            '/Public/Skyline-Library/Admin/Images/Logo/skyline-256.png',
            NULL,
            'sha384-'.hash_file("sha384", $skylineLogo64),
            NULL,
            CompilerContext::getCurrentCompiler()->getRelativeProjectPath($skylineLogo64)
        ),
        'bootstrap-js' => new JavaScriptPostLoadComponent('https://stackpath.bootstrapcdn.com/bootstrap/4.3.0/js/bootstrap.bundle.min.js', "sha384-VoPFvGr9GxhDT3n8vqqZ46twP5lgex+raTCfICQy73NLhN7ZqSfCtfSn4mLA2EFA"),
        AbstractComponent::COMP_REQUIREMENTS => [
            "jQuery"
        ],
        "core-js" => new JavaScriptPostLoadComponent(
            "/Public/Skyline-Library/Admin/JavaScript/skyline-core.js",
            'sha384-'.hash_file("sha384", $skylineCoreJS),
            NULL,
            CompilerContext::getCurrentCompiler()->getRelativeProjectPath($skylineCoreJS))
    ],
    "FontAwesome" => [
        'css' => new CSSComponent("https://stackpath.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css", 'all', "sha384-wvfXpqpZZVQGK6TAh5PVlGOfQNHSoD2xbE+QkPxCAFlNEevoEH3Sl0sibVcOQVnN"),
    ],
    new OpenDirectoryComponent(
        '/Skyline-Library/Admin',
        __DIR__ . "/Components"
    )
];
