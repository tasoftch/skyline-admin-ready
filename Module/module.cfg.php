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

use Skyline\Module\Compiler\Decider\RegexSubdomainDecider;
use Skyline\Module\Compiler\Decider\RegexURIPrefixDecider;
use Skyline\Module\Config\ModuleConfig;

return [
    ModuleConfig::MODULE_NAME => 'Ready',
    ModuleConfig::CLASS_DIRECTORY_NAME => __DIR__ . "/src",
    ModuleConfig::CLASS_PREFIX => 'Skyline\\Admin\\Ready\\',

    ModuleConfig::MODULE_DECIDER_CLASSES => [
        [
            RegexSubdomainDecider::class,
            '%^admin$%i',
            RegexSubdomainDecider::NORMALIZE_TO_NOT_HAVE_URI,
            'admin'
        ],
        [
            RegexURIPrefixDecider::class,
            RegexURIPrefixDecider::NORMALIZE_TO_NOT_HAVE_URI,
            '%^/?admin%i',
            ''
        ],
        [
            RegexURIPrefixDecider::class,
            0,
            '%^/?Public/Skyline\-Library/Admin%i'
        ]
    ]
];
