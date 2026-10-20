<?php

/**
 * @file
 * Load the rogue class from the checkout, not through the docroot mount.
 *
 * Drupal's classloader includes
 * web/modules/custom/mcp_sentinel/tests/... which starts with
 * DRUPAL_ROOT. ReflectionClass::getFileName() then stays under the
 * docroot and the unfixed fakeTestModule strips that prefix. On
 * drupal.org, getFileName() is the checkout path. Prepending this
 * file makes every PHPUnit process match that.
 */

declare(strict_types=1);

$workspace = getenv('GITHUB_WORKSPACE');
if (!is_string($workspace) || $workspace === '') {
  return;
}

$interface = $workspace . '/src/Service/McpPrincipalAuthExtensionInterface.php';
$rogue = $workspace . '/tests/modules/mcp_sentinel_rogue_auth/src/Service/McpRoguePrincipalAuthExtension.php';
if (is_file($interface)) {
  require_once $interface;
}
if (is_file($rogue)) {
  require_once $rogue;
}
