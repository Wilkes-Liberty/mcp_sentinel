<?php

/**
 * @file
 * Load the rogue class from the checkout, not the docroot mount.
 *
 * Drupal's classloader includes the file through
 * web/modules/custom/mcp_sentinel/tests, which starts with
 * DRUPAL_ROOT. ReflectionClass::getFileName() then stays under
 * the docroot and the unfixed fakeTestModule strips that prefix.
 * On drupal.org, getFileName() is the checkout path. A prepend
 * autoloader wins over Composer and PHPUnit child processes.
 */

declare(strict_types=1);

$workspace = getenv('GITHUB_WORKSPACE');
if (!is_string($workspace) || $workspace === '') {
  $workspace = '';
}

if ($workspace !== '') {
  spl_autoload_register(static function (string $class) use ($workspace): void {
    $map = [
      'Drupal\\mcp_sentinel\\Service\\McpPrincipalAuthExtensionInterface' => $workspace
      . '/src/Service/McpPrincipalAuthExtensionInterface.php',
      'Drupal\\mcp_sentinel_rogue_auth\\Service\\McpRoguePrincipalAuthExtension' => $workspace
      . '/tests/modules/mcp_sentinel_rogue_auth/src/Service/'
      . 'McpRoguePrincipalAuthExtension.php',
    ];
    if (isset($map[$class]) && is_file($map[$class])) {
      require $map[$class];
    }
  }, TRUE, TRUE);
}

$temp = getenv('RUNNER_TEMP');
$autoload = '';
if (is_string($temp) && $temp !== '') {
  $autoload = $temp . '/drupal/vendor/autoload.php';
}
if ($autoload === '' || !is_file($autoload)) {
  $autoload = getcwd() . '/vendor/autoload.php';
}
if (is_file($autoload)) {
  require_once $autoload;
}
