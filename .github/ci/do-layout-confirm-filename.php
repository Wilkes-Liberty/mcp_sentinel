<?php

/**
 * @file
 * Print how the rogue class filename resolves on this layout.
 *
 * On drupal.org the module's real path sits outside the
 * docroot (DRUPAL_ROOT is $CI_PROJECT_DIR/web; the class
 * file is $CI_PROJECT_DIR/tests/...). GitHub missed the
 * Extension.php:75 fatal because setup-php leaves
 * zend.assertions off, not because getFileName() is
 * guaranteed to stay under DRUPAL_ROOT. The red-first
 * probe is do-layout-probe-unfixed-extension.php.
 */

declare(strict_types=1);

$autoload = getcwd() . '/vendor/autoload.php';
if (is_file($autoload)) {
  require_once $autoload;
}

$workspace = getenv('GITHUB_WORKSPACE');
if (is_string($workspace) && $workspace !== '') {
  $interface = $workspace
    . '/src/Service/McpPrincipalAuthExtensionInterface.php';
  $rogue = $workspace
    . '/tests/modules/mcp_sentinel_rogue_auth/src/Service/'
    . 'McpRoguePrincipalAuthExtension.php';
  if (is_file($interface)) {
    require_once $interface;
  }
  if (is_file($rogue)) {
    require_once $rogue;
  }
}

$root = $argv[1] ?? '';
$class = 'Drupal\\mcp_sentinel_rogue_auth\\Service\\'
  . 'McpRoguePrincipalAuthExtension';
if ($root === '' || !class_exists($class)) {
  fwrite(
    STDERR,
    "Unable to load {$class} for the d.o-layout filename probe.\n",
  );
  exit(1);
}

$filename = (new ReflectionClass($class))->getFileName();
$filename = is_string($filename) ? $filename : '';

fwrite(STDOUT, "DRUPAL_ROOT: {$root}\n");
fwrite(STDOUT, "rogue getFileName: {$filename}\n");

if ($filename === '' || !is_file($filename)) {
  fwrite(STDERR, "::error::getFileName is missing.\n");
  exit(1);
}
