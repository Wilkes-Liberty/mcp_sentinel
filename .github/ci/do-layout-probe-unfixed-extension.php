<?php

/**
 * @file
 * Temporary red-first check: the unfixed fakeTestModule algorithm fatals.
 *
 * Mirrors LyingTestModulePathHandler::fakeTestModule() as it
 * landed on 1.x via #346: strip DRUPAL_ROOT when it is a prefix,
 * else pass the absolute pathname to Extension. Keep this probe
 * until the getPath() fixture is the 1.x tip.
 */

declare(strict_types=1);

use Drupal\Core\Extension\Extension;

$autoload = getcwd() . '/vendor/autoload.php';
if (!is_file($autoload)) {
  fwrite(STDERR, "vendor/autoload.php is missing.\n");
  exit(1);
}
require_once $autoload;

$workspace = getenv('GITHUB_WORKSPACE');
if (!is_string($workspace) || $workspace === '') {
  fwrite(STDERR, "GITHUB_WORKSPACE is required.\n");
  exit(1);
}
$interface = $workspace
  . '/src/Service/McpPrincipalAuthExtensionInterface.php';
$rogue = $workspace
  . '/tests/modules/mcp_sentinel_rogue_auth/src/Service/'
  . 'McpRoguePrincipalAuthExtension.php';
if (!is_file($interface) || !is_file($rogue)) {
  fwrite(STDERR, "Unable to load the rogue class from the module path.\n");
  exit(1);
}
require_once $interface;
require_once $rogue;

$root = $argv[1] ?? '';
if ($root === '') {
  fwrite(STDERR, "DRUPAL_ROOT argument is required.\n");
  exit(1);
}

$class = 'Drupal\\mcp_sentinel_rogue_auth\\Service\\'
  . 'McpRoguePrincipalAuthExtension';
if (!class_exists($class)) {
  fwrite(STDERR, "Unable to load {$class}.\n");
  exit(1);
}

$filename = (new ReflectionClass($class))->getFileName();
$filename = is_string($filename) ? $filename : '';
$infoPathname = dirname($filename)
  . '/mcp_sentinel_test.info.yml';

fwrite(STDOUT, "DRUPAL_ROOT: {$root}\n");
fwrite(STDOUT, "rogue getFileName: {$filename}\n");
fwrite(STDOUT, "infoPathname: {$infoPathname}\n");

if ($filename === '' || !is_file($filename)) {
  fwrite(STDERR, "::error::getFileName is missing.\n");
  exit(1);
}

$wrote = FALSE;
$code = 1;
try {
  if (!is_file($infoPathname)) {
    file_put_contents(
      $infoPathname,
      "name: 'MCP Sentinel unfixed-algorithm probe'\n"
      . "type: module\nhidden: true\n",
    );
    $wrote = TRUE;
  }

  $pathname = $infoPathname;
  if (str_starts_with($pathname, $root . '/')) {
    $pathname = substr($pathname, strlen($root) + 1);
    fwrite(STDOUT, "stripped to: {$pathname}\n");
  }

  try {
    new Extension($root, 'module', $pathname);
  }
  catch (AssertionError $e) {
    fwrite(STDOUT, "unfixed fakeTestModule fatals as on d.o: ");
    fwrite(STDOUT, $e->getMessage() . "\n");
    $code = 0;
  }

  if ($code !== 0) {
    fwrite(STDERR, "::error::unfixed fakeTestModule would succeed; ");
    fwrite(STDERR, "getFileName={$filename} root={$root}\n");
  }
}
finally {
  if ($wrote && is_file($infoPathname)) {
    unlink($infoPathname);
  }
}

exit($code);
