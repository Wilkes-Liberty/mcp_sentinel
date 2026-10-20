<?php

/**
 * @file
 * Fail unless the unfixed fakeTestModule algorithm fatals.
 *
 * Mirrors LyingTestModulePathHandler::fakeTestModule() as it
 * landed on 1.x via #346: strip DRUPAL_ROOT when it is a prefix,
 * else pass the absolute pathname to Extension.
 */

declare(strict_types=1);

$autoload = getcwd() . '/vendor/autoload.php';
if (!is_file($autoload)) {
  fwrite(STDERR, "vendor/autoload.php is missing.\n");
  exit(1);
}
require_once $autoload;

$root = $argv[1] ?? '';
if ($root === '') {
  fwrite(STDERR, "DRUPAL_ROOT argument is required.\n");
  exit(1);
}

$class = 'Drupal\\mcp_sentinel_rogue_auth\\Service\\McpRoguePrincipalAuthExtension';
if (!class_exists($class)) {
  fwrite(STDERR, "Unable to load {$class}.\n");
  exit(1);
}

$filename = (new ReflectionClass($class))->getFileName();
$filename = is_string($filename) ? $filename : '';
$infoPathname = dirname($filename) . '/mcp_sentinel_test.info.yml';

fwrite(STDOUT, "DRUPAL_ROOT: {$root}\n");
fwrite(STDOUT, "rogue getFileName: {$filename}\n");
fwrite(STDOUT, "infoPathname: {$infoPathname}\n");

if ($filename === '' || !is_file($filename)) {
  fwrite(STDERR, "::error::getFileName is missing.\n");
  exit(1);
}

if (!is_file($infoPathname)) {
  file_put_contents(
    $infoPathname,
    "name: 'MCP Sentinel unfixed-algorithm probe'\ntype: module\nhidden: true\n",
  );
}

$pathname = $infoPathname;
if (str_starts_with($pathname, $root . '/')) {
  $pathname = substr($pathname, strlen($root) + 1);
  fwrite(STDOUT, "stripped to: {$pathname}\n");
}

try {
  new Drupal\Core\Extension\Extension($root, 'module', $pathname);
}
catch (AssertionError $e) {
  fwrite(STDOUT, "unfixed fakeTestModule fatals as on d.o: {$e->getMessage()}\n");
  exit(0);
}

fwrite(STDERR, "::error::unfixed fakeTestModule would succeed; getFileName is still under DRUPAL_ROOT.\n");
exit(1);
