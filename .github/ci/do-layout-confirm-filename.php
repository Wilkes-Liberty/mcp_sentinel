<?php

/**
 * @file
 * Fail unless the rogue class filename is outside DRUPAL_ROOT.
 *
 * On drupal.org, ReflectionClass::getFileName() for the rogue
 * extension is the checkout path, which is not under the docroot.
 * A directory symlink at web/modules/custom/mcp_sentinel still
 * lets Drupal's classloader include the file through a path that
 * starts with DRUPAL_ROOT, so the unfixed fakeTestModule strips
 * that prefix and stays green. This probe refuses that shape.
 */

declare(strict_types=1);

$autoload = getcwd() . '/vendor/autoload.php';
if (is_file($autoload)) {
  require_once $autoload;
}

$root = $argv[1] ?? '';
$class = 'Drupal\\mcp_sentinel_rogue_auth\\Service\\McpRoguePrincipalAuthExtension';
if ($root === '' || !class_exists($class)) {
  fwrite(STDERR, "Unable to load {$class} for the d.o-layout filename probe.\n");
  exit(1);
}

$filename = (new ReflectionClass($class))->getFileName();
$filename = is_string($filename) ? $filename : '';
$rootReal = realpath($root) ?: $root;

fwrite(STDOUT, "DRUPAL_ROOT: {$root}\n");
fwrite(STDOUT, "rogue getFileName: {$filename}\n");

$underRoot = $filename !== ''
  && (str_starts_with($filename, $root . '/')
    || str_starts_with($filename, $rootReal . '/'));

if ($underRoot) {
  fwrite(STDERR, "::error::getFileName is under DRUPAL_ROOT; unfixed fakeTestModule would stay green.\n");
  exit(1);
}

if ($filename === '' || !is_file($filename)) {
  fwrite(STDERR, "::error::getFileName is missing.\n");
  exit(1);
}
