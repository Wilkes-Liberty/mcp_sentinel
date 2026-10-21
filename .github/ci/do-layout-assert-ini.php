<?php

/**
 * @file
 * Fail unless this PHP process has zend.assertions and assert.exception on.
 *
 * Used as auto_prepend_file for the d.o-layout bypass PHPUnit
 * invocation so the job proves the values rather than inferring
 * them from PHP_INI_SCAN_DIR.
 */

declare(strict_types=1);

$assertions = ini_get('zend.assertions');
$exception = ini_get('assert.exception');
fwrite(STDOUT, "zend.assertions={$assertions}\n");
fwrite(STDOUT, "assert.exception={$exception}\n");
if ($assertions !== '1' || $exception !== '1') {
  fwrite(
    STDERR,
    "::error::d.o-layout bypass process must run with zend.assertions=1"
    . " and assert.exception=1; got zend.assertions={$assertions}"
    . " assert.exception={$exception}. PHP_INI_SCAN_DIR did not apply"
    . " to this process.\n",
  );
  exit(1);
}
