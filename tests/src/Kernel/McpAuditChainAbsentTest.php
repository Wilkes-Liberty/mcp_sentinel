<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * The module behaves predictably when audit_chain is not enabled.
 *
 * Not a supported configuration — audit_chain is a hard dependency in the
 * .info.yml — but it is the state a 2.0.0 upgrade lands in for one step, and
 * that step used to take the site down permanently:
 *
 *   composer require drupal/mcp_sentinel:^2.0
 *   drush updatedb
 *
 * The new code arrived before anything could install audit_chain.
 * `mcp_sentinel.audit_logger` held a required reference to
 * `audit_chain.logger`, so the container could not compile, the front end
 * returned 500, and drush could not recover it because drush needs the same
 * container. Rolling back made it worse: at 1.13 audit_chain is only a
 * transitive requirement, so `composer require ^1.13` removed it.
 *
 * Omitting audit_chain from $modules reproduces exactly that state, which is
 * why this is a test rather than a note in an upgrade guide. Kernel tests
 * install only what they list, so this is the real thing and not a simulation.
 */
#[CoversClass(McpAuditLogger::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAuditChainAbsentTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   *
   * Every hard dependency except audit_chain. That omission is the test.
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * The container compiles, which is the whole point.
   *
   * If this fails the site is down and drush cannot fix it. Everything else in
   * this class is about behaving honestly once it is up.
   */
  public function testContainerCompilesWithoutAuditChain(): void {
    $this->assertFalse(
      $this->container->get('module_handler')->moduleExists('audit_chain'),
      'Guard: this test is meaningless if audit_chain got installed anyway.',
    );

    // Container::get() is typed as the service class in the compiled
    // definition, so assertInstanceOf() is a always-true phpstan error.
    // Comparing get_class() asserts the same fact without the noise.
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $this->assertSame(McpAuditLogger::class, $logger::class);
  }

  /**
   * A governed write is refused rather than performed unaudited.
   *
   * The alternative — returning quietly — would let every governed operation
   * proceed with no record while the module reported itself healthy. A
   * governance module that silently stops recording is the exact failure it
   * exists to prevent, so this fails closed and loudly.
   */
  public function testLoggingThrowsInsteadOfSilentlyRecordingNothing(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', TRUE)->save();

    $this->expectException(\RuntimeException::class);
    $this->expectExceptionMessageMatches('/audit_chain module is not enabled/');
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '1']);
  }

  /**
   * Verification refuses too, rather than reporting a chain it cannot see.
   *
   * Returning "ok" would assert an integrity guarantee that was never checked;
   * returning "broken" would be a false accusation. Neither is answerable
   * without the chain.
   */
  public function testVerificationRefusesRatherThanGuessing(): void {
    $this->expectException(\RuntimeException::class);
    $this->container->get('mcp_sentinel.audit_logger')->verifyChain();
  }

  /**
   * Cron-facing retention degrades quietly, because there is nothing to prune.
   *
   * The one place a no-op is honest: with no chain there are no rows, so
   * returning zero states a fact rather than hiding a failure. Taking the whole
   * cron run down over it would help nobody, and hook_requirements() is what
   * reports the missing module.
   */
  public function testPruningReturnsZeroWithoutThrowing(): void {
    $this->assertSame(0, $this->container->get('mcp_sentinel.audit_logger')->pruneOldEntries());
  }

  /**
   * The status report names the missing module, not a missing service.
   *
   * The original failure said "the service mcp_sentinel.audit_logger has a
   * dependency on a non-existent service audit_chain.logger", which tells an
   * operator under pressure nothing about what to do.
   */
  public function testStatusReportNamesTheModuleToEnable(): void {
    $this->container->get('module_handler')->loadInclude('mcp_sentinel', 'install');
    $requirements = mcp_sentinel_requirements('runtime');

    $this->assertArrayHasKey('mcp_sentinel_audit_chain_missing', $requirements);
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['mcp_sentinel_audit_chain_missing']['severity'],
    );
    $this->assertStringContainsString(
      'audit_chain',
      (string) $requirements['mcp_sentinel_audit_chain_missing']['description'],
    );
  }

}
