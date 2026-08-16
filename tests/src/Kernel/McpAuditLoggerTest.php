<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpAuditLoggerTest extends KernelTestBase {

  /**
   * {@inheritdoc}
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
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * @covers ::log
   */
  public function testLogWritesRow(): void {
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'article',
      'id' => '42',
      'label' => 'Test',
      'operation' => 'create',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $this->assertSame('entity_save', $row['operation']);
    $this->assertSame('node', $row['entity_type']);
    $this->assertSame('42', $row['entity_id']);
    $this->assertStringContainsString('create', $row['metadata']);
  }

  /**
   * The connector's X-MCP-Client label is recorded for audit (log-only).
   *
   * Integration Contract v1.0: the header is captured into the audit metadata
   * as `mcp_client` and is never an enforcement signal — governance keys on the
   * authenticated role and OAuth scopes, not on this client-supplied header.
   *
   * @covers ::log
   */
  public function testLogCapturesMcpClientHeader(): void {
    $this->container->get('request_stack')->getCurrentRequest()->headers
      ->set('X-MCP-Client', 'drupal-mcp-connector/0.6.0');

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'entity_type' => 'node',
      'bundle' => 'page',
      'id' => '7',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('drupal-mcp-connector/0.6.0', $metadata['mcp_client'] ?? NULL);
  }

  /**
   * A request without the X-MCP-Client header records no mcp_client label.
   *
   * @covers ::log
   */
  public function testLogOmitsMcpClientWhenHeaderAbsent(): void {
    // The booted kernel request carries no X-MCP-Client header.
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '8']);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertArrayNotHasKey('mcp_client', $metadata ?? []);
  }

  /**
   * No attested bundle means the row does not invent a digest.
   *
   * @covers ::log
   */
  public function testLogOmitsPolicyBundleDigestWhenNoneActive(): void {
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '9']);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertArrayNotHasKey('policy_bundle_digest', $metadata ?? []);
  }

  /**
   * An attested digest is cited on every ordinary audit row.
   *
   * @covers ::log
   */
  public function testLogCitesActivePolicyBundleDigest(): void {
    $this->container->get('state')->set(McpPolicyBundleRegistry::STATE_ACTIVE, [
      'digest' => 'sha256:cited-floor',
      'activated_at' => 1,
    ]);

    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '10']);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertSame('sha256:cited-floor', $metadata['policy_bundle_digest'] ?? NULL);
  }

  /**
   * LogAlways cites the attested digest even when audit_enabled is off.
   *
   * @covers ::logAlways
   */
  public function testLogAlwaysCitesActivePolicyBundleDigest(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $this->container->get('state')->set(McpPolicyBundleRegistry::STATE_ACTIVE, [
      'digest' => 'sha256:always-floor',
      'activated_at' => 1,
    ]);

    $this->container->get('mcp_sentinel.audit_logger')->logAlways('config_save_break_glass', [
      'id' => '11',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertSame('sha256:always-floor', $metadata['policy_bundle_digest'] ?? NULL);
  }

  /**
   * A caller that already named a digest keeps that value.
   *
   * @covers ::log
   */
  public function testLogPreservesCallerPolicyBundleDigest(): void {
    $this->container->get('state')->set(McpPolicyBundleRegistry::STATE_ACTIVE, [
      'digest' => 'sha256:active-floor',
      'activated_at' => 1,
    ]);

    $this->container->get('mcp_sentinel.audit_logger')->log('policy_bundle_activate', [
      'policy_bundle_digest' => 'sha256:activating',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->execute()
      ->fetchAssoc();

    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertSame('sha256:activating', $metadata['policy_bundle_digest'] ?? NULL);
  }

  /**
   * @covers ::log
   */
  public function testLogRespectsAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', ['id' => '1']);

    $count = (int) $this->container->get('database')
      ->select('audit_chain_log')->countQuery()->execute()->fetchField();
    $this->assertSame(0, $count);
  }

  /**
   * @covers ::pruneOldEntries
   */
  public function testPruneOldEntries(): void {
    $database = $this->container->get('database');
    $now = $this->container->get('datetime.time')->getRequestTime();
    $database->insert('audit_chain_log')->fields([
      'timestamp' => $now - (100 * 86400),
      'uid' => 0,
      'operation' => 'old',
    ])->execute();
    $database->insert('audit_chain_log')->fields([
      'timestamp' => $now,
      'uid' => 0,
      'operation' => 'fresh',
    ])->execute();

    // Retention defaults to 90 days; the 100-day-old row should be pruned.
    $pruned = $this->container->get('mcp_sentinel.audit_logger')->pruneOldEntries();
    $this->assertSame(1, $pruned);
    $remaining = (int) $database->select('audit_chain_log')->countQuery()->execute()->fetchField();
    $this->assertSame(1, $remaining);
  }

}
