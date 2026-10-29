<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAuditLogger
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpAuditLoggerTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

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
    $this->installAuditChainSchema();
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
   * An entity id over 255 bytes is hashed so the denial row still writes.
   *
   * audit_chain 1.13.0 copies metadata.id onto entity_id varchar(255)
   * without truncating it (it does truncate label). MySQL 8 strict
   * mode refuses the insert; SQLite stores the oversize value. The
   * logger must bound the column field and keep the original in
   * metadata so a 256-character principal subject cannot drop the
   * denied_access row (d.o pipeline 1023398).
   *
   * @covers ::logAlways
   */
  public function testOversizedEntityIdIsHashedAndStillWritten(): void {
    $id = str_repeat('b', 256);
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'entity_type' => 'principal',
      'id' => $id,
      'reason' => 'part_too_long',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id', 'metadata', 'operation'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $this->assertLessThanOrEqual(255, strlen((string) $row['entity_id']));
    $this->assertSame('sha256:' . hash('sha256', $id), $row['entity_id']);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $this->assertSame($id, $meta['id_original'] ?? NULL);
    $this->assertSame(hash('sha256', $id), $meta['id_sha256'] ?? NULL);
    $this->assertSame('part_too_long', $meta['reason'] ?? NULL);
  }

  /**
   * An entity id of exactly 255 bytes is stored unchanged.
   *
   * @covers ::logAlways
   */
  public function testEntityIdAtColumnLimitIsUnchanged(): void {
    $id = str_repeat('c', 255);
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'id' => $id,
      'reason' => 'ok',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $this->assertSame($id, $row['entity_id']);
  }

  /**
   * Denied-access rows are written when audit_enabled is off.
   *
   * @covers ::log
   */
  public function testDeniedAccessLoggedWhenAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $this->container->get('mcp_sentinel.audit_logger')->log('denied_access', [
      'tool' => 'mcp_sentinel_principal_context_probe',
      'principal_key' => 'iss|sub|azp',
      'human_key' => 'iss|sub',
    ]);

    $count = (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(1, $count);
  }

  /**
   * Denied_access rows record Origin and Host for operator grouping.
   *
   * @covers ::log
   */
  public function testDeniedAccessCapturesOriginAndHost(): void {
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
      'REMOTE_ADDR' => '192.0.2.10',
    ]);
    $this->pushRequestKeepingSession($request);
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'reason' => 'missing_bearer',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('l.operation', 'denied_access')
      ->execute()
      ->fetchAssoc();
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('https://client.example.test', $metadata['http_origin'] ?? NULL);
    $this->assertSame('https://mcp.example.test', $metadata['http_host'] ?? NULL);
    $this->assertSame('192.0.2.10', $row['ip_address']);
  }

  /**
   * Origin and Host survive a rolled-back transaction.
   *
   * @covers ::logSurvivingRollback
   */
  public function testDeniedAccessCapturesOriginAndHostSurvivingRollback(): void {
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
      'REMOTE_ADDR' => '192.0.2.10',
    ]);
    $this->pushRequestKeepingSession($request);
    $database = $this->container->get('database');
    $transaction = $database->startTransaction();
    $this->container->get('mcp_sentinel.audit_logger')->logSurvivingRollback('denied_access', [
      'reason' => 'missing_bearer',
    ]);
    $transaction->rollBack();
    unset($transaction);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('l.operation', 'denied_access')
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row);
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('https://client.example.test', $metadata['http_origin'] ?? NULL);
    $this->assertSame('https://mcp.example.test', $metadata['http_host'] ?? NULL);
  }

  /**
   * Allow-path rows do not grow Origin/Host keys.
   *
   * @covers ::log
   */
  public function testAllowPathOmitsOriginAndHost(): void {
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
    ]);
    $this->pushRequestKeepingSession($request);
    $this->container->get('mcp_sentinel.audit_logger')->log('entity_save', [
      'id' => '11',
    ]);

    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('l.operation', 'entity_save')
      ->execute()
      ->fetchAssoc();
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertArrayNotHasKey('http_origin', $metadata ?? []);
    $this->assertArrayNotHasKey('http_host', $metadata ?? []);
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

    // Retention defaults to 90 days. Audit Chain 1.8.0 refuses destructive
    // per-channel prune so a shared chain cannot lose a predecessor; Sentinel
    // still asks, nothing is deleted, and the refusal is recorded.
    $pruned = $this->container->get('mcp_sentinel.audit_logger')->pruneOldEntries();
    $this->assertSame(0, $pruned);
    $remaining = (int) $database->select('audit_chain_log')->countQuery()->execute()->fetchField();
    $this->assertSame(2, $remaining);
    $this->assertTrue(
      (bool) $this->container->get('state')->get('audit_chain.retention_refused'),
      'Expired rows must surface as a retention refusal, not a silent keep.',
    );
  }

}
