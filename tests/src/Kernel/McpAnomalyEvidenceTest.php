<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAnomalyEvidence;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel tests for bounded anomaly evidence.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAnomalyEvidence
 * @group mcp_sentinel
 */
#[CoversClass(McpAnomalyEvidence::class)]
#[Group('mcp_sentinel')]
final class McpAnomalyEvidenceTest extends KernelTestBase {

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
    $this->installConfig(['mcp_sentinel', 'system']);
    $this->installAuditChainSchema();
  }

  /**
   * Summarize groups by host, client, Origin, IP, and reason.
   *
   * @covers ::summarize
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryGroupsBySourceAndReason(): void {
    $this->config('system.site')->set('name', 'Example MCP site')->save();
    $this->seedDenial('missing_bearer', 'example-client', 3);
    $this->seedDenial('insufficient_scope', 'other-client', 2);

    $summary = $this->container->get('mcp_sentinel.anomaly_evidence')
      ->deniedAccessSummary(300, 8);
    $this->assertSame('Example MCP site', $summary['site']['site']);
    $this->assertSame(300, $summary['window_seconds']);
    $this->assertSame(5, $summary['count']);
    $this->assertSame(5, $summary['scanned']);
    $this->assertFalse($summary['truncated']);
    $this->assertCount(2, $summary['groups']);
    $this->assertSame('missing_bearer', $summary['groups'][0]['reason']);
    $this->assertSame(3, $summary['groups'][0]['count']);
    $this->assertSame('example-client', $summary['groups'][0]['client']);
    $this->assertSame('https://client.example.test', $summary['groups'][0]['origin']);
    $this->assertSame('192.0.2.10', $summary['groups'][0]['ip']);
    $this->assertSame('https://mcp.example.test', $summary['groups'][0]['host']);
    $this->assertSame('insufficient_scope', $summary['groups'][1]['reason']);
    $this->assertSame(2, $summary['groups'][1]['count']);
  }

  /**
   * Environment comes from settings.php, not config.
   *
   * @covers ::siteIdentity
   */
  public function testSiteIdentityReadsEnvironmentFromSettings(): void {
    $this->config('system.site')->set('name', 'Example MCP site')->save();
    $this->setSetting('mcp_sentinel.environment', 'staging');
    $identity = $this->container->get('mcp_sentinel.anomaly_evidence')
      ->siteIdentity();
    $this->assertSame('Example MCP site', $identity['site']);
    $this->assertSame('staging', $identity['environment']);
    $this->assertNotSame('', $identity['host']);
  }

  /**
   * Top N is a hard cap on groups.
   *
   * @covers ::summarize
   */
  public function testSummarizeCapsTopN(): void {
    for ($i = 0; $i < 5; $i++) {
      $this->seedDenial('reason-' . $i, 'client-' . $i, 1);
    }
    $since = $this->container->get('datetime.time')->getRequestTime() - 300;
    $summary = $this->container->get('mcp_sentinel.anomaly_evidence')
      ->summarize('denied_access', $since, 'count', [], 3);
    $this->assertCount(3, $summary['groups']);
    $this->assertCount(3, $summary['reasons']);
    $this->assertCount(3, $summary['sources']);
  }

  /**
   * Count is un-capped; scanned stops at the scan cap and truncated is set.
   *
   * @covers ::deniedAccessSummary
   */
  public function testDeniedAccessSummaryReportsTruncation(): void {
    $this->seedDenial('missing_bearer', 'example-client', 3);
    $evidence = new McpAnomalyEvidence(
      $this->container->get('database'),
      $this->container->get('config.factory'),
      $this->container->get('settings'),
      $this->container->get('request_stack'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.dlp'),
      $this->container->get('mcp_sentinel.anomaly_detector'),
      $this->container->get('datetime.time'),
      2,
    );
    $summary = $evidence->deniedAccessSummary(300, 8);
    $this->assertSame(3, $summary['count']);
    $this->assertSame(2, $summary['scanned']);
    $this->assertTrue($summary['truncated']);
  }

  /**
   * Writes one or more denied_access rows with documentation forensic labels.
   *
   * @param string $reason
   *   Reason code.
   * @param string $clientId
   *   OAuth client id.
   * @param int $times
   *   How many rows to write.
   */
  private function seedDenial(string $reason, string $clientId, int $times): void {
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'REMOTE_ADDR' => '192.0.2.10',
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
    ]);
    $this->pushRequestKeepingSession($request);
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    for ($i = 0; $i < $times; $i++) {
      $logger->logAlways('denied_access', [
        'reason' => $reason,
        'client_id' => $clientId,
        'tenant' => 'tenant-a',
      ]);
    }
  }

}
