<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use ColinODell\PsrTestLogger\TestLogger;
use Drupal\Core\Database\Connection;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAlertDispatcher;
use Drupal\mcp_sentinel\Service\McpAnomalyEvidence;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel tests for the McpAlertDispatcher service.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAlertDispatcher
 */
#[Group('mcp_sentinel')]
class McpAlertDispatcherTest extends KernelTestBase {

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
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_webhook_delivery',
    ]);
  }

  /**
   * Tests that dispatch() does nothing when given an empty array.
   */
  public function testDispatchEmptyDoesNothing(): void {
    // Should complete without errors or mail.
    $this->config('system.mail')
      ->set('interface.default', 'test_mail_collector')
      ->save();
    \Drupal::state()->set('system.test_mail_collector', []);
    $this->container->get('mcp_sentinel.anomaly_alert_dispatcher')->dispatch([]);
    $captured = \Drupal::state()->get('system.test_mail_collector') ?? [];
    $this->assertEmpty($captured, 'No mail should be sent for an empty dispatch.');
  }

  /**
   * Tests that the log channel receives a warning when anomaly_alert_log=TRUE.
   *
   * Injects a TestLogger spy as logger.channel.mcp_sentinel and asserts:
   *   - exactly one warning-level record is emitted for the fired rule.
   *   - the record's message contains the rule ID.
   *   - no email is sent (log-only channel).
   */
  public function testAlertLogsToChannel(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', TRUE)
      ->set('anomaly_alert_email', '')
      ->set('anomaly_alert_webhook', FALSE)
      ->save();

    // Inject a capturing spy logger so the warning assertion is concrete.
    $spy = new TestLogger();
    $this->container->set('logger.channel.mcp_sentinel', $spy);

    // Verify no email is sent (log-only channel).
    $this->config('system.mail')
      ->set('interface.default', 'test_mail_collector')
      ->save();
    \Drupal::state()->set('system.test_mail_collector', []);

    $dispatcher = $this->container->get('mcp_sentinel.anomaly_alert_dispatcher');
    $dispatcher->dispatch([[
      'rule' => [
        'id'             => 'test_rule',
        'label'          => 'Test Rule',
        'window_seconds' => 60,
        'threshold'      => 10,
        'debounce_seconds' => 3600,
      ],
      'count' => 15,
    ],
    ]);

    // The logger channel must have received exactly one warning for the rule.
    $warnings = array_filter(
      $spy->records,
      static fn(array $r) => $r['level'] === 'warning',
    );
    $this->assertCount(1, $warnings, 'Exactly one warning must be emitted for a single fired rule.');
    $record = reset($warnings);
    // The PSR-3 message is a template string; the rule ID is in the context.
    $this->assertStringContainsString(
      'mcp_sentinel_anomaly_alert',
      (string) $record['message'],
      'Warning message template must contain the sentinel prefix.',
    );
    $this->assertSame(
      'test_rule',
      (string) ($record['context']['@rule'] ?? ''),
      'Warning context must carry the rule ID under the @rule key.',
    );

    // Log-only channel: no email should be sent.
    $captured = \Drupal::state()->get('system.test_mail_collector') ?? [];
    $this->assertEmpty($captured, 'Log-only channel must not send email.');
  }

  /**
   * Tests that email is sent when anomaly_alert_email is non-empty.
   *
   * Uses Drupal's test mail collector to capture outbound mail.
   */
  public function testAlertSendsEmailWhenAddressConfigured(): void {
    // Enable the test mail plugin so mails are captured in state.
    $this->config('system.mail')
      ->set('interface.default', 'test_mail_collector')
      ->save();

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_email', 'ops@example.com')
      ->set('anomaly_alert_webhook', FALSE)
      ->save();

    $dispatcher = $this->container->get('mcp_sentinel.anomaly_alert_dispatcher');
    $dispatcher->dispatch([[
      'rule' => [
        'id'             => 'email_test',
        'label'          => 'Email Test Rule',
        'window_seconds' => 300,
        'threshold'      => 5,
        'debounce_seconds' => 3600,
      ],
      'count' => 8,
    ],
    ]);

    $captured = \Drupal::state()->get('system.test_mail_collector') ?? [];
    $this->assertNotEmpty($captured, 'At least one email should be captured.');
    $last = end($captured);
    $this->assertSame('ops@example.com', $last['to']);
    $this->assertStringContainsString('Email Test Rule', (string) $last['subject']);
  }

  /**
   * Tests that no email is sent when anomaly_alert_email is empty.
   */
  public function testNoEmailWhenAddressEmpty(): void {
    $this->config('system.mail')
      ->set('interface.default', 'test_mail_collector')
      ->save();

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_email', '')
      ->set('anomaly_alert_webhook', FALSE)
      ->save();

    // Clear any previously collected mail.
    \Drupal::state()->set('system.test_mail_collector', []);

    $dispatcher = $this->container->get('mcp_sentinel.anomaly_alert_dispatcher');
    $dispatcher->dispatch([[
      'rule' => [
        'id'             => 'no_email_rule',
        'label'          => 'No Email',
        'window_seconds' => 60,
        'threshold'      => 1,
        'debounce_seconds' => 0,
      ],
      'count' => 5,
    ],
    ]);

    $captured = \Drupal::state()->get('system.test_mail_collector') ?? [];
    $this->assertEmpty($captured, 'No email should be sent when address is empty.');
  }

  /**
   * Tests that the webhook channel enqueues a delivery row.
   */
  public function testAlertEnqueuesWebhookWhenEnabled(): void {
    // Configure an HTTPS webhook endpoint.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_email', '')
      ->set('anomaly_alert_webhook', TRUE)
      ->set('webhook_endpoints', [[
        'id'             => 'alert_ep',
        'label'          => 'Alert endpoint',
        'url'            => 'https://example.com/hook',
        'secret_key'     => '',
        'events'         => [],
        'enabled'        => TRUE,
        'allow_internal' => FALSE,
      ],
      ])
      ->save();

    $dispatcher = $this->container->get('mcp_sentinel.anomaly_alert_dispatcher');
    $dispatcher->dispatch([[
      'rule' => [
        'id'             => 'webhook_rule',
        'label'          => 'Webhook Rule',
        'window_seconds' => 300,
        'threshold'      => 5,
        'debounce_seconds' => 3600,
      ],
      'count' => 10,
    ],
    ]);

    // Verify a delivery row was inserted.
    $row = \Drupal::database()
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['event_name', 'status', 'endpoint_id', 'payload'])
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row, 'A webhook delivery row should exist.');
    $this->assertSame('mcp.anomaly.alert', $row['event_name']);
    $this->assertSame('pending', $row['status']);
    $this->assertSame('alert_ep', $row['endpoint_id']);
    $payload = json_decode((string) $row['payload'], TRUE);
    $this->assertIsArray($payload);
    $this->assertArrayHasKey('site', $payload);
    $this->assertArrayHasKey('host', $payload);
    $this->assertArrayHasKey('environment', $payload);
    $this->assertArrayHasKey('sources', $payload);
    $this->assertArrayHasKey('reasons', $payload);
    $this->assertArrayHasKey('tenants', $payload);
    $this->assertArrayNotHasKey('token', $payload);
    $this->assertArrayNotHasKey('authorization', $payload);
    $this->assertArrayNotHasKey('payload', $payload);
  }

  /**
   * A fired rule writes bounded audit evidence and no payload.
   */
  public function testDispatchWritesBoundedAuditEvidence(): void {
    $this->config('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_email', '')
      ->set('anomaly_alert_webhook', FALSE)
      ->set('audit_enabled', TRUE)
      ->save();

    $this->container->get('mcp_sentinel.anomaly_alert_dispatcher')->dispatch([[
      'rule' => [
        'id' => 'evidence_rule',
        'label' => 'Evidence',
        'signal' => 'bulk_read',
        'operation_pattern' => 'entity_read*',
        'window_seconds' => 300,
        'threshold' => 5,
      ],
      'count' => 7,
      'signal' => 'bulk_read',
      'actor' => [4, 9],
      'target_scope' => ['node'],
      'rule_version' => 'sha256:fixture',
      'window' => 300,
      'threshold' => 5,
      'outcome' => 'fired',
    ],
    ]);

    $row = \Drupal::database()
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('l.operation', 'anomaly_alert')
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row);
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('bulk_read', $metadata['signal']);
    $this->assertSame([4, 9], $metadata['actor']);
    $this->assertSame(['node'], $metadata['target_scope']);
    $this->assertSame('sha256:fixture', $metadata['rule_version']);
    $this->assertSame(300, $metadata['window']);
    $this->assertSame(5, $metadata['threshold']);
    $this->assertSame('fired', $metadata['outcome']);
    $this->assertSame('evidence_rule', $metadata['rule_id']);
    $this->assertSame(7, $metadata['count']);
    $this->assertArrayNotHasKey('payload', $metadata);
    $this->assertArrayNotHasKey('password', $metadata);
    $this->assertArrayNotHasKey('credentials', $metadata);
    $this->assertStringNotContainsString('secret', (string) $row['metadata']);
    $this->assertArrayHasKey('site', $metadata);
    $this->assertArrayHasKey('host', $metadata);
    $this->assertArrayHasKey('environment', $metadata);
    $this->assertArrayHasKey('sources', $metadata);
    $this->assertArrayHasKey('reasons', $metadata);
    $this->assertArrayHasKey('tenants', $metadata);
  }

  /**
   * Every enrichment field is present on the anomaly email body.
   *
   * This test fails if Site, Host, Environment, Window, Threshold, top
   * sources, reason codes, or tenants drop out of the shared renderer.
   */
  public function testAlertEmailIncludesTriageFields(): void {
    $this->config('system.site')->set('name', 'Example MCP site')->save();
    $this->enableMailCollector();
    $this->pushDenialRequest();
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'reason' => 'missing_bearer',
      'client_id' => 'example-client',
      'principal_key' => 'iss|example-sub|actor',
      'tenant' => 'tenant-a',
    ]);

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_email', 'ops@example.com')
      ->set('anomaly_alert_webhook', FALSE)
      ->save();

    $this->container->get('mcp_sentinel.anomaly_alert_dispatcher')->dispatch([[
      'rule' => [
        'id' => 'denied_access_storm',
        'label' => 'Denied access storm',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 20,
      ],
      'count' => 54,
      'window' => 300,
      'threshold' => 20,
    ],
    ]);

    $body = $this->lastMailBody();
    $this->assertStringContainsString('Site: Example MCP site', $body);
    $this->assertStringContainsString('Host:', $body);
    $this->assertStringContainsString('Environment: (unset)', $body);
    $this->assertStringContainsString('Window: 300 s', $body);
    $this->assertStringContainsString('Threshold: 20', $body);
    $this->assertStringContainsString('Top sources', $body);
    $this->assertStringContainsString('client=example-client', $body);
    $this->assertStringContainsString('mcp_client=example-mcp-client (self-reported)', $body);
    $this->assertStringContainsString('origin=https://client.example.test', $body);
    $this->assertStringContainsString('host=https://mcp.example.test', $body);
    $this->assertStringContainsString('ip=192.0.2.10', $body);
    $this->assertStringContainsString('principal=iss|example-sub|actor', $body);
    $this->assertStringContainsString('Reason codes:', $body);
    $this->assertStringContainsString('missing_bearer: 1', $body);
    $this->assertStringContainsString('Tenants:', $body);
    $this->assertStringContainsString('tenant-a: 1', $body);
  }

  /**
   * Secrets on denied_access metadata never appear in the email body.
   */
  public function testAlertEmailOmitsSecrets(): void {
    $this->enableMailCollector();
    $jwt = implode('.', [
      rtrim(strtr(base64_encode('{"alg":"HS256","typ":"JWT"}'), '+/', '-_'), '='),
      rtrim(strtr(base64_encode('{"sub":"1234567890"}'), '+/', '-_'), '='),
      'sig',
    ]);
    $basic = 'Basic ' . base64_encode('user:pass');
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'REMOTE_ADDR' => '192.0.2.10',
      'HTTP_ORIGIN' => 'https://user:pass@client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
      'HTTP_X_MCP_CLIENT' => 'example-mcp-client',
    ]);
    $this->pushRequestKeepingSession($request);
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'reason' => "Authorization: Bearer secret-token-value $basic $jwt\r\nSite: forged.example.test",
      'token' => 'secret-token-value',
      'authorization' => 'Bearer secret-token-value',
      'payload' => '{"password":"secret-token-value"}',
      'client_id' => 'https://user:pass@client.example.test/cb?access_token=leaked-access-token',
    ]);

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_email', 'ops@example.com')
      ->set('anomaly_alert_webhook', FALSE)
      ->save();

    $this->container->get('mcp_sentinel.anomaly_alert_dispatcher')->dispatch([[
      'rule' => [
        'id' => 'denied_access_storm',
        'label' => 'Denied access storm',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 20,
      ],
      'count' => 21,
      'window' => 300,
      'threshold' => 20,
    ],
    ]);

    $body = $this->lastMailBody();
    $this->assertStringNotContainsString('secret-token-value', $body);
    $this->assertStringNotContainsString('Bearer secret-token-value', $body);
    $this->assertStringNotContainsString('password', $body);
    $this->assertStringNotContainsString($basic, $body);
    $this->assertStringNotContainsString(base64_encode('user:pass'), $body);
    $this->assertStringNotContainsString($jwt, $body);
    $this->assertStringNotContainsString('user:pass', $body);
    $this->assertStringNotContainsString('leaked-access-token', $body);
    $this->assertStringNotContainsString('access_token=leaked-access-token', $body);
    foreach (preg_split("/\r\n|\n|\r/", $body) ?: [] as $line) {
      $this->assertNotSame(
        'Site: forged.example.test',
        trim($line),
        'A CRLF value must not forge a Site: line.',
      );
    }
    $this->assertStringContainsString('Site:', $body);
    $this->assertStringContainsString('Host:', $body);
    $this->assertStringContainsString('Environment:', $body);
    $this->assertStringContainsString('Window:', $body);
    $this->assertStringContainsString('Threshold:', $body);
    $this->assertStringContainsString('Top sources', $body);
    $this->assertStringContainsString('Reason codes:', $body);
    $this->assertStringContainsString('Tenants:', $body);
    $this->assertStringContainsString('Bearer [REDACTED]', $body);
    $this->assertStringContainsString('Basic [REDACTED]', $body);
  }

  /**
   * Enrichment failure still writes email, webhook, and audit for every rule.
   */
  public function testDispatchKeepsBothRulesWhenEnrichmentThrows(): void {
    $this->enableMailCollector();
    $this->enableAnomalyWebhook();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_email', 'ops@example.com')
      ->save();
    $connection = $this->createMock(Connection::class);
    $connection->method('select')->willThrowException(
      new \RuntimeException('select failed'),
    );
    $evidence = new McpAnomalyEvidence(
      $connection,
      $this->container->get('config.factory'),
      $this->container->get('settings'),
      $this->container->get('request_stack'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.dlp'),
      $this->container->get('mcp_sentinel.anomaly_detector'),
      $this->container->get('datetime.time'),
    );
    $dispatcher = new McpAlertDispatcher(
      $this->container->get('config.factory'),
      $this->container->get('logger.channel.mcp_sentinel'),
      $this->container->get('plugin.manager.mail'),
      $this->container->get('mcp_sentinel.webhook_queue_manager'),
      $this->container->get('language_manager'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $evidence,
    );

    try {
      $dispatcher->dispatch([
        $this->firedRule('rule_a', 'Rule A', 21),
        $this->firedRule('rule_b', 'Rule B', 22),
      ]);
    }
    catch (\Throwable) {
      // An uncaught enrichment exception must not become a PHPUnit error.
    }

    $captured = \Drupal::state()->get('system.test_mail_collector') ?? [];
    $this->assertCount(2, $captured, 'Both rules must still send email.');
    $bodies = [];
    foreach ($captured as $mail) {
      $body = $mail['body'] ?? '';
      $bodies[] = is_array($body) ? implode("\n", $body) : (string) $body;
    }
    $this->assertStringContainsString(
      'Rule "Rule A" triggered: 21 operations in 300 s (threshold 20).',
      $bodies[0],
    );
    $this->assertStringContainsString(
      'Rule "Rule B" triggered: 22 operations in 300 s (threshold 20).',
      $bodies[1],
    );
    $this->assertStringContainsString('Triage details unavailable (RuntimeException)', $bodies[0]);
    $this->assertStringContainsString('Triage details unavailable (RuntimeException)', $bodies[1]);

    $deliveries = \Drupal::database()
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['payload'])
      ->condition('d.event_name', 'mcp.anomaly.alert')
      ->execute()
      ->fetchCol();
    $this->assertCount(2, $deliveries, 'Both rules must still enqueue a webhook.');

    $alerts = \Drupal::database()
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'anomaly_alert')
      ->execute()
      ->fetchCol();
    $this->assertCount(2, $alerts, 'Both rules must still write an anomaly_alert row.');
  }

  /**
   * A 200-byte multibyte Origin still produces a decodable webhook payload.
   */
  public function testAlertWebhookDecodesMultibyteOrigin(): void {
    $this->enableAnomalyWebhook();
    $origin = 'https://x' . str_repeat("\u{00E9}", 95);
    $this->assertGreaterThan(128, strlen($origin));
    $this->container->get('mcp_sentinel.audit_logger')->logAlways('denied_access', [
      'reason' => 'missing_bearer',
      'client_id' => 'mb-client',
      'http_origin' => $origin,
    ]);

    $this->container->get('mcp_sentinel.anomaly_alert_dispatcher')->dispatch([
      $this->firedRule('denied_access_storm', 'Denied access storm', 21),
    ]);

    $row = \Drupal::database()
      ->select('mcp_sentinel_webhook_delivery', 'd')
      ->fields('d', ['payload'])
      ->condition('d.event_name', 'mcp.anomaly.alert')
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row, 'A webhook delivery row must exist.');
    $payload = json_decode((string) $row['payload'], TRUE);
    $this->assertIsArray($payload);
    $this->assertArrayHasKey('sources', $payload);
    $this->assertNotEmpty($payload['sources']);
    $labelled = (string) ($payload['sources'][0]['origin'] ?? '');
    $this->assertNotSame('', $labelled);
    $this->assertStringNotContainsString(
      "\xEF\xBF\xBD",
      $labelled,
      'A byte-level cut must not leave a replacement character in Origin.',
    );
    $this->assertSame(
      mb_strcut($origin, 0, McpAnomalyEvidence::LABEL_MAX, 'UTF-8'),
      $labelled,
    );
  }

  /**
   * Enables Drupal's test mail collector.
   */
  private function enableMailCollector(): void {
    $this->config('system.mail')
      ->set('interface.default', 'test_mail_collector')
      ->save();
    \Drupal::state()->set('system.test_mail_collector', []);
  }

  /**
   * Pushes a denial request with documentation Origin, Host, and IP.
   */
  private function pushDenialRequest(): void {
    $request = Request::create('https://mcp.example.test/mcp', 'POST', [], [], [], [
      'REMOTE_ADDR' => '192.0.2.10',
      'HTTP_ORIGIN' => 'https://client.example.test',
      'HTTP_HOST' => 'mcp.example.test',
      'HTTP_X_MCP_CLIENT' => 'example-mcp-client',
    ]);
    $this->pushRequestKeepingSession($request);
  }

  /**
   * Enables webhook delivery for mcp.anomaly.alert.
   */
  private function enableAnomalyWebhook(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_alert_log', FALSE)
      ->set('anomaly_alert_webhook', TRUE)
      ->set('webhook_endpoints', [[
        'id' => 'alert_ep',
        'label' => 'Alert endpoint',
        'url' => 'https://example.com/hook',
        'secret_key' => '',
        'events' => [],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])
      ->save();
  }

  /**
   * One fired-rule fixture.
   *
   * @return array<string, mixed>
   *   Detector result.
   */
  private function firedRule(string $id, string $label, int $count): array {
    return [
      'rule' => [
        'id' => $id,
        'label' => $label,
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 20,
      ],
      'count' => $count,
      'window' => 300,
      'threshold' => 20,
    ];
  }

  /**
   * Body of the last captured mail, as one string.
   */
  private function lastMailBody(): string {
    $captured = \Drupal::state()->get('system.test_mail_collector') ?? [];
    $this->assertNotEmpty($captured, 'An anomaly email must be captured.');
    $last = end($captured);
    $body = $last['body'] ?? '';
    return is_array($body) ? implode("\n", $body) : (string) $body;
  }

}
