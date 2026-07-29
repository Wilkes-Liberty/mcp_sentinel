<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use ColinODell\PsrTestLogger\TestLogger;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for the McpAlertDispatcher service.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAlertDispatcher
 */
#[Group('mcp_sentinel')]
class McpAlertDispatcherTest extends KernelTestBase {

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
    $this->installSchema('audit_chain', ['audit_chain_log']);
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
      ->fields('d', ['event_name', 'status', 'endpoint_id'])
      ->execute()
      ->fetchAssoc();
    $this->assertNotFalse($row, 'A webhook delivery row should exist.');
    $this->assertSame('mcp.anomaly.alert', $row['event_name']);
    $this->assertSame('pending', $row['status']);
    $this->assertSame('alert_ep', $row['endpoint_id']);
  }

}
