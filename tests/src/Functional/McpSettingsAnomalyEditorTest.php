<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the anomaly rules multi-row editor on the settings form.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpSettingsAnomalyEditorTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Stored rules render as rows and round-trip byte-identically.
   */
  public function testRulesRenderAsRowsAndRoundTrip(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'denied_storm',
        'label' => 'Denied storm',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 20,
        'debounce_seconds' => 3600,
        'enabled' => FALSE,
      ],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->fieldValueEquals('anomaly_rules_rows[0][id]', 'denied_storm');
    $this->assertSession()->fieldValueEquals('anomaly_rules_rows[0][threshold]', '20');
    $this->submitForm([], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('anomaly_rules');
    $this->assertSame([[
      'id' => 'denied_storm',
      'label' => 'Denied storm',
      'operation_pattern' => 'denied_access',
      'window_seconds' => 300,
      'threshold' => 20,
      'debounce_seconds' => 3600,
      'enabled' => FALSE,
    ],
    ], $stored);
  }

  /**
   * Adding and removing rows mutates the stored sequence in the same shape.
   */
  public function testAddAndRemoveRowMutateStoredSequence(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'denied_storm',
        'label' => 'Denied storm',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 20,
        'debounce_seconds' => 3600,
        'enabled' => FALSE,
      ],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    // One stored rule + one blank trailing row. Fill the blank and add another.
    $this->submitForm([
      'anomaly_rules_rows[1][id]' => 'write_burst',
      'anomaly_rules_rows[1][label]' => 'Write burst',
      'anomaly_rules_rows[1][operation_pattern]' => 'entity_save',
      'anomaly_rules_rows[1][window_seconds]' => '60',
      'anomaly_rules_rows[1][threshold]' => '50',
      'anomaly_rules_rows[1][debounce_seconds]' => '600',
      'anomaly_rules_rows[1][enabled]' => 1,
    ], 'Add rule');
    $this->submitForm([], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('anomaly_rules');
    $this->assertSame([
      [
        'id' => 'denied_storm',
        'label' => 'Denied storm',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 20,
        'debounce_seconds' => 3600,
        'enabled' => FALSE,
      ],
      [
        'id' => 'write_burst',
        'label' => 'Write burst',
        'operation_pattern' => 'entity_save',
        'window_seconds' => 60,
        'threshold' => 50,
        'debounce_seconds' => 600,
        'enabled' => TRUE,
      ],
    ], $stored);

    // Remove the first rule via its own button; only write_burst remains.
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([], 'Remove rule 1');
    $this->submitForm([], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('anomaly_rules');
    $this->assertSame([[
      'id' => 'write_burst',
      'label' => 'Write burst',
      'operation_pattern' => 'entity_save',
      'window_seconds' => 60,
      'threshold' => 50,
      'debounce_seconds' => 600,
      'enabled' => TRUE,
    ],
    ], $stored);
  }

  /**
   * An off-hours signal is stored; a count signal is omitted.
   */
  public function testOffHoursSignalIsStoredAndCountIsOmitted(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_hours_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'after_hours',
        'label' => 'After hours',
        'operation_pattern' => 'entity_read',
        'signal' => 'off_hours',
        'window_seconds' => 300,
        'threshold' => 1,
        'debounce_seconds' => 3600,
        'enabled' => TRUE,
      ]])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->fieldValueEquals('anomaly_rules_rows[0][signal]', 'off_hours');
    $this->submitForm([], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('anomaly_rules');
    $this->assertSame('off_hours', $stored[0]['signal'] ?? NULL);
  }

  /**
   * A duplicate rule id is rejected.
   */
  public function testDuplicateRuleIdRejected(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'anomaly_rules_rows[0][id]' => 'r',
      'anomaly_rules_rows[0][operation_pattern]' => 'x',
      'anomaly_rules_rows[0][window_seconds]' => '60',
      'anomaly_rules_rows[0][threshold]' => '5',
      'anomaly_rules_rows[1][id]' => 'r',
      'anomaly_rules_rows[1][operation_pattern]' => 'y',
      'anomaly_rules_rows[1][window_seconds]' => '60',
      'anomaly_rules_rows[1][threshold]' => '5',
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('Duplicate anomaly rule id');
  }

}
