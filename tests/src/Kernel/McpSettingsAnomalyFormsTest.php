<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Component\Utility\NestedArray;
use Drupal\Core\Form\FormState;
use Drupal\Core\Render\Element;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Form\McpSettingsForm;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Bulk-read keys on anomaly rules survive an untouched Settings save.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSettingsAnomalyFormsTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt',
    'audit_chain', 'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('path_alias');
    $this->installSchema('system', ['sequences']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks', 'mcp_sentinel_webhook_delivery']);
    $this->installConfig(['mcp_sentinel', 'user']);
    // The shipped governed_roles default names mcp_api; the checkboxes element
    // rejects a submitted value that is not one of its options.
    Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
  }

  /**
   * Collects every processed element's default value, keyed by #parents.
   *
   * Lets a test submit a form programmatically with the same values it would
   * carry untouched, then override only the elements under test.
   */
  private function defaultValues(array $form): array {
    $values = [];
    foreach (Element::children($form) as $key) {
      $element = $form[$key];
      if (is_array($element) && array_key_exists('#default_value', $element) && isset($element['#parents']) && ($element['#input'] ?? FALSE)) {
        NestedArray::setValue($values, $element['#parents'], $element['#default_value']);
      }
      if (is_array($element)) {
        $values = NestedArray::mergeDeep($values, $this->defaultValues($element));
      }
    }
    return $values;
  }

  /**
   * A seeded bulk_read rule keeps complete_ratio and entity_type on Save.
   */
  public function testBulkReadKeysSurviveUntouchedSettingsSave(): void {
    $rule = [
      'id' => 'near_complete_nodes',
      'label' => 'Near-complete node read',
      'signal' => 'bulk_read',
      'operation_pattern' => 'entity_read*',
      'window_seconds' => 300,
      'threshold' => 10,
      'complete_ratio' => 0.75,
      'entity_type' => 'node',
      'debounce_seconds' => 3600,
      'enabled' => TRUE,
    ];
    $this->config('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [$rule])
      ->save();

    $built = \Drupal::formBuilder()->getForm(McpSettingsForm::class);
    $values = $this->defaultValues($built);
    $submitted = $values['anomaly_rules_rows'][0] ?? [];
    $this->assertSame('bulk_read', $submitted['signal'] ?? NULL);
    $this->assertArrayNotHasKey('complete_ratio', $submitted);
    $this->assertArrayNotHasKey('entity_type', $submitted);

    $form_state = (new FormState())->setValues($values);
    \Drupal::formBuilder()->submitForm(McpSettingsForm::class, $form_state);
    $this->assertSame([], $form_state->getErrors());

    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $stored = $this->config('mcp_sentinel.settings')->get('anomaly_rules');
    $this->assertIsArray($stored);
    $this->assertCount(1, $stored);
    $this->assertSame(0.75, $stored[0]['complete_ratio'] ?? NULL);
    $this->assertSame('node', $stored[0]['entity_type'] ?? NULL);
    $this->assertSame('bulk_read', $stored[0]['signal'] ?? NULL);
    $this->assertSame('near_complete_nodes', $stored[0]['id'] ?? NULL);
  }

}
