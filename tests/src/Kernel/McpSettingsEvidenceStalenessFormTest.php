<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Component\Utility\NestedArray;
use Drupal\Core\Form\FormState;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Render\Element;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Form\McpSettingsForm;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * The settings form saves and validates the evidence staleness thresholds.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSettingsEvidenceStalenessFormTest extends KernelTestBase {

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
    // Settings form build counts consumers. The module is enabled, so the
    // count queries the storage; KernelTestBase does not install it.
    $this->installEntitySchema('consumer');
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
   * Submits the settings form with its defaults plus the given overrides.
   *
   * @param array<string, mixed> $overrides
   *   Top-level form values to change.
   *
   * @return \Drupal\Core\Form\FormStateInterface
   *   The submitted form state.
   */
  private function submitWith(array $overrides): FormStateInterface {
    $built = \Drupal::formBuilder()->getForm(McpSettingsForm::class);
    $values = array_replace($this->defaultValues($built), $overrides);
    $form_state = (new FormState())->setValues($values);
    \Drupal::formBuilder()->submitForm(McpSettingsForm::class, $form_state);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    return $form_state;
  }

  /**
   * The form shows the shipped defaults and saves new values as integers.
   */
  public function testSavesThresholds(): void {
    $built = \Drupal::formBuilder()->getForm(McpSettingsForm::class);
    $values = $this->defaultValues($built);
    $this->assertSame(86400, (int) ($values['evidence_stale_after'] ?? -1));
    $this->assertSame(0, (int) ($values['evidence_stale_rows'] ?? -1));

    $state = $this->submitWith(['evidence_stale_after' => '3600', 'evidence_stale_rows' => '25']);
    $this->assertSame([], $state->getErrors());
    $config = $this->config('mcp_sentinel.settings');
    $this->assertSame(3600, $config->get('evidence_stale_after'));
    $this->assertSame(25, $config->get('evidence_stale_rows'));
  }

  /**
   * An age below the floor or a negative row count is refused.
   */
  public function testRejectsInvalidThresholds(): void {
    $state = $this->submitWith(['evidence_stale_after' => '120', 'evidence_stale_rows' => '-1']);
    $errors = $state->getErrors();
    $this->assertArrayHasKey('evidence_stale_after', $errors);
    $this->assertArrayHasKey('evidence_stale_rows', $errors);
    $config = $this->config('mcp_sentinel.settings');
    $this->assertSame(86400, $config->get('evidence_stale_after'));
    $this->assertSame(0, $config->get('evidence_stale_rows'));
  }

}
