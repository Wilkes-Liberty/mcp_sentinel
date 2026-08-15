<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Component\Utility\NestedArray;
use Drupal\Core\Form\FormState;
use Drupal\Core\Render\Element;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Form\McpSettingsForm;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * The classification settings section and the profile egress-ceilings tab.
 *
 * Operators edit the vocabulary, the classification map (a row editor like
 * the DLP patterns) and the schema label on the settings form, and per-surface
 * ceilings on each policy profile (d.o #3616540 part 2).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpClassificationFormsTest extends KernelTestBase {

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
    $this->installSchema('audit_chain', ['audit_chain_log']);
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
   * The settings form carries a classification section built from config.
   */
  public function testSettingsFormBuildsClassificationSection(): void {
    $form = \Drupal::formBuilder()->getForm(McpSettingsForm::class);
    $section = $form['classification'] ?? NULL;
    $this->assertIsArray($section, 'The settings form has a classification section.');
    $this->assertSame("public\ninternal\nrestricted", $section['classification_labels']['#default_value']);
    $this->assertSame('internal', $section['context_schema_label']['#default_value']);
    $rows = $section['classification_map_rows'];
    // Five shipped rows plus one blank row to fill.
    $this->assertCount(6, array_filter(Element::children($rows), 'is_int'));
    $this->assertSame('user', $rows[0]['entity_type']['#default_value']);
    $this->assertSame('', $rows[0]['bundle']['#default_value']);
    $this->assertSame('', $rows[0]['field']['#default_value']);
    $this->assertSame('restricted', $rows[0]['label']['#default_value']);
    $this->assertSame('', $rows[5]['entity_type']['#default_value']);
    $this->assertArrayHasKey('add', $rows);
    $this->assertArrayHasKey('remove', $rows[0]);
  }

  /**
   * Submitting the settings form saves vocabulary, map and schema label.
   */
  public function testSettingsFormSavesClassification(): void {
    $built = \Drupal::formBuilder()->getForm(McpSettingsForm::class);
    $values = $this->defaultValues($built);
    $values['classification_labels'] = " open \nstaff\n\nsecret\nstaff";
    $values['context_schema_label'] = 'staff';
    // A browser submits every rendered row; blank the ones not in use.
    $blank = ['entity_type' => '', 'bundle' => '', 'field' => '', 'label' => ''];
    $values['classification_map_rows'] = [
      0 => ['entity_type' => 'node', 'bundle' => 'memo', 'field' => '', 'label' => 'secret'],
      1 => ['entity_type' => ' node ', 'bundle' => '', 'field' => 'field_ssn', 'label' => 'secret'],
      2 => $blank,
      3 => ['entity_type' => 'media', 'bundle' => '', 'field' => '', 'label' => 'open'],
      4 => $blank,
      5 => $blank,
    ];
    $form_state = (new FormState())->setValues($values);
    \Drupal::formBuilder()->submitForm(McpSettingsForm::class, $form_state);
    $this->assertSame([], $form_state->getErrors());

    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertSame(['open', 'staff', 'secret'], $settings->get('classification_labels'));
    $this->assertSame('staff', $settings->get('context_schema_label'));
    $this->assertSame([
      ['entity_type' => 'node', 'bundle' => 'memo', 'field' => '', 'label' => 'secret'],
      ['entity_type' => 'node', 'bundle' => '', 'field' => 'field_ssn', 'label' => 'secret'],
      ['entity_type' => 'media', 'bundle' => '', 'field' => '', 'label' => 'open'],
    ], $settings->get('classification_map'));
  }

  /**
   * Labels outside the submitted vocabulary are rejected on both fields.
   */
  public function testSettingsFormRejectsUnknownLabels(): void {
    $built = \Drupal::formBuilder()->getForm(McpSettingsForm::class);
    $values = $this->defaultValues($built);
    $values['classification_labels'] = "public\ninternal";
    $values['context_schema_label'] = 'restricted';
    $blank = ['entity_type' => '', 'bundle' => '', 'field' => '', 'label' => ''];
    $values['classification_map_rows'] = [
      0 => ['entity_type' => 'node', 'bundle' => '', 'field' => '', 'label' => 'bogus'],
      1 => ['entity_type' => '', 'bundle' => 'memo', 'field' => '', 'label' => 'internal'],
      2 => $blank,
      3 => $blank,
      4 => $blank,
      5 => $blank,
    ];
    $form_state = (new FormState())->setValues($values);
    \Drupal::formBuilder()->submitForm(McpSettingsForm::class, $form_state);
    $errors = $form_state->getErrors();
    $this->assertArrayHasKey('classification][classification_map_rows][0][label', $errors);
    $this->assertArrayHasKey('classification][classification_map_rows][1][entity_type', $errors, 'A row without an entity type is incomplete.');
    $this->assertArrayHasKey('classification][context_schema_label', $errors);
    // Nothing was written.
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertSame(['public', 'internal', 'restricted'], $this->config('mcp_sentinel.settings')->get('classification_labels'));
  }

  /**
   * The profile form offers one ceiling select per surface and saves them.
   */
  public function testProfileFormSavesCeilings(): void {
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $form_object = \Drupal::entityTypeManager()->getFormObject('mcp_policy_profile', 'edit')->setEntity($profile);
    $built = \Drupal::formBuilder()->getForm($form_object);
    $tab = $built['egress'] ?? NULL;
    $this->assertIsArray($tab, 'The profile form has an egress ceilings tab.');
    foreach (['tool', 'context', 'jsonapi', 'graphql', 'drush'] as $surface) {
      $this->assertArrayHasKey($surface, $tab['egress_ceilings']);
      $this->assertSame(['' => '- No ceiling -', 'public' => 'public', 'internal' => 'internal', 'restricted' => 'restricted'], array_map('strval', $tab['egress_ceilings'][$surface]['#options']));
      $this->assertSame('', $tab['egress_ceilings'][$surface]['#default_value']);
    }

    $values = $this->defaultValues($built);
    $values['egress_ceilings'] = ['tool' => 'restricted', 'context' => '', 'jsonapi' => 'internal', 'graphql' => '', 'drush' => ''];
    $form_state = (new FormState())->setValues($values);
    // An entity form saves from its Save button's handlers, not the
    // form-level ones; a programmatic submission has to name that button.
    $form_state->setTriggeringElement($built['actions']['submit']);
    $form_object = \Drupal::entityTypeManager()->getFormObject('mcp_policy_profile', 'edit')->setEntity($profile);
    \Drupal::formBuilder()->submitForm($form_object, $form_state);
    $this->assertSame([], $form_state->getErrors());

    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $saved = McpPolicyProfile::load('default');
    $this->assertEqualsCanonicalizing(['tool' => 'restricted', 'jsonapi' => 'internal'], $saved->getEgressCeilings(), 'Empty selects are absent keys, not empty ceilings.');
  }

}
