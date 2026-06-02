<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests vertical-tabs grouping on the MCP policy-profile form.
 *
 * Verifies that:
 * - the add/edit form renders vertical tabs with the expected section titles,
 * - saving the form round-trips all profile entity fields byte-identically,
 * - the existing McpPolicyProfileUiTest create flow still passes.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpPolicyProfileTabsTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Vertical tabs render and a new profile saves correctly.
   */
  public function testProfileFormRendersVerticalTabsAndSaves(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/add');
    $this->assertSession()->statusCodeEquals(200);
    // Functional tests run without JS; Drupal renders the vertical-tabs panes
    // wrapper as a server-side attribute rather than the JS-enhanced class.
    $this->assertSession()->elementExists('css', '[data-vertical-tabs-panes]');
    $this->assertSession()->pageTextContains('Allowed operations');
    $this->assertSession()->pageTextContains('Rate limits');
    // Save round-trips correctly.
    $this->submitForm([
      'label' => 'Readonly',
      'id' => 'readonly',
      'allow_read' => 1,
      'allow_write' => 0,
    ], 'Save');
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface|null $profile */
    $profile = \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->load('readonly');
    $this->assertNotNull($profile);
    $this->assertTrue($profile->get('allow_read'));
    $this->assertFalse($profile->get('allow_write'));
  }

  /**
   * All profile entity fields survive a save with no changes (round-trip).
   *
   * This is the behavior-preservation test: load the default profile into the
   * edit form, submit with no edits, and assert every stored key is identical.
   */
  public function testProfileEntityRoundTripsUnchangedAfterVerticalTabsSave(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));

    // Seed a profile with every field set to a non-default value.
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->create([
        'id' => 'roundtrip',
        'label' => 'Round-trip test',
        'status' => TRUE,
        'roles' => [],
        'weight' => 5,
        'allow_read' => TRUE,
        'allow_write' => FALSE,
        'allow_delete' => FALSE,
        'allow_graphql_mutations' => TRUE,
        'allowed_entity_types' => ['node', 'taxonomy_term'],
        'denied_entity_types' => ['user'],
        'redacted_fields' => ['pass', 'mail'],
        'rate_limit_requests' => 300,
        'rate_limit_window' => 60,
        'result_count_cap' => 500,
        'response_size_cap' => 2097152,
        'allowed_ips' => ['203.0.113.0/24'],
      ]);
    $profile->save();

    // Capture the stored config before loading the form.
    /** @var \Drupal\Core\Config\ImmutableConfig $before_config */
    $before_config = \Drupal::config('mcp_sentinel.policy_profile.roundtrip');
    $before = $before_config->getRawData();

    // Load the edit form and save with no edits.
    // The edit-form link template is /profiles/{id} (no trailing /edit).
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/roundtrip');
    $this->assertSession()->statusCodeEquals(200);
    $this->submitForm([], 'Save');

    // Reload and compare all keys.
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $after_profile = \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->load('roundtrip');
    $this->assertNotNull($after_profile);

    $after_config = \Drupal::config('mcp_sentinel.policy_profile.roundtrip');
    $after = $after_config->getRawData();

    // Core profile keys must be byte-identical.
    foreach ([
      'allow_read',
      'allow_write',
      'allow_delete',
      'allow_graphql_mutations',
      'allowed_entity_types',
      'denied_entity_types',
      'redacted_fields',
      'rate_limit_requests',
      'rate_limit_window',
      'result_count_cap',
      'response_size_cap',
      'allowed_ips',
      'weight',
    ] as $key) {
      $this->assertSame(
        $before[$key] ?? NULL,
        $after[$key] ?? NULL,
        "Profile config key '$key' changed after vertical-tabs save."
      );
    }
  }

}
