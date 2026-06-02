<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the live policy-preview summary on the profile form.
 *
 * Verifies that the policy-preview element renders on initial page load,
 * correctly reflects default gate values, and shows the right summary after
 * a full-page save (AJAX refresh is covered by the server-side build).
 * The preview is read-only and stores nothing on the profile entity.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpPolicyPreviewTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * The preview renders on initial load and reflects the entity defaults.
   *
   * McpPolicyProfile defaults: allow_read = TRUE, allow_write = FALSE.
   */
  public function testPreviewSummarizesGatesOnLoad(): void {
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/add');
    $this->assertSession()->statusCodeEquals(200);
    // The preview wrapper exists.
    $this->assertSession()->elementExists('css', '.mcp-policy-preview');
    // Default new profile: allow_read = TRUE (allowed); allow_write = FALSE
    // (denied). The preview must reflect the entity's own defaults.
    $preview = $this->assertSession()->elementExists('css', '.mcp-policy-preview');
    $this->assertStringContainsString('Read: allowed', $preview->getText());
    $this->assertStringContainsString('Write: denied', $preview->getText());
  }

  /**
   * Preview reflects gate values saved on a profile.
   */
  public function testPreviewReflectsStoredProfileValues(): void {
    // Create a profile with read allowed but write denied.
    \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->create([
        'id' => 'preview_test',
        'label' => 'Preview test',
        'allow_read' => TRUE,
        'allow_write' => FALSE,
        'allow_delete' => FALSE,
        'allow_graphql_mutations' => FALSE,
        'allowed_entity_types' => ['node', 'media'],
        'denied_entity_types' => ['user'],
        'redacted_fields' => ['pass'],
        'rate_limit_requests' => 100,
        'rate_limit_window' => 30,
        'result_count_cap' => 0,
        'response_size_cap' => 0,
        'allowed_ips' => ['10.0.0.0/8', '192.168.1.1'],
      ])
      ->save();

    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/preview_test');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->elementExists('css', '.mcp-policy-preview');
    $preview = $this->assertSession()->elementExists('css', '.mcp-policy-preview');
    $text = $preview->getText();
    // Read allowed, write denied.
    $this->assertStringContainsString('Read: allowed', $text);
    $this->assertStringContainsString('Write: denied', $text);
    // Allowed entity types listed.
    $this->assertStringContainsString('node', $text);
    $this->assertStringContainsString('media', $text);
    // Denied entity types listed.
    $this->assertStringContainsString('user', $text);
    // Redacted fields listed.
    $this->assertStringContainsString('pass', $text);
    // Rate limit shown.
    $this->assertStringContainsString('100', $text);
    // IP allowlist shown (2 CIDRs).
    $this->assertStringContainsString('2', $text);
  }

  /**
   * The preview wrapper is present and is read-only (stores nothing).
   */
  public function testPreviewIsReadOnlyAndStoresNothing(): void {
    \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->create([
        'id' => 'readonly_preview',
        'label' => 'Readonly preview',
        'allow_read' => TRUE,
        'allow_write' => FALSE,
        'allow_delete' => FALSE,
        'allow_graphql_mutations' => FALSE,
      ])
      ->save();

    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/readonly_preview');
    // The AJAX wrapper exists.
    $this->assertSession()->elementExists('css', '#mcp-policy-preview-wrapper');
    // Save with no edits; stored config must not have gained a 'preview' key.
    $this->submitForm([], 'Save');
    $config = \Drupal::config('mcp_sentinel.policy_profile.readonly_preview');
    $raw = $config->getRawData();
    $this->assertArrayNotHasKey('preview', $raw,
      'The policy preview must not be stored on the config entity.');
  }

  /**
   * Preview summary updates after a form submit with changed gate values.
   */
  public function testPreviewUpdatesAfterSaveWithChangedGates(): void {
    \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->create([
        'id' => 'gatechange',
        'label' => 'Gate change',
        'allow_read' => FALSE,
        'allow_write' => FALSE,
        'allow_delete' => FALSE,
        'allow_graphql_mutations' => FALSE,
      ])
      ->save();

    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/gatechange');
    // Initial: all denied.
    $preview = $this->assertSession()->elementExists('css', '.mcp-policy-preview');
    $this->assertStringContainsString('Read: denied', $preview->getText());

    // Submit with allow_read = 1; the redirect goes to the collection page.
    // Reload the edit form to verify the saved profile, then check the preview.
    $this->submitForm(['allow_read' => 1], 'Save');
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/gatechange');
    $preview = $this->assertSession()->elementExists('css', '.mcp-policy-preview');
    $this->assertStringContainsString('Read: allowed', $preview->getText());
  }

}
