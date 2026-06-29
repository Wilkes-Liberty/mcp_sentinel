<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;

/**
 * Tests the admin UI for MCP policy profiles.
 *
 * @group mcp_sentinel
 */
final class McpPolicyProfileUiTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Admin user can load the collection page and create a new profile.
   */
  public function testAdminCanCreateProfile(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);

    // The collection page loads successfully and lists the shipped default.
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Default');
    // Create a new profile via the add form.
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/add');
    $this->submitForm([
      'label' => 'Reader bot',
      'id' => 'reader_bot',
      'allow_read' => 1,
      'allow_write' => 0,
    ], 'Save');
    $this->assertSession()->pageTextContains('Reader bot');

    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface|null $profile */
    $profile = $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile')->load('reader_bot');
    $this->assertNotNull($profile);
    $this->assertTrue($profile->allowsRead());
    $this->assertFalse($profile->allowsWrite());
  }

  /**
   * The per-entity-type delete-override textarea round-trips through the form.
   */
  public function testPerTypeDeleteOverrideRoundTrips(): void {
    $admin = $this->drupalCreateUser(['administer mcp sentinel']);
    $this->drupalLogin($admin);

    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/add');
    $this->submitForm([
      'label' => 'Term janitor',
      'id' => 'term_janitor',
      'allow_read' => 1,
      'allow_write' => 1,
      'allow_delete' => 0,
      'entity_rules_delete' => "taxonomy_term",
    ], 'Save');
    $this->assertSession()->pageTextContains('Term janitor');

    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface|null $profile */
    $profile = $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile')->load('term_janitor');
    $this->assertNotNull($profile);
    $this->assertSame(
      ['taxonomy_term' => ['allow_delete' => TRUE]],
      $profile->getEntityRules()
    );
    // The global delete gate stays off; only the listed type is opened.
    $this->assertFalse($profile->allowsDelete());
    $this->assertTrue($profile->allowsDeleteForEntityType('taxonomy_term'));
    $this->assertFalse($profile->allowsDeleteForEntityType('node'));

    // The textarea is pre-filled with the granted type on edit.
    $this->drupalGet('/admin/config/services/mcp-sentinel/profiles/term_janitor');
    $this->assertSession()->fieldValueEquals('entity_rules_delete', 'taxonomy_term');
  }

}
