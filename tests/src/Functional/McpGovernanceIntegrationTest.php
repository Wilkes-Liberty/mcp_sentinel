<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\Tests\BrowserTestBase;

/**
 * Proves governance triggers on the role fallback path, not on a header.
 *
 * An agent holding the mcp_api role is write-gated by the resolved policy
 * profile when governed_role_fallback is enabled — with no MCP header present.
 * A regular user without a governed role resolves to NULL and is ungated.
 *
 * @group mcp_sentinel
 */
final class McpGovernanceIntegrationTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel', 'node'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * A governed account is write-gated by role with the fallback enabled.
   *
   * Asserts:
   *  - With governed_role_fallback = TRUE, a user holding the governed role is
   *    governed and write-gated by the resolved policy profile.
   *  - A regular user without a governed role resolves to NULL.
   */
  public function testWriteGateAppliesByRoleWithoutHeader(): void {
    // Enable the role-based fallback so this test exercises the role path.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->save();

    $this->drupalCreateContentType(['type' => 'article']);

    // Tighten the shipped default profile: deny writes.
    $profile = McpPolicyProfile::load('default');
    $profile->set('allow_write', FALSE)->save();

    // Create a governed agent account (mcp_api role) — no MCP header anywhere.
    $agent = $this->drupalCreateUser([
      'access content',
      'create article content',
      'edit any article content',
    ]);
    $agent->addRole('mcp_api');
    $agent->save();

    $node = $this->drupalCreateNode(['type' => 'article']);

    /** @var \Drupal\mcp_sentinel\Service\McpPolicyResolver $resolver */
    $resolver = $this->container->get('mcp_sentinel.policy_resolver');
    $resolvedProfile = $resolver->resolve($agent);

    $access = $this->container->get('mcp_sentinel.access_checker')
      ->checkEntityAccess($node, 'update', $resolvedProfile);
    $this->assertTrue($access->isForbidden(), 'Governed agent is write-gated by role alone.');

    // A non-governed user resolves to NULL and is untouched by Sentinel.
    $human = $this->drupalCreateUser();
    $this->assertNull($resolver->resolve($human), 'Ungoverned user resolves to NULL.');
  }

}
