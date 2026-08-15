<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Covers the classification vocabulary, map and per-profile egress ceilings.
 *
 * Slice A of d.o #3616540 part 2 ships dark: the shipped settings label the
 * identity/credential types `restricted`, and no profile carries a ceiling,
 * so installing the module changes no read decision.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpClassificationConfigTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'tool', 'key', 'serialization',
    'consumers', 'simple_oauth', 'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * The shipped settings carry the ordered vocabulary and the default map.
   */
  public function testShippedClassificationSettings(): void {
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertSame(['public', 'internal', 'restricted'], $settings->get('classification_labels'));
    $this->assertSame('internal', $settings->get('context_schema_label'));

    $map = $settings->get('classification_map');
    $this->assertIsArray($map);
    $labelled = [];
    foreach ($map as $row) {
      $this->assertSame(['entity_type', 'bundle', 'field', 'label'], array_keys($row));
      $this->assertSame('', $row['bundle'], 'Shipped rows label whole entity types.');
      $this->assertSame('', $row['field'], 'Shipped rows label whole entity types.');
      $labelled[$row['entity_type']] = $row['label'];
    }
    // P0.4's default-deny classes, expressed as labels: the identity and
    // credential types the default profile already denies.
    $this->assertSame([
      'user' => 'restricted',
      'oauth2_token' => 'restricted',
      'key' => 'restricted',
      'consumer' => 'restricted',
      'encryption_profile' => 'restricted',
    ], $labelled);
  }

  /**
   * A bare profile and the shipped default profile carry no ceilings.
   */
  public function testProfilesShipWithoutCeilings(): void {
    $bare = McpPolicyProfile::create(['id' => 'bare', 'label' => 'Bare']);
    $this->assertSame([], $bare->getEgressCeilings());
    $this->assertNull($bare->getEgressCeiling(McpGovernedSurface::JsonApi));

    $default = McpPolicyProfile::load('default');
    $this->assertNotNull($default);
    $this->assertSame([], $default->getEgressCeilings());
    foreach (McpGovernedSurface::cases() as $surface) {
      $this->assertNull($default->getEgressCeiling($surface), $surface->value . ' has no shipped ceiling.');
    }
  }

  /**
   * Ceilings round-trip through config save/load, keyed by surface.
   */
  public function testCeilingsRoundTrip(): void {
    McpPolicyProfile::create([
      'id' => 'capped',
      'label' => 'Capped',
      'egress_ceilings' => ['jsonapi' => 'internal', 'tool' => 'restricted'],
    ])->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $profile = McpPolicyProfile::load('capped');
    $this->assertNotNull($profile);
    // Key order follows the config schema after a save; a map is a map.
    $this->assertEqualsCanonicalizing(['jsonapi' => 'internal', 'tool' => 'restricted'], $profile->getEgressCeilings());
    $this->assertSame('internal', $profile->getEgressCeiling(McpGovernedSurface::JsonApi));
    $this->assertSame('restricted', $profile->getEgressCeiling(McpGovernedSurface::Tool));
    $this->assertNull($profile->getEgressCeiling(McpGovernedSurface::Graphql), 'An absent surface key is no ceiling.');
    $this->assertNull($profile->getEgressCeiling(McpGovernedSurface::Drush));

    // Exported configuration carries the key, so a round-trip does not drift.
    $exported = $this->config('mcp_sentinel.mcp_policy_profile.capped')->get('egress_ceilings');
    $this->assertEqualsCanonicalizing(['jsonapi' => 'internal', 'tool' => 'restricted'], $exported);
  }

}
