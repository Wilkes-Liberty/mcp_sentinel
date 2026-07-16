<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\taxonomy\Entity\Term;
use Drupal\taxonomy\Entity\Vocabulary;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAccessChecker
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpAccessCheckerTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key',
    'image', 'options', 'path_alias', 'consumers', 'simple_oauth',
    'encrypt', 'taxonomy',
    'mcp_sentinel',
  ];

  /**
   * A node used across the access assertions.
   */
  private Node $node;

  /**
   * A taxonomy term used by the per-entity-type override assertions.
   */
  private Term $term;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('taxonomy_term');
    $this->installConfig(['mcp_sentinel']);
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $this->node = Node::create(['type' => 'article', 'title' => 'Test']);
    Vocabulary::create(['vid' => 'tags', 'name' => 'Tags'])->save();
    $this->term = Term::create(['vid' => 'tags', 'name' => 'Term']);
  }

  /**
   * Returns the access checker service.
   */
  private function checker(): McpAccessChecker {
    return $this->container->get('mcp_sentinel.access_checker');
  }

  /**
   * Creates an unsaved policy profile with the given values.
   *
   * @param array $values
   *   Profile field values to set beyond the required id/label.
   *
   * @return \Drupal\mcp_sentinel\Entity\McpPolicyProfile
   *   The unsaved profile entity.
   */
  private function profile(array $values): McpPolicyProfile {
    return McpPolicyProfile::create(['id' => 'p', 'label' => 'P'] + $values);
  }

  /**
   * Sets the master enabled flag in config.
   */
  private function setMaster(bool $enabled): void {
    $this->config('mcp_sentinel.settings')->set('enabled', $enabled)->save();
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testDisabledForbidsEverything(): void {
    $this->setMaster(FALSE);
    $p = $this->profile(['allow_write' => TRUE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $p)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testDeniedEntityType(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['denied_entity_types' => ['node'], 'allow_write' => TRUE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $p)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testAllowlistExcludesOthers(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'allowed_entity_types' => ['taxonomy_term'],
      'allow_write' => TRUE,
    ]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $p)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testReadGate(): void {
    $this->setMaster(TRUE);
    $deny = $this->profile(['allow_read' => FALSE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'view', $deny)->isForbidden()
    );
    $allow = $this->profile(['allow_read' => TRUE]);
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->node, 'view', $allow)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testWriteAndDeleteGates(): void {
    $this->setMaster(TRUE);
    $off = $this->profile(['allow_write' => FALSE, 'allow_delete' => FALSE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'create', $off)->isForbidden()
    );
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $off)->isForbidden()
    );
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'delete', $off)->isForbidden()
    );
    $on = $this->profile(['allow_write' => TRUE, 'allow_delete' => TRUE]);
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->node, 'update', $on)->isForbidden()
    );
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->node, 'delete', $on)->isForbidden()
    );
  }

  /**
   * A per-entity-type delete override opens that type only.
   *
   * With the global delete gate off and an entity_rules override granting
   * delete for taxonomy_term, a term delete is permitted while a node delete
   * stays forbidden — the global no-delete guarantee holds for other types.
   *
   * @covers ::checkEntityAccess
   */
  public function testPerTypeDeleteOverrideAllowsTaxonomyButNotNode(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'allow_write' => TRUE,
      'allow_delete' => FALSE,
      'entity_rules' => ['taxonomy_term' => ['allow_delete' => TRUE]],
    ]);
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->term, 'delete', $p)->isForbidden(),
      'A per-type override must permit deleting the named entity type.'
    );
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'delete', $p)->isForbidden(),
      'Types without an override must stay delete-denied under the global flag.'
    );
  }

  /**
   * Without entity_rules, deletes follow the global allow_delete flag.
   *
   * @covers ::checkEntityAccess
   */
  public function testNoEntityRulesFollowsGlobalDelete(): void {
    $this->setMaster(TRUE);
    $off = $this->profile(['allow_delete' => FALSE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->term, 'delete', $off)->isForbidden(),
      'With no override and global delete off, a term delete is forbidden.'
    );
    $on = $this->profile(['allow_delete' => TRUE]);
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->term, 'delete', $on)->isForbidden(),
      'With no override and global delete on, a term delete is permitted.'
    );
  }

  /**
   * The per-type resolver overrides a present type and falls back otherwise.
   *
   * @covers \Drupal\mcp_sentinel\Entity\McpPolicyProfile::allowsDeleteForEntityType
   * @covers \Drupal\mcp_sentinel\Entity\McpPolicyProfile::allowsWriteForEntityType
   */
  public function testEntityRuleResolverFallback(): void {
    $p = $this->profile([
      'allow_write' => TRUE,
      'allow_delete' => FALSE,
      'entity_rules' => [
        'taxonomy_term' => ['allow_delete' => TRUE],
        'node' => ['allow_write' => FALSE],
      ],
    ]);
    // Delete: present override wins; absent type falls back to the global flag.
    $this->assertTrue($p->allowsDeleteForEntityType('taxonomy_term'));
    $this->assertFalse($p->allowsDeleteForEntityType('media'));
    // Write: present override wins; absent type falls back to the global flag.
    $this->assertFalse($p->allowsWriteForEntityType('node'));
    $this->assertTrue($p->allowsWriteForEntityType('media'));
  }

  /**
   * Create is forbidden when the write gate is off (create is a write).
   *
   * @covers ::checkCreateAccess
   */
  public function testCreateBlockedWhenWriteGateOff(): void {
    $this->setMaster(TRUE);
    $off = $this->profile(['allow_write' => FALSE]);
    $this->assertTrue(
      $this->checker()->checkCreateAccess('node', $off)->isForbidden(),
      'Create must be forbidden when allow_write is FALSE.'
    );
  }

  /**
   * Create is permitted when the write gate is on and the type is allowed.
   *
   * @covers ::checkCreateAccess
   */
  public function testCreateAllowedWhenWriteGateOn(): void {
    $this->setMaster(TRUE);
    $on = $this->profile(['allow_write' => TRUE]);
    $this->assertFalse(
      $this->checker()->checkCreateAccess('node', $on)->isForbidden(),
      'Create must be permitted when allow_write is TRUE and the type is allowed.'
    );
  }

  /**
   * Create is forbidden for a denied entity type even when write is allowed.
   *
   * @covers ::checkCreateAccess
   */
  public function testCreateBlockedForDeniedType(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['denied_entity_types' => ['user'], 'allow_write' => TRUE]);
    $this->assertTrue(
      $this->checker()->checkCreateAccess('user', $p)->isForbidden(),
      'Create of a denied entity type must be forbidden.'
    );
  }

  /**
   * Create is forbidden for a type outside a non-empty allowlist.
   *
   * @covers ::checkCreateAccess
   */
  public function testCreateBlockedWhenTypeNotInAllowlist(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'allowed_entity_types' => ['taxonomy_term'],
      'allow_write' => TRUE,
    ]);
    $this->assertTrue(
      $this->checker()->checkCreateAccess('node', $p)->isForbidden(),
      'Create of a type not in the allowlist must be forbidden.'
    );
  }

  /**
   * Create is forbidden when the master switch is disabled.
   *
   * @covers ::checkCreateAccess
   */
  public function testCreateBlockedWhenMasterDisabled(): void {
    $this->setMaster(FALSE);
    $p = $this->profile(['allow_write' => TRUE]);
    $this->assertTrue(
      $this->checker()->checkCreateAccess('node', $p)->isForbidden(),
      'Create must be forbidden when the master switch is off.'
    );
  }

  /**
   * A JSON:API filter-access deny carries the governance cache contexts.
   *
   * Without 'user.roles' + 'oauth2_scopes', JSON:API's filter-access cache can
   * serve a governed deny-result to a non-governed account sharing the bin.
   *
   * @covers ::getJsonApiFilterAccess
   */
  public function testJsonApiFilterAccessDenyHasCacheContexts(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['denied_entity_types' => ['node']]);
    $access = $this->checker()->getJsonApiFilterAccess('node', $p);
    $result = $access[JSONAPI_FILTER_AMONG_ALL] ?? NULL;
    $this->assertNotNull($result, 'A denied type must return a filter-access result.');
    $this->assertTrue($result->isForbidden());
    $contexts = $result->getCacheContexts();
    $this->assertContains('user.roles', $contexts,
      'JSON:API filter-access deny must vary by user.roles.');
    $this->assertContains('oauth2_scopes', $contexts,
      'JSON:API filter-access deny must vary by oauth2_scopes.');
    // No IP restriction → result remains cacheable (max-age not forced to 0).
    $this->assertSame(-1, $result->getCacheMaxAge(),
      'Without an IP restriction the filter-access result stays cacheable.');
  }

  /**
   * The not-in-allowlist filter-access deny also carries the cache contexts.
   *
   * @covers ::getJsonApiFilterAccess
   */
  public function testJsonApiFilterAccessAllowlistDenyHasCacheContexts(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['allowed_entity_types' => ['taxonomy_term']]);
    $access = $this->checker()->getJsonApiFilterAccess('node', $p);
    $result = $access[JSONAPI_FILTER_AMONG_ALL] ?? NULL;
    $this->assertNotNull($result);
    $this->assertTrue($result->isForbidden());
    $this->assertContains('user.roles', $result->getCacheContexts());
    $this->assertContains('oauth2_scopes', $result->getCacheContexts());
  }

  /**
   * With allowed_ips set, the filter-access deny is uncacheable (max-age 0).
   *
   * @covers ::getJsonApiFilterAccess
   */
  public function testJsonApiFilterAccessDenyUncacheableWhenIpRestricted(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'denied_entity_types' => ['node'],
      'allowed_ips' => ['203.0.113.0/24'],
    ]);
    $result = $this->checker()->getJsonApiFilterAccess('node', $p)[JSONAPI_FILTER_AMONG_ALL];
    $this->assertContains('user.roles', $result->getCacheContexts());
    $this->assertContains('oauth2_scopes', $result->getCacheContexts());
    $this->assertSame(0, $result->getCacheMaxAge(),
      'An IP-restricted profile must make the filter-access deny uncacheable.');
  }

}
