<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\mcp_sentinel\Traits\McpClassificationTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Entity-level classification egress enforcement (d.o #3616540 part 2).
 *
 * A "destination" is (server-resolved profile, governed surface). An entity
 * whose label exceeds the profile's ceiling for the current surface is
 * forbidden with the stable code classification_egress_denied and a bounded
 * evidence row; the same read under a sufficient ceiling is unchanged. Hard
 * P0.4 denies keep winning, and every case is proven in both directions.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpClassificationEgressAccessTest extends KernelTestBase {

  use UserCreationTrait;
  use McpClassificationTestTrait;

  /**
   * A value that must never appear in evidence.
   */
  private const SENTINEL_VALUE = 'SENTINEL-VALUE-7f3a9c';

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
   * The governed account.
   */
  private UserInterface $agent;

  /**
   * A node in the restricted bundle.
   */
  private Node $memo;

  /**
   * A node in an unlabelled bundle.
   */
  private Node $article;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('system', ['sequences']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel', 'user']);

    NodeType::create(['type' => 'memo', 'name' => 'Memo'])->save();
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access content');
    $role->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('classification_map', [
        ['entity_type' => 'node', 'bundle' => 'memo', 'field' => '', 'label' => 'restricted'],
      ])
      ->save();
    // The first account is uid 1, which bypasses every access check; burn it
    // on a bystander so the governed agent is an ordinary account. No
    // permissions argument on the agent: createUser() would replace the roles
    // value with its own role.
    $this->createUser();
    $this->agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);

    // Fixtures are saved BEFORE the governed account becomes current: the
    // default profile's deny_publish backstop would otherwise unpublish them.
    $this->memo = Node::create(['type' => 'memo', 'title' => self::SENTINEL_VALUE, 'status' => 1]);
    $this->memo->save();
    $this->article = Node::create(['type' => 'article', 'title' => 'Public article', 'status' => 1]);
    $this->article->save();
    \Drupal::currentUser()->setAccount($this->agent);
  }

  /**
   * The reason string of a forbidden result, or NULL.
   */
  private function reason(Node $node, string $operation = 'view'): ?string {
    $result = $node->access($operation, $this->agent, TRUE);
    if (!$result->isForbidden()) {
      return NULL;
    }
    return $result instanceof AccessResultReasonInterface ? (string) $result->getReason() : '(no reason)';
  }

  /**
   * An over-ceiling entity is forbidden; at ceiling it reads unchanged (§5.1).
   */
  public function testEntityAboveCeilingIsForbiddenAndAtCeilingUnchanged(): void {
    $this->onRequest('/jsonapi/node/memo');

    $this->setCeilings(['jsonapi' => 'internal']);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));
    $this->assertNull($this->reason($this->article), 'An unlabelled bundle is unaffected by the ceiling.');
    $this->assertTrue($this->article->access('view', $this->agent));

    $this->setCeilings(['jsonapi' => 'restricted']);
    $this->assertNull($this->reason($this->memo), 'A sufficient ceiling changes nothing.');
    $this->assertTrue($this->memo->access('view', $this->agent));

    $this->setCeilings([]);
    $this->assertNull($this->reason($this->memo), 'No ceiling: the mechanism is dark.');
  }

  /**
   * The same entity and profile: allowed on one surface, refused on another.
   */
  public function testCeilingIsPerSurface(): void {
    $this->setCeilings(['jsonapi' => 'restricted', 'graphql' => 'internal']);

    $this->onRequest('/jsonapi/node/memo');
    $this->assertNull($this->reason($this->memo));

    $this->onRequest('/graphql');
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));
  }

  /**
   * A Tool call site names its surface through the request attribute.
   */
  public function testToolSurfaceIsHonoured(): void {
    $this->setCeilings(['tool' => 'internal', 'jsonapi' => 'restricted']);
    $this->onRequest('/_mcp', [], [McpClassificationResolver::REQUEST_ATTRIBUTE_SURFACE => 'tool']);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));

    $this->onRequest('/_mcp', [], [McpClassificationResolver::REQUEST_ATTRIBUTE_SURFACE => 'jsonapi']);
    $this->assertNull($this->reason($this->memo));
  }

  /**
   * Outside every governed surface the strictest configured ceiling applies.
   */
  public function testUnknownSurfaceTakesStrictestCeiling(): void {
    $this->setCeilings(['jsonapi' => 'restricted', 'tool' => 'internal']);
    $this->onRequest('/node/1');
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));

    $this->setCeilings(['jsonapi' => 'restricted', 'tool' => 'restricted']);
    $this->onRequest('/node/1');
    $this->assertNull($this->reason($this->memo));
  }

  /**
   * A declared ceiling narrows the effective ceiling, never widens it (§5.5).
   */
  public function testDeclaredCeilingNarrowsOnly(): void {
    $this->setCeilings(['jsonapi' => 'restricted']);
    $this->onRequest('/jsonapi/node/memo', [McpClassificationResolver::HEADER_DECLARED_CEILING => 'internal']);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));

    $this->setCeilings(['jsonapi' => 'internal']);
    $this->onRequest('/jsonapi/node/memo', [McpClassificationResolver::HEADER_DECLARED_CEILING => 'restricted']);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo), 'Declaring above the profile ceiling changes nothing.');

    $this->setCeilings(['jsonapi' => 'restricted']);
    $this->onRequest('/jsonapi/node/memo', [McpClassificationResolver::HEADER_DECLARED_CEILING => 'restricted']);
    $this->assertNull($this->reason($this->memo));
  }

  /**
   * Hard P0.4 denies keep winning: a denied type stays denied (§5.8).
   */
  public function testHardDenyWinsOverPermittedLabel(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('denied_entity_types', ['node'])
      ->save();
    $this->setCeilings(['jsonapi' => 'restricted']);
    $this->onRequest('/jsonapi/node/memo');
    $reason = $this->reason($this->memo);
    $this->assertNotNull($reason);
    $this->assertStringContainsString("Entity type 'node' is denied", $reason);
    $this->assertStringNotContainsString(McpClassificationResolver::DENIAL_CODE, $reason);
    $this->assertSame([], $this->evidenceRows(), 'The hard deny short-circuits before any classification evidence.');
  }

  /**
   * Denial evidence names labels, surface, profile and type — never values.
   */
  public function testEvidenceIsBoundedAndCarriesNoValues(): void {
    $this->setCeilings(['jsonapi' => 'internal']);
    $this->onRequest('/jsonapi/node/memo', [
      McpClassificationResolver::HEADER_DECLARED_CEILING => 'internal',
      McpClassificationResolver::HEADER_DECLARED_DESTINATION => 'tenant-a:export',
    ]);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));
    // A second check of the same subject in the same request adds no row.
    \Drupal::entityTypeManager()->getAccessControlHandler('node')->resetCache();
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));

    $rows = $this->evidenceRows();
    $this->assertCount(1, $rows, 'One bounded row per subject per request.');
    // A new request starts a new de-duplication set.
    $this->onRequest('/jsonapi/node/memo');
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $this->reason($this->memo));
    $this->assertCount(2, $this->evidenceRows(), 'The next request records its own row.');
    $row = $rows[0];
    $this->assertSame('jsonapi', $row['surface']);
    $this->assertSame('default', $row['profile']);
    $this->assertSame('node', $row['entity_type']);
    $this->assertSame('memo', $row['bundle']);
    $this->assertSame('restricted', $row['classification']);
    $this->assertSame('internal', $row['ceiling']);
    $this->assertSame('internal', $row['declared_ceiling']);
    $this->assertSame('tenant-a:export', $row['declared_destination']);
    $this->assertSame(McpClassificationResolver::DENIAL_CODE, $row['reason']);
    $this->assertArrayHasKey('origin', $row);
    $this->assertArrayHasKey('site', $row['origin']);
    $this->assertArrayHasKey('environment', $row['origin']);
    $this->assertStringNotContainsString(self::SENTINEL_VALUE, (string) json_encode($row));
    $this->assertSame('', $row['entity_id'], 'Entity ids are not part of the bounded evidence.');
    $this->assertNull($row['entity_label'], 'Entity labels (values) are not part of the bounded evidence.');
  }

  /**
   * At-ceiling reads write no evidence at all.
   */
  public function testNoEvidenceWithoutDenial(): void {
    $this->setCeilings(['jsonapi' => 'restricted']);
    $this->onRequest('/jsonapi/node/memo');
    $this->assertNull($this->reason($this->memo));
    $this->assertSame([], $this->evidenceRows());
  }

  /**
   * JSON:API filter access is refused type-wide when any row is over ceiling.
   */
  public function testFilterAccessRefusedTypeWide(): void {
    $checker = $this->container->get('mcp_sentinel.access_checker');
    $profile = $this->container->get('mcp_sentinel.policy_resolver')->resolve($this->agent);
    $this->assertNotNull($profile);

    $this->setCeilings(['jsonapi' => 'internal']);
    $this->onRequest('/jsonapi/node/article');
    $profile = $this->container->get('mcp_sentinel.policy_resolver')->resolve($this->agent);
    $access = $checker->getJsonApiFilterAccess('node', $profile);
    $this->assertArrayHasKey(JSONAPI_FILTER_AMONG_ALL, $access, 'The memo bundle is over ceiling, so node filtering is refused even on the article route.');
    $this->assertTrue($access[JSONAPI_FILTER_AMONG_ALL]->isForbidden());
    $term = $checker->getJsonApiFilterAccess('taxonomy_term', $profile);
    $this->assertFalse($term[JSONAPI_FILTER_AMONG_ALL]->isForbidden(), 'Types without over-ceiling rows filter as before.');

    $this->setCeilings(['jsonapi' => 'restricted']);
    $profile = $this->container->get('mcp_sentinel.policy_resolver')->resolve($this->agent);
    $this->assertFalse($checker->getJsonApiFilterAccess('node', $profile)[JSONAPI_FILTER_AMONG_ALL]->isForbidden());
  }

  /**
   * Ceiling-dependent results vary by route and by the declared-ceiling header.
   */
  public function testCeilingDependentResultsCarryCacheContexts(): void {
    $this->setCeilings(['jsonapi' => 'internal']);
    $this->onRequest('/jsonapi/node/memo');
    $result = $this->memo->access('view', $this->agent, TRUE);
    $this->assertInstanceOf(AccessResult::class, $result);
    $contexts = $result->getCacheContexts();
    $this->assertContains('route', $contexts);
    $this->assertContains('headers:' . McpClassificationResolver::HEADER_DECLARED_CEILING, $contexts);

    // The permitted (neutral) decision depends on the same two dimensions.
    $this->setCeilings(['jsonapi' => 'restricted']);
    $neutral = $this->memo->access('view', $this->agent, TRUE);
    $this->assertInstanceOf(AccessResult::class, $neutral);
    $this->assertFalse($neutral->isForbidden());
    $this->assertContains('route', $neutral->getCacheContexts());
    $this->assertContains('headers:' . McpClassificationResolver::HEADER_DECLARED_CEILING, $neutral->getCacheContexts());

    // So does an under-ceiling filter-access decision.
    $profile = $this->container->get('mcp_sentinel.policy_resolver')->resolve($this->agent);
    $filter = $this->container->get('mcp_sentinel.access_checker')->getJsonApiFilterAccess('node', $profile);
    $this->assertArrayHasKey(JSONAPI_FILTER_AMONG_ALL, $filter);
    $this->assertFalse($filter[JSONAPI_FILTER_AMONG_ALL]->isForbidden());
    $this->assertContains('headers:' . McpClassificationResolver::HEADER_DECLARED_CEILING, $filter[JSONAPI_FILTER_AMONG_ALL]->getCacheContexts());
  }

}
