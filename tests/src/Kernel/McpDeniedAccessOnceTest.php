<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\McpRolePermissions;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * A deny writes one HMAC row, even when more than one gate fires.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDeniedAccessOnceTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;
  use ContentModerationTestTrait;

  /**
   * Synthetic tenant that owns the fixture.
   */
  private const TENANT_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';

  /**
   * Synthetic tenant that must be refused.
   */
  private const TENANT_B = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'datetime',
    'views',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'workflows',
    'content_moderation',
    'language',
    'content_translation',
    'scheduler',
    'scheduler_content_moderation_integration',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('content_moderation_state');
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'content_moderation',
      'scheduler',
      'mcp_sentinel',
    ]);
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    McpRolePermissions::grant('mcp_api', [
      'access content',
      'access user profiles',
      'administer nodes',
      'access mcp sentinel context',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
    ]);
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->save();
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->save();
    $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile')
      ->resetCache();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $article = NodeType::create([
      'type' => 'article',
      'name' => 'Article',
    ]);
    $article->setThirdPartySetting('scheduler', 'publish_enable', TRUE);
    $article->setThirdPartySetting('scheduler', 'unpublish_enable', TRUE);
    $article->save();
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'article');
    // Uid 1 bypasses entity access; burn it so the agent is ordinary.
    $this->createUser();
  }

  /**
   * A tenant-mismatch tool update writes exactly one denied_access row.
   */
  public function testNodeOperationsTenantUpdateWritesOneDeniedAccessRow(): void {
    $this->actAsGovernedAgent();
    $node = $this->createOwnedPage();
    $this->sealTenant(self::TENANT_B, 'subject-b');
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'update');
    $tool->setInputValue('id', (string) $node->id());
    $tool->setInputValue('title', 'Taken');
    $tool->execute();

    $this->assertFalse(
      $tool->getResultStatus(),
      'Another tenant must not update the owned node.',
    );
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'The hook refuse() row must be the only denied_access write.',
    );
  }

  /**
   * Tool skip is by entity and operation, not by rule.
   *
   * The tool's own reasons map to a different rule than the hook's
   * tenant_mismatch, so a same-operation skip must still collapse the
   * second write. A later different operation on the same entity writes.
   */
  public function testToolSkipMatchesEntityAndOperationNotRule(): void {
    $this->actAsGovernedAgent();
    $node = $this->createOwnedPage();
    $this->sealTenant(self::TENANT_B, 'subject-b');
    $account = $this->container->get('current_user')->getAccount();
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $this->assertTrue($node->access('view', $account, TRUE)->isForbidden());
    $this->assertSame(1, $this->deniedAccessCount());

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $log = new \ReflectionMethod($tool, 'logDeniedAccess');
    $id = (string) $node->id();

    $log->invoke(
      $tool,
      'mcp_sentinel_node_operations',
      'node',
      $id,
      'view',
      'core access denied',
    );
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'The same entity and operation must not write a second row.',
    );

    $log->invoke(
      $tool,
      'mcp_sentinel_node_operations',
      'node',
      $id,
      'update',
      'core access denied',
    );
    $this->assertSame(
      2,
      $this->deniedAccessCount(),
      'A different operation on the same entity must write its own row.',
    );
    $this->assertEqualsCanonicalizing(
      ['view', 'update'],
      $this->deniedAccessOperations(),
    );
  }

  /**
   * Workflow-transition tenant deny writes exactly one denied_access row.
   */
  public function testWorkflowTransitionTenantUpdateWritesOneDeniedAccessRow(): void {
    $this->actAsGovernedAgent();
    $node = $this->createOwnedDraftArticle();
    $this->sealTenant(self::TENANT_B, 'subject-b');
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_workflow_transition');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', (string) $node->id());
    $tool->setInputValue('state', 'published');
    $tool->execute();

    $this->assertFalse(
      $tool->getResultStatus(),
      'Another tenant must not transition the owned article.',
    );
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'The hook refuse() row must be the only denied_access write.',
    );
  }

  /**
   * Bulk-operations tenant deny writes exactly one denied_access row.
   */
  public function testBulkOperationsTenantUpdateWritesOneDeniedAccessRow(): void {
    $this->actAsGovernedAgent();
    $node = $this->createOwnedPage();
    $this->sealTenant(self::TENANT_B, 'subject-b');
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'unpublish');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', [(string) $node->id()]);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    $data = $tool->getResult()->getContextValues();
    $this->assertArrayHasKey(
      (string) $node->id(),
      $data['failed'] ?? [],
      'Another tenant must not unpublish the owned node.',
    );
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'The hook refuse() row must be the only denied_access write.',
    );
  }

  /**
   * Tenant and scheduled-publish both refusing one update write one row.
   *
   * Both gates run through hook_entity_access(): the tenant boundary
   * returns first so the scheduled-publish gate never refuse()s.
   */
  public function testTenantAndScheduledUpdateWritesOneDeniedAccessRow(): void {
    $this->actAsGovernedAgent();
    $node = $this->createOwnedScheduledArticle();
    $this->configureProfile([
      'allow_scheduled_publish' => TRUE,
      'max_moderation_state' => 'draft',
    ]);
    $account = $this->container->get('current_user')->getAccount();

    $this->container->get('database')->delete('audit_chain_log')->execute();
    $ceiling = $node->access('update', $account, TRUE);
    $this->assertTrue(
      $ceiling->isForbidden(),
      'The scheduled-publish ceiling must refuse the owning tenant.',
    );
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'The scheduled-publish gate must write one row for tenant A.',
    );
    $this->assertSame(
      'scheduled_transition',
      $this->lastDenialMetadata()['rule'] ?? NULL,
    );

    $this->sealTenant(self::TENANT_B, 'subject-b');
    $this->container->get('database')->delete('audit_chain_log')->execute();
    $access = $node->access('update', $account, TRUE);
    $this->assertTrue($access->isForbidden());
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'One update refused by both gates must leave one denied_access row.',
    );
    $this->assertSame(
      'tenant_mismatch',
      $this->lastDenialMetadata()['rule'] ?? NULL,
    );
  }

  /**
   * Two entities denied by the same rule in one request write two rows.
   */
  public function testTwoEntitiesSameRuleWriteTwoDeniedAccessRows(): void {
    $this->actAsGovernedAgent();
    $first = $this->createUser([]);
    $second = $this->createUser([]);
    $this->assertInstanceOf(User::class, $first);
    $this->assertInstanceOf(User::class, $second);
    $account = $this->container->get('current_user')->getAccount();
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $this->assertTrue($first->access('view', $account, TRUE)->isForbidden());
    $this->assertTrue($second->access('view', $account, TRUE)->isForbidden());
    $this->assertSame(
      2,
      $this->deniedAccessCount(),
      'The dedupe key must include entity type and id.',
    );
  }

  /**
   * View and update of the same entity in one request write two rows.
   */
  public function testSameEntityViewAndUpdateWriteTwoDeniedAccessRows(): void {
    $this->actAsGovernedAgent();
    $user = $this->createUser([]);
    $this->assertInstanceOf(User::class, $user);
    $account = $this->container->get('current_user')->getAccount();
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $this->assertTrue($user->access('view', $account, TRUE)->isForbidden());
    $this->assertTrue($user->access('update', $account, TRUE)->isForbidden());
    $this->assertSame(
      2,
      $this->deniedAccessCount(),
      'The dedupe key must include the rule and the operation.',
    );
    $this->assertEqualsCanonicalizing(
      ['view', 'update'],
      $this->deniedAccessOperations(),
    );
  }

  /**
   * With no current request, identical refuses are not collapsed.
   */
  public function testNoRequestNeverDedupesDeniedAccess(): void {
    $stack = $this->container->get('request_stack');
    $popped = [];
    while ($stack->getCurrentRequest() !== NULL) {
      $popped[] = $stack->pop();
    }
    try {
      $explainer = $this->container->get('mcp_sentinel.deny_explainer');
      $this->container->get('database')->delete('audit_chain_log')->execute();

      $explainer->refuse('tenant_mismatch');
      $explainer->refuse('tenant_mismatch');
      $this->assertSame(
        2,
        $this->deniedAccessCount(),
        'A queue worker with no request must not reuse a dedupe slot.',
      );
    }
    finally {
      // KernelTestBase::tearDown() reads the session off the current
      // request on Drupal 11.3, so hand the bootstrap request(s) back.
      foreach (array_reverse($popped) as $request) {
        $stack->push($request);
      }
    }
  }

  /**
   * Counts denied_access rows written during this test.
   */
  private function deniedAccessCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Decodes the latest denied_access metadata.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  private function lastDenialMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id', 'metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $meta['id'] = (string) $row['entity_id'];
    return $meta;
  }

  /**
   * Entity operations recorded on denied_access rows, oldest first.
   *
   * @return list<string|null>
   *   metadata.operation values.
   */
  private function deniedAccessOperations(): array {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $ops = [];
    $result = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'ASC')
      ->execute();
    foreach ($result as $record) {
      $meta = $logger->decodeMetadata((string) $record->metadata);
      $ops[] = $meta['operation'] ?? NULL;
    }
    return $ops;
  }

  /**
   * A governed mcp_api account set as the current user.
   */
  private function actAsGovernedAgent(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Creates a page owned by tenant A.
   */
  private function createOwnedPage(): Node {
    $this->sealTenant(self::TENANT_A, 'subject-a');
    $node = Node::create([
      'type' => 'page',
      'title' => 'Owned page',
      'status' => 1,
    ]);
    $node->save();
    return $node;
  }

  /**
   * Creates a moderated draft article owned by tenant A.
   */
  private function createOwnedDraftArticle(): Node {
    $this->sealTenant(self::TENANT_A, 'subject-a');
    $node = Node::create([
      'type' => 'article',
      'title' => 'Owned article',
      'moderation_state' => 'draft',
      'status' => 0,
    ]);
    $node->save();
    return $node;
  }

  /**
   * Creates a scheduled article owned by tenant A.
   *
   * The profile allows scheduled publishing and there is no ceiling, so
   * the owning tenant may store the schedule. The caller then tightens
   * max_moderation_state so a later update is refused.
   */
  private function createOwnedScheduledArticle(): Node {
    $this->configureProfile(['allow_scheduled_publish' => TRUE]);
    $this->sealTenant(self::TENANT_A, 'subject-a');
    $node = Node::create([
      'type' => 'article',
      'title' => 'Owned scheduled',
      'moderation_state' => 'draft',
      'status' => 0,
    ]);
    $now = \Drupal::time()->getRequestTime();
    $node->set('publish_on', $now + 86400);
    $node->set('publish_state', 'published');
    $node->save();
    return $node;
  }

  /**
   * Sets keys on the default policy profile.
   *
   * @param array<string, mixed> $values
   *   Profile keys and their values.
   */
  private function configureProfile(array $values): void {
    $config = $this->config('mcp_sentinel.mcp_policy_profile.default');
    foreach ($values as $key => $value) {
      $config->set($key, $value);
    }
    $config->save();
    $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile')
      ->resetCache();
    $this->container->get('entity_type.manager')
      ->getAccessControlHandler('node')
      ->resetCache();
  }

  /**
   * Seals a synthetic network principal on the current request.
   */
  private function sealTenant(string $tenant, string $subject): void {
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://issuer.example/realms/disposable',
      'sub' => $subject,
      'azp' => 'drupal-mcp',
      'tenant' => $tenant,
      'scope' => 'mcp_read mcp_write',
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $holder = $this->principalContextHolder();
    $holder->resetForTest();
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    $stack->push($request);
    $this->container->get('entity_type.manager')
      ->getAccessControlHandler('node')
      ->resetCache();
    $context = $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest($request);
    $holder->seal($context, $request);
  }

}
