<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
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
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
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
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'mcp_sentinel',
    ]);
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    user_role_grant_permissions('mcp_api', [
      'access content',
      'access user profiles',
      'administer nodes',
      'access mcp sentinel context',
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
   * Tenant and scheduled-publish both refusing one update write one row.
   */
  public function testTenantAndScheduledUpdateWritesOneDeniedAccessRow(): void {
    $this->actAsGovernedAgent();
    $node = $this->createOwnedPage();
    $this->sealTenant(self::TENANT_B, 'subject-b');
    $this->container->get('database')->delete('audit_chain_log')->execute();

    $explainer = $this->container->get('mcp_sentinel.deny_explainer');
    $explainer->refuse(
      'Scheduled transition is not permitted by the MCP Sentinel profile.',
      NULL,
      TRUE,
      'node',
      (string) $node->id(),
    );
    $access = $node->access(
      'update',
      $this->container->get('current_user')->getAccount(),
      TRUE,
    );
    $this->assertTrue($access->isForbidden());
    $this->assertSame(
      1,
      $this->deniedAccessCount(),
      'One update refused by both gates must leave one denied_access row.',
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
