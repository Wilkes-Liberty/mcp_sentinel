<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessException;
use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpTenantResourceBoundary;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tenant ownership at the governed resource boundary (DEV-839).
 *
 * A content entity created under one sealed network tenant is readable
 * and writable only by that tenant. Another tenant is refused with no
 * stored change. An entity with no ownership row keeps its existing
 * access. The user entity is not owned this way.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpTenantResourceBoundaryTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * Synthetic tenant A. Not a live tenant identifier.
   */
  private const TENANT_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';

  /**
   * Synthetic tenant B. Not a live tenant identifier.
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
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('node', ['node_access']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_tenant_resource']);
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'mcp_sentinel',
    ]);
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * Another tenant cannot read or change an owned fixture.
   */
  public function testOtherTenantCannotReadOrChangeOwnedFixture(): void {
    // User 1 is granted every permission, including bypass node access.
    // The node handler returns before hook_entity_access() runs.
    $this->createUser();
    $editor = $this->createUser([
      'access content',
      'edit any page content',
      'delete any page content',
    ]);
    $this->assertNotSame('1', (string) $editor->id());
    $this->assertFalse($editor->hasPermission('bypass node access'));

    $this->sealTenant(self::TENANT_A, 'subject-a');
    $node = Node::create([
      'type' => 'page',
      'title' => 'fixture-a',
      'status' => 1,
    ]);
    $node->save();
    $id = (int) $node->id();
    $this->assertSame(self::TENANT_A, $this->ownerOf($node));

    $own_view = $this->nodeAccess($node, 'view', $editor);
    $this->assertFalse(
      $own_view->isForbidden(),
      'The owning tenant can view the fixture.',
    );

    $this->sealTenant(self::TENANT_B, 'subject-b');
    $view = $this->nodeAccess($node, 'view', $editor);
    $this->assertTrue(
      $view->isForbidden(),
      'Another tenant cannot view an owned fixture.',
    );
    $this->assertSame('tenant_mismatch', $this->reason($view));
    $this->assertSame(0, $view->getCacheMaxAge());
    $update = $this->nodeAccess($node, 'update', $editor);
    $this->assertTrue(
      $update->isForbidden(),
      'Another tenant cannot update an owned fixture.',
    );
    $this->assertSame('tenant_mismatch', $this->reason($update));

    $node->setTitle('taken');
    $this->assertStorageRefused(static fn () => $node->save());
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$id]);
    $stored = $storage->load($id);
    $this->assertInstanceOf(Node::class, $stored);
    $this->assertSame('fixture-a', $stored->label());

    $this->assertStorageRefused(static fn () => $stored->delete());
    $storage->resetCache([$id]);
    $this->assertInstanceOf(Node::class, $storage->load($id));

    $this->sealTenant(self::TENANT_A, 'subject-a');
    $owned = $storage->load($id);
    $owned->setTitle('fixture-a-kept');
    $owned->save();
    $storage->resetCache([$id]);
    $kept = $storage->load($id);
    $this->assertSame('fixture-a-kept', $kept->label());

    $this->container->get('mcp_sentinel.principal_context_holder')->resetForTest();
    $this->container->get('entity_type.manager')
      ->getAccessControlHandler('node')
      ->resetCache();
    $open = $this->nodeAccess($kept, 'view', $editor);
    $this->assertFalse($open->isForbidden(), 'An unsealed request is not tenant-denied.');

    $shared = Node::create([
      'type' => 'page',
      'title' => 'unowned',
      'status' => 1,
    ]);
    $shared->save();
    $this->sealTenant(self::TENANT_B, 'subject-b');
    $shared_view = $this->nodeAccess($shared, 'view', $editor);
    $this->assertFalse(
      $shared_view->isForbidden(),
      'A fixture with no owner row keeps its existing access.',
    );

    $person = User::create([
      'name' => 'not-owned',
      'mail' => 'not-owned@example.com',
      'status' => 1,
    ]);
    $person->save();
    $user_view = $this->container->get('entity_type.manager')
      ->getAccessControlHandler('user')
      ->access($person, 'view', $editor, TRUE);
    $this->assertNotSame('tenant_mismatch', $this->reason($user_view));
  }

  /**
   * A tenant longer than the stored column cannot create a fixture.
   */
  public function testOversizedTenantCannotCreateFixture(): void {
    $this->sealTenant(str_repeat('b', 129), 'subject-long');
    $node = Node::create([
      'type' => 'page',
      'title' => 'too-long',
      'status' => 1,
    ]);
    $this->assertStorageRefused(static fn () => $node->save());
    $count = (int) $this->container->get('entity_type.manager')
      ->getStorage('node')
      ->getQuery()
      ->accessCheck(FALSE)
      ->count()
      ->execute();
    $this->assertSame(0, $count);
    $this->assertNull($this->ownerOf($node));
  }

  /**
   * Stored tenant for a node, or NULL when it has no owner row.
   */
  private function ownerOf(Node $node): ?string {
    $statement = $this->container->get('database')
      ->select(McpTenantResourceBoundary::TABLE, 'ownership')
      ->fields('ownership', ['tenant'])
      ->condition('entity_type', 'node')
      ->condition('uuid', (string) $node->uuid())
      ->execute();
    $value = $statement ? $statement->fetchField() : FALSE;
    return is_string($value) && $value !== '' ? $value : NULL;
  }

  /**
   * The write was rolled back with a tenant mismatch.
   *
   * Entity storage wraps the access exception and rolls the transaction
   * back. The caller checks that the fixture row is unchanged.
   */
  private function assertStorageRefused(callable $operation): void {
    try {
      $operation();
      $this->fail('The write must be refused before commit.');
    }
    catch (EntityStorageException $exception) {
      $this->assertSame('tenant_mismatch', $exception->getMessage());
      $this->assertInstanceOf(AccessException::class, $exception->getPrevious());
    }
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
    $holder = $this->container->get('mcp_sentinel.principal_context_holder');
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

  /**
   * Denial reason, or an empty string when the result has none.
   */
  private function reason(AccessResultInterface $result): string {
    return $result instanceof AccessResultReasonInterface ? $result->getReason() : '';
  }

  /**
   * Node access for one operation.
   */
  private function nodeAccess(
    Node $node,
    string $operation,
    AccountInterface $account,
  ): AccessResult {
    $result = $this->container->get('entity_type.manager')
      ->getAccessControlHandler('node')
      ->access($node, $operation, $account, TRUE);
    $this->assertInstanceOf(AccessResult::class, $result);
    return $result;
  }

}
