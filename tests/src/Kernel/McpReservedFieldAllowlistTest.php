<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\comment\Entity\CommentType;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpNodeOperationsTool;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Field-definition allowlist for node/media fields maps (DEV-844).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpReservedFieldAllowlistTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;

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
    'comment',
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
    $this->installEntitySchema('comment');
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'comment',
      'mcp_sentinel',
    ]);

    $role = Role::load('mcp_api') ?? Role::create([
      'id' => 'mcp_api',
      'label' => 'MCP API',
    ]);
    $role->grantPermission('access mcp sentinel context')
      ->grantPermission('administer nodes')
      ->save();

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
      ->set('denied_entity_types', [])
      ->save();
    $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile')
      ->resetCache();

    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $this->createStringField('node', 'page', 'subject', 'Subject');
    $this->createStringField('node', 'page', 'sub', 'Token sub');
    $this->createUserReferenceField('node', 'page', 'actor', 'Actor');

    CommentType::create([
      'id' => 'comment',
      'label' => 'Default comments',
      'target_entity_type_id' => 'node',
    ])->save();

  }

  /**
   * Comment and node subject fields are allowlisted; owner fields are not.
   */
  public function testServiceAllowsRealSubjectAndRefusesOwner(): void {
    $service = $this->container->get('mcp_sentinel.entity_field_reserved_allowlist');

    $comment = $service->forBundle('comment', 'comment');
    $this->assertContains('subject', $comment['allow']);
    $this->assertContains('uid', $comment['refuse']);

    $page = $service->forBundle('node', 'page');
    $this->assertContains('subject', $page['allow']);
    $this->assertNotContains('sub', $page['allow']);
    $this->assertContains('uid', $page['refuse']);
    $this->assertContains('revision_uid', $page['refuse']);
    $this->assertContains('actor', $page['refuse']);

    $article = $service->forBundle('node', 'article');
    $this->assertNotContains('subject', $article['allow']);
  }

  /**
   * A real subject field on the target bundle is accepted.
   */
  public function testRealSubjectFieldAccepted(): void {
    $this->createGovernedAccount();
    $tool = $this->executeNodeCreate('page', [
      'subject' => 'Hello from comment-like subject',
    ]);
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $this->assertStringNotContainsString(
      'identity or tenant keys',
      (string) $tool->getResultMessage(),
    );
  }

  /**
   * A uid key in fields is refused (author comes from the token).
   */
  public function testUidInFieldsRefused(): void {
    $tool = $this->executeNodeCreate('page', ['uid' => 2]);
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('fields.uid', (string) $tool->getResultMessage());
  }

  /**
   * A user-reference field is refused even when its name is reserved.
   */
  public function testUserReferenceFieldRefused(): void {
    $tool = $this->executeNodeCreate('page', ['actor' => 1]);
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('fields.actor', (string) $tool->getResultMessage());
  }

  /**
   * A reserved subject key that is not a field on the bundle is refused.
   */
  public function testNonexistentSubjectRefused(): void {
    $tool = $this->executeNodeCreate('article', ['subject' => 'No such field']);
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('fields.subject', (string) $tool->getResultMessage());
  }

  /**
   * A sub field is refused even when that field exists.
   */
  public function testSubFieldNeverExempt(): void {
    $tool = $this->executeNodeCreate('page', ['sub' => 'spoof']);
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('fields.sub', (string) $tool->getResultMessage());
  }

  /**
   * Update refuse lists use the loaded node's type, not a caller bundle.
   */
  public function testUpdateRefuseListIgnoresCallerBundle(): void {
    $this->createUserReferenceField('node', 'page', 'field_author', 'Author');
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => 'page',
      'title' => 'Owned page',
      'uid' => 1,
    ]);
    $node->save();

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    self::assertInstanceOf(McpNodeOperationsTool::class, $tool);
    $tool->setInputValue('action', 'update');
    $tool->setInputValue('id', (string) $node->id());
    $tool->setInputValue('bundle', 'article');
    $tool->setInputValue('fields', ['field_author' => 1]);
    $tool->execute();

    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString(
      'fields.field_author',
      (string) $tool->getResultMessage(),
    );
  }

  /**
   * A governed mcp_api account set as the current user.
   */
  private function createGovernedAccount(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Runs node_operations create with a fields map.
   *
   * @param string $bundle
   *   Node type.
   * @param array<string, mixed> $fields
   *   The fields map.
   */
  private function executeNodeCreate(string $bundle, array $fields): McpNodeOperationsTool {
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    self::assertInstanceOf(McpNodeOperationsTool::class, $tool);
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', $bundle);
    $tool->setInputValue('title', 'Reserved-field probe');
    $tool->setInputValue('published', FALSE);
    $tool->setInputValue('fields', $fields);
    $tool->execute();
    return $tool;
  }

  /**
   * Adds a string field to a bundle.
   */
  private function createStringField(
    string $entityType,
    string $bundle,
    string $name,
    string $label,
  ): void {
    FieldStorageConfig::create([
      'field_name' => $name,
      'entity_type' => $entityType,
      'type' => 'string',
    ])->save();
    FieldConfig::create([
      'field_name' => $name,
      'entity_type' => $entityType,
      'bundle' => $bundle,
      'label' => $label,
    ])->save();
  }

  /**
   * Adds an entity_reference-to-user field to a bundle.
   */
  private function createUserReferenceField(
    string $entityType,
    string $bundle,
    string $name,
    string $label,
  ): void {
    FieldStorageConfig::create([
      'field_name' => $name,
      'entity_type' => $entityType,
      'type' => 'entity_reference',
      'settings' => ['target_type' => 'user'],
    ])->save();
    FieldConfig::create([
      'field_name' => $name,
      'entity_type' => $entityType,
      'bundle' => $bundle,
      'label' => $label,
      'settings' => ['handler' => 'default:user'],
    ])->save();
  }

}
