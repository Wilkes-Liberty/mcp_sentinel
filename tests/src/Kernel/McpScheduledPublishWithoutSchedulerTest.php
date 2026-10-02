<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * The scheduled-publish gate is inert when SCMI is not installed.
 *
 * Scheduler Content Moderation Integration is an optional module. Without it
 * there are no scheduled-state fields, so the setting must change nothing and
 * a governed draft save must behave exactly as before.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpScheduledPublishWithoutSchedulerTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;
  use ContentModerationTestTrait;

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
    'workflows',
    'content_moderation',
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
    $this->installConfig(['field', 'filter', 'system', 'node', 'user', 'content_moderation', 'mcp_sentinel']);

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'article');
    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access content');
    $role->grantPermission('create article content');
    $role->grantPermission('edit any article content');
    $role->grantPermission('use editorial transition create_new_draft');
    $role->save();

    $this->createUser([], 'bystander');
  }

  /**
   * With the setting on or off, a governed draft save is unchanged.
   */
  public function testGovernedDraftSaveIsUnchanged(): void {
    foreach ([FALSE, TRUE] as $allowed) {
      \Drupal::configFactory()
        ->getEditable('mcp_sentinel.mcp_policy_profile.default')
        ->set('allow_write', TRUE)
        ->set('denied_entity_types', [])
        ->set('allow_scheduled_publish', $allowed)
        ->save();
      \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
      $this->assertSame($allowed, McpPolicyProfile::load('default')->allowsScheduledPublishForEntityType('node'));

      $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
      \Drupal::currentUser()->setAccount($agent);

      $node = Node::create([
        'type' => 'article',
        'title' => 'Draft',
        'moderation_state' => 'draft',
        'uid' => $agent->id(),
      ]);
      $this->assertCount(0, $node->validate());
      $node->save();
      $this->assertFalse($node->hasField('publish_state'));
      $this->assertTrue($node->access('update', $agent));
    }
  }

}
