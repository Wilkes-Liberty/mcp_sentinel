<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Event\McpDestructiveOpEvent;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the destructive-op veto event on the bulk operations tool.
 *
 * The base module must behave identically when no subscriber vetoes (the
 * approval submodule absent): a governed bulk delete deletes the entity. When a
 * subscriber vetoes, the entity must survive and land in the 'queued' results
 * bucket. This validates the decoupling seam used by mcp_sentinel_approval.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDestructiveOpEventTest extends KernelTestBase {

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
    $this->installEntitySchema('path_alias');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel']);

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('delete any article content');
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    McpPolicyProfile::create([
      'id'          => 'agent_delete',
      'label'       => 'Agent delete profile',
      'roles'       => ['mcp_agent'],
      'weight'      => 10,
      'allow_write' => TRUE,
      'allow_delete' => TRUE,
    ])->save();

    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
  }

  /**
   * Sets a governed user with full delete rights as the current user.
   */
  private function setGovernedCurrentUser(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Runs the bulk delete tool against a single node id and returns its result.
   *
   * @param int $nid
   *   The node id to delete.
   *
   * @return array
   *   The structured result array (succeeded/failed/queued).
   */
  private function runBulkDelete(int $nid): array {
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', [(string) $nid]);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();
    return $tool->getResult()->getContextValues();
  }

  /**
   * Bulk operations returns a failure when the current user has no profile.
   *
   * Regression guard for the Fix 2 null-profile guard: an ungoverned account
   * must be rejected up-front rather than falling through the entity loop.
   */
  public function testBulkOperationsFailsForUngovernedAccount(): void {
    // Create a user without the mcp_agent role — no profile will resolve.
    $account = $this->createUser(['delete any article content', 'access mcp sentinel context']);
    $this->container->get('current_user')->setAccount($account);

    $node = Node::create(['type' => 'article', 'title' => 'Should survive']);
    $node->save();
    $nid = (int) $node->id();

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_bulk_operations');
    $tool->setInputValue('operation', 'delete');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('ids', [(string) $nid]);
    $tool->setInputValue('confirm', TRUE);
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Bulk operations must fail when no governance profile applies.');
    $this->assertStringContainsString(
      'no governance profile',
      (string) $tool->getResultMessage(),
    );
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'Node must not be deleted when the account is ungoverned.',
    );
  }

  /**
   * With no veto subscriber the bulk delete proceeds (regression guard).
   */
  public function testBulkDeleteProceedsWhenNotVetoed(): void {
    $this->setGovernedCurrentUser();

    $node = Node::create(['type' => 'article', 'title' => 'Doomed']);
    $node->save();
    $nid = (int) $node->id();

    $results = $this->runBulkDelete($nid);

    $this->assertContains((string) $nid, $results['succeeded']);
    $this->assertSame([], $results['queued']);
    $this->assertNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'Node must be deleted when nothing vetoes.',
    );
  }

  /**
   * A subscriber that vetoes prevents deletion and queues the id.
   */
  public function testBulkDeleteVetoedKeepsEntity(): void {
    $this->setGovernedCurrentUser();

    // Register a throwaway subscriber that vetoes every destructive op.
    $dispatcher = $this->container->get('event_dispatcher');
    $dispatcher->addListener(
      McpDestructiveOpEvent::NAME,
      static function (McpDestructiveOpEvent $event): void {
        $event->veto('Queued for approval (test).');
      },
    );

    $node = Node::create(['type' => 'article', 'title' => 'Survivor']);
    $node->save();
    $nid = (int) $node->id();

    $results = $this->runBulkDelete($nid);

    $this->assertSame([], $results['succeeded']);
    $this->assertArrayHasKey($nid, $results['queued']);
    $this->assertSame('Queued for approval (test).', $results['queued'][$nid]);
    $this->assertNotNull(
      $this->container->get('entity_type.manager')->getStorage('node')->load($nid),
      'Node must survive when the destructive op is vetoed.',
    );
  }

}
