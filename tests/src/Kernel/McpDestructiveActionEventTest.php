<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the destructive-action veto event on the config-set tool.
 *
 * Mirrors McpDestructiveOpEventTest for the non-entity (config) path. The base
 * module must apply a governed config write when nothing vetoes; when a
 * subscriber vetoes (as mcp_sentinel_approval does), the write must be held and
 * reported as queued for approval, and the configuration must be unchanged.
 *
 * Regression guard: McpConfigSetTool must dispatch the event under
 * McpDestructiveActionEvent::NAME. A nameless dispatch is delivered under the
 * event's class name instead, so the approval subscriber never fires and the
 * write silently proceeds — the veto seam becomes a no-op.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDestructiveActionEventTest extends KernelTestBase {

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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('path_alias');
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installConfig(['system', 'mcp_sentinel']);

    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    // A profile that permits config writes so execution reaches the veto seam.
    McpPolicyProfile::create([
      'id'                 => 'agent_config_write',
      'label'              => 'Agent config-write profile',
      'roles'              => ['mcp_agent'],
      'weight'             => 10,
      'allow_config_read'  => TRUE,
      'allow_config_write' => TRUE,
    ])->save();

    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Runs the config-set tool for one key and returns its result context values.
   *
   * @param string $name
   *   The config object name.
   * @param array $data
   *   The map of keys to write.
   *
   * @return array
   *   The structured result context values.
   */
  private function runConfigSet(string $name, array $data): array {
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_config_set');
    $tool->setInputValue('name', $name);
    $tool->setInputValue('data', $data);
    $tool->execute();
    return $tool->getResult()->getContextValues();
  }

  /**
   * Reads a config value straight from storage, bypassing the static cache.
   */
  private function readConfig(string $name, string $key): mixed {
    $factory = $this->container->get('config.factory');
    $factory->reset($name);
    return $factory->get($name)->get($key);
  }

  /**
   * With no veto subscriber the governed config write is applied.
   */
  public function testConfigWriteProceedsWhenNotVetoed(): void {
    $result = $this->runConfigSet('system.site', ['slogan' => 'Applied directly']);

    $this->assertArrayNotHasKey('queued_for_approval', $result);
    $this->assertSame('Applied directly', $this->readConfig('system.site', 'slogan'));
  }

  /**
   * A subscriber vetoing under the event NAME holds the write for approval.
   *
   * This fails if McpConfigSetTool dispatches without the event NAME: the
   * listener would never run and the write would be applied instead of held.
   */
  public function testConfigWriteVetoedIsHeldForApproval(): void {
    $dispatcher = $this->container->get('event_dispatcher');
    $dispatcher->addListener(
      McpDestructiveActionEvent::NAME,
      static function (McpDestructiveActionEvent $event): void {
        $event->veto('Queued for approval (test).');
      },
    );

    $result = $this->runConfigSet('system.site', ['slogan' => 'Should not apply']);

    $this->assertArrayHasKey('queued_for_approval', $result);
    $this->assertTrue($result['queued_for_approval']);
    $this->assertNotSame(
      'Should not apply',
      $this->readConfig('system.site', 'slogan'),
      'A vetoed config write must not be applied.',
    );
  }

}
