<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\OwnPermissionFixtureTool;
use Drupal\tool\Tool\ToolDefinition;
use Drupal\tool\Tool\ToolManager;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Governed tools declare the context permission on their Tool API definition.
 *
 * Catalog code that cannot supply inputs, such as MCP Server Tool Bridge's
 * tools/list, asks ToolManager::checkPermission() about the definition alone.
 * A governed tool that declares no permission would be advertised to every
 * account with endpoint access, even though execution refuses it. A tool
 * that declares its own permission keeps it and also requires the context
 * permission, so either permission alone is not enough for the catalog.
 *
 * @group mcp_sentinel
 *
 * @see https://www.drupal.org/project/mcp_sentinel/issues/3629706
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpGovernedToolDeclaredPermissionTest extends KernelTestBase {

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
    'mcp_sentinel_downstream_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'mcp_sentinel']);
    // The first account is uid 1 and passes every permission check.
    $this->createUser([], 'superuser');
  }

  /**
   * Every governed tool carries the context permission.
   *
   * A tool that declares its own permission keeps that permission as an
   * additional required part.
   */
  public function testGovernedToolsDeclareTheContextPermission(): void {
    $governed = [];
    foreach ($this->container->get('plugin.manager.tool')->getDefinitions() as $id => $definition) {
      self::assertInstanceOf(ToolDefinition::class, $definition);
      if (!is_subclass_of($definition->getClass(), McpGovernedToolBase::class)) {
        continue;
      }
      $governed[$id] = $definition->getPermission();
    }

    self::assertGreaterThanOrEqual(12, count($governed), 'The shipped governed tools were discovered.');
    self::assertSame(
      McpGovernedToolBase::CONTEXT_PERMISSION . ',' . OwnPermissionFixtureTool::PERMISSION,
      $governed['mcp_sentinel_own_permission_fixture'],
    );
    unset($governed['mcp_sentinel_own_permission_fixture']);
    foreach ($governed as $id => $permission) {
      self::assertSame(McpGovernedToolBase::CONTEXT_PERMISSION, $permission, $id);
    }
  }

  /**
   * The input-free catalog check denies accounts that cannot run the tool.
   */
  public function testCatalogCheckDeniesAccountsWithoutTheContextPermission(): void {
    $definition = $this->container->get('plugin.manager.tool')->getDefinition('mcp_sentinel_site_context');
    self::assertInstanceOf(ToolDefinition::class, $definition);

    $outsider = $this->createUser(['access content']);
    self::assertFalse(ToolManager::checkPermission($definition, $outsider)->isAllowed());

    $agent = $this->createUser([McpGovernedToolBase::CONTEXT_PERMISSION]);
    self::assertTrue(ToolManager::checkPermission($definition, $agent)->isAllowed());
  }

  /**
   * A tool's own permission does not stand in for the context permission.
   *
   * The catalog check requires both. An account that holds only one of them
   * cannot run the tool, so the catalog hides it.
   */
  public function testCatalogCheckRequiresBothPermissionsWhenTheToolDeclaresOne(): void {
    $manager = $this->container->get('plugin.manager.tool');
    $definition = $manager->getDefinition('mcp_sentinel_own_permission_fixture');
    self::assertInstanceOf(ToolDefinition::class, $definition);

    $custom_only = $this->createUser([OwnPermissionFixtureTool::PERMISSION]);
    self::assertFalse(ToolManager::checkPermission($definition, $custom_only)->isAllowed());

    $context_only = $this->createUser([McpGovernedToolBase::CONTEXT_PERMISSION]);
    self::assertFalse(ToolManager::checkPermission($definition, $context_only)->isAllowed());

    $both = $this->createUser([
      McpGovernedToolBase::CONTEXT_PERMISSION,
      OwnPermissionFixtureTool::PERMISSION,
    ]);
    self::assertTrue(ToolManager::checkPermission($definition, $both)->isAllowed());
  }

}
