<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_server\Kernel;

use Drupal\mcp_sentinel_server\Drush\Commands\McpSentinelServerCommands;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests that MCP Sentinel Tool plugins are discoverable by the Tool API.
 *
 * Covers gap G10: verifies that every plugin ID declared in
 * McpSentinelServerCommands::TOOLS is discoverable via the Tool plugin manager
 * (plugin.manager.tool). The mcp_sentinel_server submodule's setup command
 * iterates that list, so a missing or mis-keyed plugin would silently skip
 * registration.
 *
 * The mcp_server_tool_bridge dependency (mcp_server_tool_bridge:McpToolConfig
 * entity storage) is NOT required for this test — we only exercise the Tool
 * plugin discovery layer which is provided by the base 'tool' module that is
 * already a hard dependency of mcp_sentinel. The server submodule itself has
 * no install/schema requirements beyond its dependencies.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_server
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_server')]
#[RunTestsInSeparateProcesses]
final class McpServerRegistrationTest extends KernelTestBase {

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
   * Tool plugin IDs that the server submodule registers with mcp_server.
   *
   * These match the TOOLS constant in McpSentinelServerCommands (minus
   * mcp_sentinel_graphql_schema, which requires the graphql submodule).
   */
  private const BASE_TOOL_IDS = [
    'mcp_sentinel_site_context',
    'mcp_sentinel_security_policy',
    'mcp_sentinel_content_lock',
    'mcp_sentinel_node_operations',
    'mcp_sentinel_media_create',
    'mcp_sentinel_workflow_transition',
    'mcp_sentinel_bulk_operations',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Every base MCP Sentinel tool plugin is discoverable by plugin.manager.tool.
   *
   * Verifies the server submodule's TOOLS map references real plugin IDs.
   * A mismatch would cause mcp-sentinel:setup to silently skip the tool.
   */
  public function testBaseSentinelToolPluginsAreDiscoverable(): void {
    /** @var \Drupal\tool\Tool\ToolManager $manager */
    $manager = $this->container->get('plugin.manager.tool');

    foreach (self::BASE_TOOL_IDS as $toolId) {
      $this->assertTrue(
        $manager->hasDefinition($toolId),
        "Tool plugin '$toolId' must be discoverable by plugin.manager.tool."
      );
    }
  }

  /**
   * Each discovered tool plugin can be instantiated without error.
   *
   * Instantiation exercises the plugin factory + dependency injection wiring.
   * A constructor wiring error surfaces here rather than at setup-command time.
   */
  public function testBaseSentinelToolPluginsInstantiateCleanly(): void {
    /** @var \Drupal\tool\Tool\ToolManager $manager */
    $manager = $this->container->get('plugin.manager.tool');

    foreach (self::BASE_TOOL_IDS as $toolId) {
      if (!$manager->hasDefinition($toolId)) {
        $this->markTestSkipped("Tool plugin '$toolId' not found — skipping instantiation check.");
      }
      try {
        $tool = $manager->createInstance($toolId);
        $this->assertNotNull($tool, "Instantiated tool '$toolId' must not be null.");
      }
      catch (\Throwable $e) {
        $this->fail("Tool plugin '$toolId' threw during instantiation: " . $e->getMessage());
      }
    }
  }

  /**
   * The OAuth scope map in McpSentinelServerCommands covers every base tool.
   *
   * Validates that the TOOLS constant in McpSentinelServerCommands uses the
   * same IDs as the base tool set — a refactored plugin ID that is not updated
   * in the server commands would silently lose its scope tag.
   */
  public function testServerCommandsToolMapMatchesBasePlugins(): void {
    // Read the TOOLS constant via reflection so this test stays in sync when
    // new tools are added, without duplicating the list here.
    $rc = new \ReflectionClass(McpSentinelServerCommands::class);
    $constants = $rc->getConstants();
    $this->assertArrayHasKey('TOOLS', $constants,
      'McpSentinelServerCommands must declare a TOOLS constant.');

    $commandToolIds = array_keys($constants['TOOLS']);

    // Every base tool must appear in the command map (graphql schema tool
    // is conditional on the graphql submodule and may be present or absent).
    foreach (self::BASE_TOOL_IDS as $toolId) {
      $this->assertContains(
        $toolId,
        $commandToolIds,
        "Tool '$toolId' is missing from McpSentinelServerCommands::TOOLS."
      );
    }
  }

  /**
   * Every tool in the server command map has a valid OAuth scope string.
   *
   * The scope tags ('mcp:read' or 'mcp:write') are forwarded to
   * mcp_server_oauth; an empty or null scope would silently disable auth on
   * a registered tool.
   */
  public function testServerCommandsToolMapScopesAreNonEmpty(): void {
    $rc = new \ReflectionClass(McpSentinelServerCommands::class);
    $constants = $rc->getConstants();
    $tools = $constants['TOOLS'] ?? [];

    foreach ($tools as $toolId => $scope) {
      $this->assertIsString($scope,
        "Scope for tool '$toolId' must be a string.");
      $this->assertNotEmpty($scope,
        "Scope for tool '$toolId' must not be empty.");
      $this->assertStringStartsWith('mcp:',
        $scope,
        "Scope '$scope' for tool '$toolId' must follow the 'mcp:*' namespace.");
    }
  }

}
