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
 *
 * @runTestsInSeparateProcesses
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
    'audit_chain',
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
   * The TOOLS registration list covers every base tool plugin.
   *
   * TOOLS is the explicit allow-list of tool ids the setup command registers;
   * a refactored plugin id not updated here would silently lose registration.
   */
  public function testServerCommandsToolListCoversBasePlugins(): void {
    $rc = new \ReflectionClass(McpSentinelServerCommands::class);
    $constants = $rc->getConstants();
    $this->assertArrayHasKey('TOOLS', $constants,
      'McpSentinelServerCommands must declare a TOOLS constant.');

    // TOOLS is a flat list of tool ids; every base tool must appear (the
    // graphql schema tool is conditional on the graphql submodule).
    foreach (self::BASE_TOOL_IDS as $toolId) {
      $this->assertContains($toolId, $constants['TOOLS'],
        "Tool '$toolId' is missing from McpSentinelServerCommands::TOOLS.");
    }
  }

  /**
   * Every registered tool derives a valid, non-empty 'mcp_*' scope.
   *
   * The scope is derived per plugin (operation + config-domain) and forwarded
   * to mcp_server_oauth; an empty or malformed scope would silently disable
   * auth on a registered tool. Scope machine ids use the 'mcp_*' convention so
   * the token scope matches the governance allowlist end-to-end.
   */
  public function testEveryRegisteredToolDerivesValidScope(): void {
    $command = $this->serverCommands();
    $rc = new \ReflectionClass(McpSentinelServerCommands::class);
    $toolIds = $rc->getConstants()['TOOLS'] ?? [];

    foreach ($toolIds as $toolId) {
      // graphql_schema is conditional on the graphql submodule; only assert
      // the base tools discoverable in this test's module set.
      if (!in_array($toolId, self::BASE_TOOL_IDS, TRUE)) {
        continue;
      }
      $scope = $command->scopeForTool($toolId);
      $this->assertIsString($scope, "Scope for '$toolId' must be a string.");
      $this->assertNotEmpty($scope, "Scope for '$toolId' must not be empty.");
      $this->assertStringStartsWith('mcp_', $scope,
        "Scope '$scope' for '$toolId' must follow the 'mcp_*' namespace.");
    }
  }

  /**
   * The command derives each tool's scope from the plugin's own declarations.
   *
   * Config-read tools are isolated behind the read-only 'mcp_config_read'
   * scope; the config write tool keeps 'mcp_config'. Content tools derive
   * mcp_read/mcp_write from their ToolOperation. Derived, not tabulated, so the
   * plugin's operation + ConfigScopeToolInterface are the source of truth.
   */
  public function testScopeForToolDerivesConfigAndContentScopes(): void {
    $command = $this->serverCommands();

    // Config domain: reads isolated behind the read-only config scope; write
    // behind the config write scope.
    $this->assertSame('mcp_config_read', $command->scopeForTool('mcp_sentinel_config_get'));
    $this->assertSame('mcp_config_read', $command->scopeForTool('mcp_sentinel_config_list'));
    $this->assertSame('mcp_config', $command->scopeForTool('mcp_sentinel_config_set'));

    // Content domain: derived from ToolOperation::isModifying().
    $this->assertSame('mcp_read', $command->scopeForTool('mcp_sentinel_site_context'));
    $this->assertSame('mcp_read', $command->scopeForTool('mcp_sentinel_security_policy'));
    $this->assertSame('mcp_write', $command->scopeForTool('mcp_sentinel_node_operations'));
    $this->assertSame('mcp_write', $command->scopeForTool('mcp_sentinel_workflow_transition'));
  }

  /**
   * No content-domain tool may derive a config-tier scope.
   *
   * Security boundary: a content-tier token (mcp_read/mcp_write) must never
   * reach a config tool, so none of the base content tools may derive
   * 'mcp_config' or 'mcp_config_read'.
   */
  public function testNoContentToolDerivesConfigScope(): void {
    $command = $this->serverCommands();

    // BASE_TOOL_IDS are the content/read tools only — none are config tools.
    foreach (self::BASE_TOOL_IDS as $toolId) {
      $scope = $command->scopeForTool($toolId);
      $this->assertNotSame('mcp_config', $scope,
        "Content tool '$toolId' must not derive the 'mcp_config' scope.");
      $this->assertNotSame('mcp_config_read', $scope,
        "Content tool '$toolId' must not derive the 'mcp_config_read' scope.");
    }
  }

  /**
   * The auditor tier is read-only: config-read, no write or admin scopes.
   *
   * Security boundary: the read-only config auditor exists to read config for
   * governance/audits without any write capability. It must map to the
   * dedicated auditor role and carry mcp_config_read but none of the write or
   * admin scopes.
   */
  public function testAuditorTierIsReadOnly(): void {
    $rc = new \ReflectionClass(McpSentinelServerCommands::class);
    $tiers = $rc->getConstants()['TIERS'] ?? [];

    $this->assertArrayHasKey('auditor', $tiers, 'An auditor tier must be defined.');
    [$role, $scopes] = $tiers['auditor'];

    $this->assertSame('mcp_config_auditor', $role,
      'The auditor tier must map to the dedicated read-only config role.');
    $this->assertContains('mcp_config_read', $scopes,
      'The auditor tier must grant the read-only config scope.');
    $this->assertNotContains('mcp_config', $scopes,
      'The auditor tier must not grant the config write scope.');
    $this->assertNotContains('mcp_write', $scopes,
      'The auditor tier must not grant the content write scope.');
    $this->assertNotContains('mcp_admin', $scopes,
      'The auditor tier must not grant the admin scope.');
  }

  /**
   * The config-capable tiers retain config read after the scope split.
   *
   * The config_get/config_list tools now require mcp_config_read, so the
   * developer and admin tiers must also carry it or they lose config read.
   */
  public function testDeveloperAndAdminTiersRetainConfigRead(): void {
    $rc = new \ReflectionClass(McpSentinelServerCommands::class);
    $tiers = $rc->getConstants()['TIERS'] ?? [];

    $this->assertContains('mcp_config_read', $tiers['developer'][1],
      'The developer tier must carry mcp_config_read to keep config read.');
    $this->assertContains('mcp_config_read', $tiers['admin'][1],
      'The admin tier must carry mcp_config_read to keep config read.');
  }

  /**
   * Builds the server commands service from the container.
   *
   * @return \Drupal\mcp_sentinel_server\Drush\Commands\McpSentinelServerCommands
   *   The command object with real collaborators wired.
   */
  private function serverCommands(): McpSentinelServerCommands {
    return new McpSentinelServerCommands(
      $this->container->get('entity_type.manager'),
      $this->container->get('module_handler'),
      $this->container->get('plugin.manager.tool'),
      $this->container->get('cache_tags.invalidator'),
      $this->container->get('config.factory'),
    );
  }

}
