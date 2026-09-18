<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_server\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\mcp_sentinel_server\Drush\Commands\McpSentinelServerCommands;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\ErrorHandler\DebugClassLoader;

/**
 * Tests that setup registrations appear in the MCP Server tool catalog.
 *
 * McpServerRegistrationTest covers Tool API discovery only. tools/list can
 * still return HTTP 200 with an empty catalog when the Tool Bridge plugin is
 * not discovered by plugin.manager.mcp_server.tool. This test asks that
 * manager after mcp-sentinel:setup writes the bridge configs.
 *
 * @group mcp_sentinel
 * @group mcp_sentinel_server
 *
 * @see https://www.drupal.org/project/mcp_sentinel/issues/3624392
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_server')]
#[RunTestsInSeparateProcesses]
final class McpServerCatalogTest extends KernelTestBase {

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
    $list = $this->container->get('extension.list.module');
    if (!$list->exists('mcp_server') || !$list->exists('mcp_server_tool_bridge')) {
      $this->markTestSkipped('drupal/mcp_server and mcp_server_tool_bridge must be installed.');
    }
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);
    $this->enableModules([
      'mcp_server',
      'mcp_server_tool_bridge',
      'mcp_sentinel_server',
    ]);
    $this->installConfig(['mcp_server']);
    // mcp_server discovers Plugin/Tool in every module. The Tool API module
    // ships Plugin/tool (lowercase). On a case-insensitive filesystem
    // Symfony's DebugClassLoader treats that as a class-name mismatch and
    // aborts getDefinitions() before the catalog can be read. CI installs
    // vendor on Linux, where the directories are distinct and this is a
    // no-op. Disable the checker so the catalog assertion can run locally.
    if (class_exists(DebugClassLoader::class)) {
      DebugClassLoader::disable();
    }
  }

  /**
   * Setup registrations are visible to plugin.manager.mcp_server.tool.
   *
   * This is the tools/list catalog. A missing ToolApi plugin leaves it empty
   * even when plugin.manager.tool still lists every Sentinel tool.
   */
  public function testSetupRegistersRequiredToolsInMcpServerCatalog(): void {
    $command = $this->serverCommands();
    $result = $command->setup([
      'allow-unauthenticated-development' => TRUE,
    ]);
    // Development setup writes the registrations and exits not-ready.
    $this->assertSame(3, $result);

    $this->assertTrue(
      $this->container->has('plugin.manager.mcp_server.tool'),
      'MCP Server tool plugin manager must exist after enabling mcp_server.',
    );
    /** @var \Drupal\Component\Plugin\Discovery\CachedDiscoveryInterface $manager */
    $manager = $this->container->get('plugin.manager.mcp_server.tool');
    $manager->clearCachedDefinitions();
    $definitions = $manager->getDefinitions();

    $toolManager = $this->container->get('plugin.manager.tool');
    foreach (McpToolScopeResolver::REQUIRED_TOOLS as $toolId) {
      $wireName = 'tool_api__' . $toolId;
      $this->assertArrayHasKey(
        $wireName,
        $definitions,
        "MCP Server catalog must include '$wireName' after mcp-sentinel:setup.",
      );
    }

    foreach (McpToolScopeResolver::OPTIONAL_TOOLS as $toolId) {
      $wireName = 'tool_api__' . $toolId;
      if ($toolManager->hasDefinition($toolId)) {
        $this->assertArrayHasKey(
          $wireName,
          $definitions,
          "Optional tool '$toolId' is compiled, so setup must register '$wireName'.",
        );
      }
      else {
        $this->assertArrayNotHasKey(
          $wireName,
          $definitions,
          "Optional tool '$toolId' is not compiled; setup must not invent '$wireName'.",
        );
      }
    }

    $this->assertArrayNotHasKey(
      'tool_api__mcp_sentinel_sql_query',
      $definitions,
      'SQL stays Tool API / Drush; setup must not register it in the MCP catalog.',
    );
  }

  /**
   * Without setup, required tools are absent from the MCP catalog.
   *
   * Confirms the catalog assertion is about bridge configs, not Tool API
   * discovery. The empty catalog is the same shape as a mismatched Tool
   * Bridge / MCP Server pairing.
   */
  public function testCatalogOmitsSentinelToolsUntilSetup(): void {
    $this->assertTrue(
      $this->container->has('plugin.manager.mcp_server.tool'),
      'MCP Server tool plugin manager must exist after enabling mcp_server.',
    );
    /** @var \Drupal\Component\Plugin\Discovery\CachedDiscoveryInterface $manager */
    $manager = $this->container->get('plugin.manager.mcp_server.tool');
    $manager->clearCachedDefinitions();
    $definitions = $manager->getDefinitions();

    foreach (McpToolScopeResolver::REQUIRED_TOOLS as $toolId) {
      $this->assertArrayNotHasKey(
        'tool_api__' . $toolId,
        $definitions,
        "Catalog must not include '$toolId' before mcp-sentinel:setup.",
      );
    }
  }

  /**
   * Builds the server commands service with console IO.
   *
   * @return \Drupal\mcp_sentinel_server\Drush\Commands\McpSentinelServerCommands
   *   The command object with real collaborators wired.
   */
  private function serverCommands(): McpSentinelServerCommands {
    $command = new McpSentinelServerCommands(
      $this->container->get('entity_type.manager'),
      $this->container->get('module_handler'),
      $this->container->get('plugin.manager.tool'),
      $this->container->get('cache_tags.invalidator'),
      $this->container->get('config.factory'),
    );
    $command->setInput(new ArrayInput([]));
    $command->setOutput(new BufferedOutput());
    return $command;
  }

}
