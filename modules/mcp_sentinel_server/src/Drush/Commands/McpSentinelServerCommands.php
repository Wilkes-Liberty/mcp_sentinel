<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_server\Drush\Commands;

use Drupal\Core\Cache\CacheTagsInvalidatorInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\tool\Tool\ToolManager;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Drush commands that register MCP Sentinel tools with mcp_server.
 *
 * The mcp_server Tool API bridge exposes Tool API plugins to MCP clients via
 * `mcp_tool_config` config entities. This command creates one such entity per
 * MCP Sentinel tool, and (when mcp_server_oauth is enabled) tags each with an
 * OAuth scope and authentication mode.
 */
final class McpSentinelServerCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * The OAuth scope namespace used for third-party settings.
   */
  private const OAUTH_PROVIDER = 'mcp_server_oauth';

  /**
   * MCP Sentinel tools to register, keyed by Tool API plugin id.
   *
   * The map value is the OAuth scope the tool is tagged with when the
   * mcp_server_oauth submodule is enabled.
   */
  private const TOOLS = [
    'mcp_sentinel_site_context' => 'mcp_read',
    'mcp_sentinel_security_policy' => 'mcp_read',
    'mcp_sentinel_content_lock' => 'mcp_write',
    'mcp_sentinel_node_operations' => 'mcp_write',
    'mcp_sentinel_media_create' => 'mcp_write',
    'mcp_sentinel_workflow_transition' => 'mcp_write',
    'mcp_sentinel_bulk_operations' => 'mcp_write',
    // Registered only when the mcp_sentinel_graphql submodule is enabled.
    'mcp_sentinel_graphql_schema' => 'mcp_read',
  ];

  /**
   * Cache tags to invalidate so mcp_server re-discovers the registered tools.
   */
  private const DISCOVERY_TAGS = ['mcp_server:discovery', 'mcp_server:tools'];

  /**
   * Constructs a new McpSentinelServerCommands object.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ModuleHandlerInterface $moduleHandler,
    #[Autowire(service: 'plugin.manager.tool')]
    private readonly ToolManager $toolManager,
    #[Autowire(service: 'cache_tags.invalidator')]
    private readonly CacheTagsInvalidatorInterface $cacheTagsInvalidator,
  ) {
    parent::__construct();
  }

  /**
   * Register all MCP Sentinel tools with mcp_server.
   *
   * Creates or updates one mcp_tool_config entity per available MCP Sentinel
   * Tool plugin. Idempotent — safe to run repeatedly.
   */
  #[CLI\Command(name: 'mcp-sentinel:setup', aliases: ['mcps:setup'])]
  #[CLI\Option(name: 'require-oauth', description: 'Require OAuth2 (authentication_mode=required) for the registered tools. No effect unless mcp_server_oauth is enabled.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:setup', description: 'Register MCP Sentinel tools (OAuth left disabled).')]
  #[CLI\Usage(name: 'drush mcp-sentinel:setup --require-oauth', description: 'Register tools and require OAuth scopes.')]
  public function setup(array $options = ['require-oauth' => FALSE]): int {
    $storage = $this->entityTypeManager->getStorage('mcp_tool_config');
    $oauth_enabled = $this->moduleHandler->moduleExists(self::OAUTH_PROVIDER);
    $mode = !empty($options['require-oauth']) ? 'required' : 'disabled';

    $rows = [];
    foreach (self::TOOLS as $tool_id => $scope) {
      if (!$this->toolManager->hasDefinition($tool_id)) {
        $rows[] = [$tool_id, 'skipped (tool not available)', '—', '—'];
        continue;
      }

      // mcp_tool_config is a config entity provided by the optional
      // mcp_server_tool_bridge module; type to the core interface so static
      // analysis resolves set()/setThirdPartySetting()/save() without a hard
      // dependency on that module's concrete class.
      /** @var \Drupal\Core\Config\Entity\ConfigEntityInterface $entity */
      $entity = $storage->load($tool_id) ?? $storage->create(['id' => $tool_id]);
      $entity->set('tool_id', $tool_id);
      $entity->set('status', TRUE);

      if ($oauth_enabled) {
        $entity->setThirdPartySetting(self::OAUTH_PROVIDER, 'authentication_mode', $mode);
        $entity->setThirdPartySetting(self::OAUTH_PROVIDER, 'scopes', [$scope]);
      }

      $entity->save();
      $rows[] = [
        $tool_id,
        'registered',
        $oauth_enabled ? $mode : 'n/a (oauth off)',
        $oauth_enabled ? $scope : '—',
      ];
    }

    $this->cacheTagsInvalidator->invalidateTags(self::DISCOVERY_TAGS);

    $this->io()->title('MCP Sentinel tool registration');
    $this->io()->table(['Tool', 'Status', 'Auth mode', 'Scope'], $rows);

    if (!$oauth_enabled) {
      $this->logger()->notice('mcp_server_oauth is not enabled — tools registered without OAuth scopes. Enable it and re-run with --require-oauth to enforce.');
    }

    return self::EXIT_SUCCESS;
  }

  /**
   * Remove the mcp_tool_config entities created by mcp-sentinel:setup.
   */
  #[CLI\Command(name: 'mcp-sentinel:teardown', aliases: ['mcps:teardown'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:teardown', description: 'Unregister all MCP Sentinel tools from mcp_server.')]
  public function teardown(): int {
    $storage = $this->entityTypeManager->getStorage('mcp_tool_config');
    $entities = array_filter(array_map(
      static fn(string $id) => $storage->load($id),
      array_keys(self::TOOLS),
    ));

    if (!$entities) {
      $this->logger()->notice('No MCP Sentinel tool registrations found.');
      return self::EXIT_SUCCESS;
    }

    $storage->delete($entities);
    $this->cacheTagsInvalidator->invalidateTags(self::DISCOVERY_TAGS);
    $this->logger()->success(sprintf('Unregistered %d MCP Sentinel tool(s).', count($entities)));
    return self::EXIT_SUCCESS;
  }

}
