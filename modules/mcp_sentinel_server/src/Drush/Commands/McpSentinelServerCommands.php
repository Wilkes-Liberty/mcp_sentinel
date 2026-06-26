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
    'mcp_sentinel_config_get' => 'mcp_read',
    'mcp_sentinel_config_list' => 'mcp_read',
    'mcp_sentinel_config_set' => 'mcp_write',
    // Registered only when the mcp_sentinel_graphql submodule is enabled.
    'mcp_sentinel_graphql_schema' => 'mcp_read',
  ];

  /**
   * Cache tags to invalidate so mcp_server re-discovers the registered tools.
   */
  private const DISCOVERY_TAGS = ['mcp_server:discovery', 'mcp_server:tools'];

  /**
   * Agent tiers: tier name => [role id, [oauth2 scope ids]].
   *
   * The single source of truth for what each environment provisions. Keeping it
   * here means the connector config, Keychain item, and consumer all derive
   * one definition and cannot drift (the recurring §6 break in the governance
   * design). Roles/scopes themselves are shipped by the site (e.g. webcms
   * config/sync); this command binds an agent account + consumer to them.
   */
  private const TIERS = [
    'content' => ['mcp_content_editor', ['mcp_read', 'mcp_write']],
    'developer' => ['mcp_config_editor', ['mcp_read', 'mcp_write', 'mcp_config']],
    'admin' => ['mcp_admin', ['mcp_read', 'mcp_write', 'mcp_config', 'mcp_admin']],
  ];

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
   * Idempotently provision an agent tier's role, account, and consumer.
   *
   * One source of truth for a tier's identity so the connector config, Keychain
   * item, and consumer can't drift. Ensures the tier role exists, a dedicated
   * agent user account holds it, and an OAuth consumer with a deterministic
   * client_id (<tier>-<env>) is bound to that account and the tier's scopes.
   *
   * Secrets are never created or rotated here — that remains a human action.
   * The command prints the client_id so the operator can wire the connector and
   * set the consumer secret out of band.
   *
   * @param string $tier
   *   The tier to provision: content, developer, or admin.
   * @param array $options
   *   The command options.
   */
  #[CLI\Command(name: 'mcp-sentinel:agent-provision', aliases: ['mcps:provision'])]
  #[CLI\Argument(name: 'tier', description: 'Tier to provision: content, developer, or admin.')]
  #[CLI\Option(name: 'env', description: 'Environment label used to build the consumer client_id (<tier>-<env>).')]
  #[CLI\Usage(name: 'drush mcp-sentinel:agent-provision content --env=prod', description: 'Provision the content tier consumer for prod.')]
  public function agentProvision(string $tier, array $options = ['env' => 'dev']): int {
    if (!isset(self::TIERS[$tier])) {
      $this->logger()->error(sprintf('Unknown tier "%s". Valid tiers: %s.', $tier, implode(', ', array_keys(self::TIERS))));
      return self::EXIT_FAILURE;
    }
    if (!$this->moduleHandler->moduleExists('consumers') || !$this->moduleHandler->moduleExists('simple_oauth')) {
      $this->logger()->error('The consumers and simple_oauth modules must be enabled to provision an agent consumer.');
      return self::EXIT_FAILURE;
    }

    [$roleId, $scopeIds] = self::TIERS[$tier];
    $env = preg_replace('/[^a-z0-9_-]/', '', strtolower((string) ($options['env'] ?? 'dev'))) ?: 'dev';
    $clientId = $tier . '-' . $env;
    $rows = [];

    // 1. Role — create an empty role if the site has not shipped it yet. An
    //    existing role's permissions are left untouched.
    $roleStorage = $this->entityTypeManager->getStorage('user_role');
    $role = $roleStorage->load($roleId);
    if ($role === NULL) {
      $role = $roleStorage->create(['id' => $roleId, 'label' => 'MCP agent: ' . $tier]);
      $role->save();
      $rows[] = ['role', $roleId, 'created (no permissions — grant via config)'];
    }
    else {
      $rows[] = ['role', $roleId, 'present'];
    }

    // 2. Agent user account holding the tier role.
    $userStorage = $this->entityTypeManager->getStorage('user');
    $accountName = 'mcp-agent-' . $tier;
    $existing = $userStorage->loadByProperties(['name' => $accountName]);
    $account = $existing ? reset($existing) : NULL;
    if ($account === NULL) {
      $account = $userStorage->create([
        'name' => $accountName,
        'status' => 1,
      ]);
      $account->addRole($roleId);
      $account->save();
      $rows[] = ['user', $accountName, 'created'];
    }
    else {
      if (!$account->hasRole($roleId)) {
        $account->addRole($roleId);
        $account->save();
      }
      $rows[] = ['user', $accountName, 'present (role ensured)'];
    }

    // 3. Consumer with deterministic client_id, owner = agent account, scopes.
    $scopeStorage = $this->entityTypeManager->getStorage('oauth2_scope');
    $presentScopes = array_values(array_filter(
      $scopeIds,
      static fn (string $id): bool => $scopeStorage->load($id) !== NULL,
    ));
    $missing = array_diff($scopeIds, $presentScopes);

    $consumerStorage = $this->entityTypeManager->getStorage('consumer');
    $found = $consumerStorage->loadByProperties(['client_id' => $clientId]);
    /** @var \Drupal\Core\Entity\ContentEntityInterface $consumer */
    $consumer = $found ? reset($found) : $consumerStorage->create([
      'client_id' => $clientId,
      'label' => 'MCP agent (' . $tier . ' / ' . $env . ')',
      'is_default' => FALSE,
    ]);
    $consumer->set('owner_id', $account->id());
    if ($consumer->hasField('scopes')) {
      $consumer->set('scopes', array_map(
        static fn (string $id): array => ['scope_id' => $id],
        $presentScopes,
      ));
    }
    $consumer->save();
    $rows[] = ['consumer', $clientId, $found ? 'updated' : 'created'];

    $this->io()->title(sprintf('MCP Sentinel agent provisioning — %s tier (%s)', $tier, $env));
    $this->io()->table(['Kind', 'Id', 'Status'], $rows);
    $this->io()->writeln(sprintf('Consumer client_id: <info>%s</info>', $clientId));
    if ($missing) {
      $this->logger()->warning(sprintf('Scopes not found and skipped (ship them in config): %s', implode(', ', $missing)));
    }
    $this->logger()->notice('Set the consumer secret out of band (human action); this command never creates or rotates secrets.');

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
