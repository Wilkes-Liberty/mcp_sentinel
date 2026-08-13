<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_server\Drush\Commands;

use Drupal\Core\Cache\CacheTagsInvalidatorInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\Entity\ConfigEntityInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Tool\ConfigScopeToolInterface;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\mcp_sentinel_server\ToolScopeResolver;
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
   * MCP Sentinel tools to register with mcp_server, as Tool API plugin ids.
   *
   * This is the explicit allow-list of tools the setup command registers. The
   * OAuth scope each tool requires is NOT stored here — it is derived from the
   * plugin's own declarations (its ToolOperation and whether it implements
   * ConfigScopeToolInterface) by scopeForTool(), so the plugin is the single
   * source of truth for its scope and cannot drift from a parallel table.
   */
  private const TOOLS = [
    'mcp_sentinel_site_context',
    'mcp_sentinel_security_policy',
    'mcp_sentinel_content_lock',
    'mcp_sentinel_node_operations',
    'mcp_sentinel_media_create',
    'mcp_sentinel_workflow_transition',
    'mcp_sentinel_bulk_operations',
    // Config tools derive to the config scope family (config_get/list =>
    // mcp_config_read, config_set => mcp_config), so a content-tier token
    // (mcp_read/mcp_write only) can never read or write configuration.
    'mcp_sentinel_config_get',
    'mcp_sentinel_config_list',
    'mcp_sentinel_config_set',
    // Registered only when the mcp_sentinel_graphql submodule is enabled.
    'mcp_sentinel_graphql_schema',
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
    // Read-only content auditor: content reads only, no writes. Carries the
    // content-editor role (so it resolves to the content policy) but only the
    // mcp_read scope, so every write tool is unreachable at the scope layer.
    // Pair with the connector's "auditor" preset for reports and content
    // audits.
    'content-auditor' => ['mcp_content_editor', ['mcp_read']],
    // Read-only config auditor: config read only, no writes. Reads config for
    // governance/audits (config_get/list require mcp_config_read) while the
    // policy profile denies every write. Deliberately config-scoped (no
    // mcp_read) so it resolves unambiguously to the config_auditor profile.
    'auditor' => ['mcp_config_auditor', ['mcp_config_read']],
    // Developer/admin carry mcp_config_read too, since config_get/list moved to
    // the read scope; mcp_config remains their config *write* capability.
    'developer' => ['mcp_config_editor', ['mcp_read', 'mcp_write', 'mcp_config', 'mcp_config_read']],
    'admin' => ['mcp_admin', ['mcp_read', 'mcp_write', 'mcp_config', 'mcp_config_read', 'mcp_admin']],
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
    private readonly ConfigFactoryInterface $configFactory,
  ) {
    parent::__construct();
  }

  /**
   * Derives the OAuth scope a registered tool requires.
   *
   * The scope is computed from the tool plugin's own declarations — its
   * ToolOperation (read vs modifying) and whether it implements
   * ConfigScopeToolInterface (config vs content domain) — so the plugin is the
   * single source of truth for its scope rather than a hand-maintained table.
   *
   * @param string $toolId
   *   The Tool API plugin id.
   *
   * @return string|null
   *   The OAuth scope machine id, or NULL when the tool is not available.
   */
  public function scopeForTool(string $toolId): ?string {
    if (!$this->toolManager->hasDefinition($toolId)) {
      return NULL;
    }
    $definition = $this->toolManager->getDefinition($toolId);
    $isConfigDomain = is_a($definition->getClass(), ConfigScopeToolInterface::class, TRUE);
    return ToolScopeResolver::resolve($definition->getOperation(), $isConfigDomain);
  }

  /**
   * Register all MCP Sentinel tools with mcp_server.
   *
   * Creates or updates one mcp_tool_config entity per available MCP Sentinel
   * Tool plugin. Idempotent — safe to run repeatedly.
   */
  #[CLI\Command(name: 'mcp-sentinel:setup', aliases: ['mcps:setup'])]
  #[CLI\Option(name: 'allow-unauthenticated-development', description: 'Development only: register tools without required OAuth. The command exits nonzero and production readiness remains false.')]
  #[CLI\Option(name: 'require-oauth', description: 'Deprecated compatibility flag. OAuth is required by default.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:setup', description: 'Register every Sentinel tool with required OAuth and exact derived scope.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:setup --allow-unauthenticated-development', description: 'Explicitly create a development-only, not-ready registration.')]
  public function setup(
    array $options = [
      'allow-unauthenticated-development' => FALSE,
      'require-oauth' => FALSE,
    ],
  ): int {
    $development = !empty($options['allow-unauthenticated-development']);
    if (!$this->moduleHandler->moduleExists('mcp_server_tool_bridge')) {
      $this->logger()?->error('mcp_server_tool_bridge must be enabled before Sentinel tools can be registered.');
      return self::EXIT_FAILURE;
    }
    $oauthEnabled = $this->moduleHandler->moduleExists(self::OAUTH_PROVIDER);
    if (!$development && !$oauthEnabled) {
      $this->logger()?->error('mcp_server_oauth is required for production Sentinel tool registration.');
      return self::EXIT_FAILURE;
    }

    $storage = $this->entityTypeManager->getStorage('mcp_tool_config');
    $mode = $development ? 'disabled' : 'required';
    $configuredScopes = (array) ($this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('agent_scopes') ?? []);

    $toolIds = McpToolScopeResolver::REQUIRED_TOOLS;
    foreach (McpToolScopeResolver::OPTIONAL_TOOLS as $toolId) {
      if ($this->toolManager->hasDefinition($toolId)) {
        $toolIds[] = $toolId;
      }
    }

    $rows = [];
    $planned = [];
    foreach ($toolIds as $toolId) {
      $scope = $this->scopeForTool($toolId);
      if ($scope === NULL) {
        $this->logger()?->error(sprintf('Required Sentinel tool "%s" is not available; no registrations were changed.', $toolId));
        return self::EXIT_FAILURE;
      }
      if (!$development && !in_array($scope, $configuredScopes, TRUE)) {
        $this->logger()?->error(sprintf('Required OAuth scope "%s" for tool "%s" is absent from mcp_sentinel.settings:agent_scopes.', $scope, $toolId));
        return self::EXIT_FAILURE;
      }

      // mcp_tool_config is a config entity provided by the optional
      // mcp_server_tool_bridge module; type to the core interface so static
      // analysis resolves set()/setThirdPartySetting()/save() without a hard
      // dependency on that module's concrete class.
      $loaded = $storage->load($toolId);
      $original = $loaded instanceof ConfigEntityInterface
        ? clone $loaded
        : NULL;
      $entity = $loaded instanceof ConfigEntityInterface
        ? $loaded
        : $storage->create(['id' => $toolId]);
      if (!$entity instanceof ConfigEntityInterface) {
        $this->logger()?->error(sprintf('Tool registration storage returned an invalid entity for "%s"; no registrations were changed.', $toolId));
        return self::EXIT_FAILURE;
      }
      $entity->set('tool_id', $toolId);
      $entity->set('status', TRUE);

      if ($oauthEnabled) {
        $entity->setThirdPartySetting(self::OAUTH_PROVIDER, 'authentication_mode', $mode);
        $entity->setThirdPartySetting(self::OAUTH_PROVIDER, 'scopes', [$scope]);
      }
      $planned[] = ['entity' => $entity, 'original' => $original];
    }

    $saved = [];
    try {
      foreach ($planned as $item) {
        $saved[] = $item;
        $item['entity']->save();
        $rows[] = [
          $item['entity']->id(),
          'registered',
          $oauthEnabled ? $mode : 'development only',
          $oauthEnabled ? $item['entity']->getThirdPartySetting(self::OAUTH_PROVIDER, 'scopes')[0] : '—',
        ];
      }
    }
    catch (\Throwable $exception) {
      $this->rollbackEntities($saved);
      $this->logger()?->error('Sentinel tool registration failed; every partial registration was rolled back.');
      return self::EXIT_FAILURE;
    }

    $this->cacheTagsInvalidator->invalidateTags(self::DISCOVERY_TAGS);

    $this->io()->title('MCP Sentinel tool registration');
    $this->io()->table(['Tool', 'Status', 'Auth mode', 'Scope'], $rows);

    if ($development) {
      $this->logger()?->warning('Development-only unauthenticated registration is active. Production contract_ready remains false.');
      return self::EXIT_FAILURE_WITH_CLARITY;
    }

    $designated = array_filter((array) ($this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('agent_oauth_clients') ?? []));
    if ($designated === []) {
      $this->logger()?->warning('Tool registration succeeded, but no designated Consumer is configured. Production contract_ready remains false until agent-provision completes.');
      return self::EXIT_FAILURE_WITH_CLARITY;
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
   *   The tier to provision: content, content-auditor, auditor, developer, or
   *   admin.
   * @param array $options
   *   The command options.
   */
  #[CLI\Command(name: 'mcp-sentinel:agent-provision', aliases: ['mcps:provision'])]
  #[CLI\Argument(name: 'tier', description: 'Tier to provision: content, content-auditor, auditor, developer, or admin.')]
  #[CLI\Option(name: 'env', description: 'Environment label used to build the consumer client_id (<tier>-<env>).')]
  #[CLI\Usage(name: 'drush mcp-sentinel:agent-provision content --env=prod', description: 'Provision the content tier consumer for prod.')]
  public function agentProvision(string $tier, array $options = ['env' => 'dev']): int {
    if (!isset(self::TIERS[$tier])) {
      $this->logger()?->error(sprintf('Unknown tier "%s". Valid tiers: %s.', $tier, implode(', ', array_keys(self::TIERS))));
      return self::EXIT_FAILURE;
    }
    if (!$this->moduleHandler->moduleExists('consumers') || !$this->moduleHandler->moduleExists('simple_oauth')) {
      $this->logger()?->error('The consumers and simple_oauth modules must be enabled to provision an agent consumer.');
      return self::EXIT_FAILURE;
    }

    [$roleId, $scopeIds] = self::TIERS[$tier];
    $env = preg_replace('/[^a-z0-9_-]/', '', strtolower((string) ($options['env'] ?? 'dev'))) ?: 'dev';
    $clientId = $tier . '-' . $env;
    $rows = [];

    // Preflight every immutable prerequisite before changing role, account,
    // Consumer, or designation config. Missing scopes are a hard failure, not
    // a warning followed by a weaker token.
    $scopeStorage = $this->entityTypeManager->getStorage('oauth2_scope');
    $missingScopes = array_values(array_filter(
      $scopeIds,
      static fn (string $id): bool => $scopeStorage->load($id) === NULL,
    ));
    if ($missingScopes !== []) {
      $this->logger()?->error(sprintf('Required scopes are missing; nothing was changed: %s.', implode(', ', $missingScopes)));
      return self::EXIT_FAILURE;
    }

    $profiles = $this->entityTypeManager
      ->getStorage('mcp_policy_profile')
      ->loadMultiple();
    $applicableProfile = FALSE;
    foreach ($profiles as $profile) {
      if ($profile instanceof McpPolicyProfileInterface
        && $profile->status()
        && in_array($roleId, $profile->getRoles(), TRUE)) {
        $applicableProfile = TRUE;
        break;
      }
    }
    if (!$applicableProfile) {
      $this->logger()?->error(sprintf('No enabled MCP policy profile applies to role "%s"; nothing was changed.', $roleId));
      return self::EXIT_FAILURE;
    }

    $snapshots = [];
    $settings = $this->configFactory->getEditable('mcp_sentinel.settings');
    $originalClientIds = (array) ($settings->get('agent_oauth_clients') ?? []);

    try {

      // 1. Role — create an empty role if the site has not shipped it yet. An
      //    existing role's permissions are left untouched.
      $roleStorage = $this->entityTypeManager->getStorage('user_role');
      $role = $roleStorage->load($roleId);
      if ($role === NULL) {
        $role = $roleStorage->create(['id' => $roleId, 'label' => 'MCP agent: ' . $tier]);
        $snapshots[] = ['entity' => $role, 'original' => NULL];
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
        $snapshots[] = ['entity' => $account, 'original' => NULL];
        $account->save();
        $rows[] = ['user', $accountName, 'created'];
      }
      else {
        if (!$account->isActive()) {
          throw new \RuntimeException('The existing tier account is blocked; provisioning will not silently reactivate it.');
        }
        if (!$account->hasRole($roleId)) {
          $snapshots[] = ['entity' => $account, 'original' => clone $account];
          $account->addRole($roleId);
          $account->save();
        }
        $rows[] = ['user', $accountName, 'present (role ensured)'];
      }

      // 3. Consumer with deterministic client_id, owner = agent account, and
      // scopes.
      $consumerStorage = $this->entityTypeManager->getStorage('consumer');
      $found = $consumerStorage->loadByProperties(['client_id' => $clientId]);
      /** @var \Drupal\Core\Entity\ContentEntityInterface $consumer */
      $consumer = $found ? reset($found) : $consumerStorage->create([
        'client_id' => $clientId,
        'label' => 'MCP agent (' . $tier . ' / ' . $env . ')',
        'is_default' => FALSE,
      ]);
      $snapshots[] = [
        'entity' => $consumer,
        'original' => $found ? clone $consumer : NULL,
      ];
      $consumer->set('owner_id', $account->id());
      $consumer->set('status', 1);
      if ($consumer->hasField('scopes')) {
        $consumer->set('scopes', array_map(
          static fn (string $id): array => ['scope_id' => $id],
          $scopeIds,
        ));
      }
      $consumer->save();
      $rows[] = ['consumer', $clientId, $found ? 'updated' : 'created'];

      // Designation is the final write. If it fails, role/account/Consumer
      // state is restored; the site cannot retain a half-provisioned identity.
      $settings->set('agent_oauth_clients', array_values(array_unique([
        ...$originalClientIds,
        $clientId,
      ])))->save();
    }
    catch (\Throwable $exception) {
      $this->rollbackEntities($snapshots);
      try {
        $settings->set('agent_oauth_clients', $originalClientIds)->save();
      }
      catch (\Throwable) {
        $this->logger()?->critical('Provisioning rollback could not restore designation config; inspect mcp_sentinel.settings immediately.');
      }
      $this->logger()?->error('Agent provisioning failed; partial identity and designation writes were rolled back.');
      return self::EXIT_FAILURE;
    }

    $this->io()->title(sprintf('MCP Sentinel agent provisioning — %s tier (%s)', $tier, $env));
    $this->io()->table(['Kind', 'Id', 'Status'], $rows);
    $this->io()->writeln(sprintf('Consumer client_id: <info>%s</info>', $clientId));
    $this->logger()?->notice('Set the consumer secret out of band (human action); this command never creates or rotates secrets.');

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
      self::TOOLS,
    ));

    if (!$entities) {
      $this->logger()?->notice('No MCP Sentinel tool registrations found.');
      return self::EXIT_SUCCESS;
    }

    $storage->delete($entities);
    $this->cacheTagsInvalidator->invalidateTags(self::DISCOVERY_TAGS);
    $this->logger()?->success(sprintf('Unregistered %d MCP Sentinel tool(s).', count($entities)));
    return self::EXIT_SUCCESS;
  }

  /**
   * Restores entity snapshots in reverse write order.
   *
   * @param array<int, array{entity: \Drupal\Core\Entity\EntityInterface, original: \Drupal\Core\Entity\EntityInterface|null}> $snapshots
   *   Saved entities and their pre-write state; NULL denotes a new entity.
   */
  private function rollbackEntities(array $snapshots): void {
    foreach (array_reverse($snapshots) as $snapshot) {
      try {
        if ($snapshot['original'] instanceof EntityInterface) {
          $snapshot['original']->save();
        }
        else {
          $snapshot['entity']->delete();
        }
      }
      catch (\Throwable) {
        $this->logger()?->critical('An entity rollback step failed; inspect the Sentinel provisioning state immediately.');
      }
    }
  }

}
