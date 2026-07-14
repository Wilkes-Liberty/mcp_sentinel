<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Entity\Attribute\ConfigEntityType;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Form\McpPolicyProfileDeleteForm;
use Drupal\mcp_sentinel\Form\McpPolicyProfileForm;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\McpPolicyProfileListBuilder;

/**
 * The MCP Sentinel policy profile config entity.
 */
#[ConfigEntityType(
  id: 'mcp_policy_profile',
  label: new TranslatableMarkup('MCP policy profile'),
  label_collection: new TranslatableMarkup('MCP policy profiles'),
  label_singular: new TranslatableMarkup('MCP policy profile'),
  label_plural: new TranslatableMarkup('MCP policy profiles'),
  config_prefix: 'mcp_policy_profile',
  admin_permission: 'administer mcp sentinel',
  entity_keys: [
    'id' => 'id',
    'label' => 'label',
    'weight' => 'weight',
    'status' => 'status',
  ],
  handlers: [
    'list_builder' => McpPolicyProfileListBuilder::class,
    'form' => [
      'add' => McpPolicyProfileForm::class,
      'edit' => McpPolicyProfileForm::class,
      'delete' => McpPolicyProfileDeleteForm::class,
    ],
    'route_provider' => [
      'html' => 'Drupal\Core\Entity\Routing\AdminHtmlRouteProvider',
    ],
  ],
  links: [
    'collection' => '/admin/config/services/mcp-sentinel/profiles',
    'add-form' => '/admin/config/services/mcp-sentinel/profiles/add',
    'edit-form' => '/admin/config/services/mcp-sentinel/profiles/{mcp_policy_profile}',
    'delete-form' => '/admin/config/services/mcp-sentinel/profiles/{mcp_policy_profile}/delete',
  ],
  config_export: [
    'id',
    'label',
    'weight',
    'roles',
    'allow_read',
    'allow_write',
    'allow_delete',
    'allow_graphql_mutations',
    'allowed_entity_types',
    'denied_entity_types',
    'redacted_fields',
    'rate_limit_requests',
    'rate_limit_window',
    'result_count_cap',
    'response_size_cap',
    'allowed_ips',
    'allow_config_read',
    'allow_config_write',
    'denied_config_types',
    'deny_publish',
    'max_moderation_state',
    'deny_external_redirects',
    'allowed_redirect_hosts',
    'entity_rules',
  ],
)]
final class McpPolicyProfile extends ConfigEntityBase implements McpPolicyProfileInterface {

  /**
   * The machine name.
   */
  protected string $id;

  /**
   * The human-readable label.
   */
  protected string $label;

  /**
   * Resolution weight; higher wins when several profiles match.
   */
  protected int $weight = 0;

  /**
   * Role IDs this profile applies to.
   *
   * @var string[]
   */
  protected array $roles = [];

  /**
   * Whether read operations are permitted.
   */
  protected bool $allow_read = TRUE;

  /**
   * Whether write (create/update) operations are permitted.
   */
  protected bool $allow_write = FALSE;

  /**
   * Whether delete operations are permitted.
   */
  protected bool $allow_delete = FALSE;

  /**
   * Whether GraphQL mutations are permitted.
   */
  protected bool $allow_graphql_mutations = FALSE;

  /**
   * Allowed entity type IDs (empty = all allowed).
   *
   * @var string[]
   */
  protected array $allowed_entity_types = [];

  /**
   * Denied entity type IDs.
   *
   * @var string[]
   */
  protected array $denied_entity_types = [];

  /**
   * Field machine names redacted from MCP responses.
   *
   * @var string[]
   */
  protected array $redacted_fields = [];

  /**
   * Maximum requests per rate-limit window (0 = unlimited).
   */
  protected int $rate_limit_requests = 0;

  /**
   * Rate-limit window duration in seconds.
   */
  protected int $rate_limit_window = 60;

  /**
   * Maximum result items returned per tool/API call (0 = unlimited).
   */
  protected int $result_count_cap = 0;

  /**
   * Maximum response size in bytes (0 = unlimited).
   */
  protected int $response_size_cap = 0;

  /**
   * Allowed client IP addresses and CIDR ranges (empty = all IPs allowed).
   *
   * @var string[]
   */
  protected array $allowed_ips = [];

  /**
   * Whether configuration read operations are permitted.
   */
  protected bool $allow_config_read = FALSE;

  /**
   * Whether configuration write operations are permitted.
   */
  protected bool $allow_config_write = FALSE;

  /**
   * Config name prefixes denied for read and write (deny always wins).
   *
   * @var string[]
   */
  protected array $denied_config_types = [];

  /**
   * Whether the agent is forbidden from publishing content.
   *
   * When TRUE (the safe default), agent-authored content is forced to a
   * non-published state: moderated transitions to a published state are denied
   * and unmoderated publishable entities are saved unpublished. A human
   * publisher remains responsible for publishing.
   */
  protected bool $deny_publish = TRUE;

  /**
   * Highest moderation state the agent may set (empty = unrestricted).
   *
   * The state ID of the ceiling state; transitions to a higher-weight state in
   * the entity's workflow are denied. Empty applies no ceiling.
   */
  protected string $max_moderation_state = '';

  /**
   * Whether the agent is forbidden from creating off-domain redirects.
   *
   * When TRUE (the safe default), a governed agent may not create or update a
   * redirect whose destination is an external URL pointing at a host outside
   * the allowlist — an open-redirect / phishing guard. Internal, entity:,
   * base:, and relative targets are always permitted. Existing profiles saved
   * before this knob existed carry no value; the getter defaults to TRUE so the
   * gate is on by default.
   */
  protected bool $deny_external_redirects = TRUE;

  /**
   * Hostnames a governed agent may target with an external redirect.
   *
   * An allowlist of bare hostnames (e.g. docs.example.com). Empty means the
   * site's own host(s) — derived from the request host and the
   * trusted_host_patterns setting — are the implicit allowlist.
   *
   * @var string[]
   */
  protected array $allowed_redirect_hosts = [];

  /**
   * Per-entity-type destructive overrides.
   *
   * A map of entity_type ID => rule, where a rule is an associative array that
   * may carry 'allow_delete' and/or 'allow_write' booleans. A present override
   * supersedes the corresponding global flag for that entity type only; an
   * absent override (or absent key) falls back to the global flag. Empty means
   * every type follows the global allow_delete / allow_write flags.
   *
   * @var array<string, array{allow_delete?: bool, allow_write?: bool}>
   */
  protected array $entity_rules = [];

  /**
   * {@inheritdoc}
   */
  public function getRoles(): array {
    return array_values($this->roles);
  }

  /**
   * {@inheritdoc}
   */
  public function getWeight(): int {
    return (int) $this->weight;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsRead(): bool {
    return (bool) $this->allow_read;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsWrite(): bool {
    return (bool) $this->allow_write;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsDelete(): bool {
    return (bool) $this->allow_delete;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsGraphqlMutations(): bool {
    return (bool) $this->allow_graphql_mutations;
  }

  /**
   * {@inheritdoc}
   */
  public function getAllowedEntityTypes(): array {
    return array_values(array_filter($this->allowed_entity_types));
  }

  /**
   * {@inheritdoc}
   */
  public function getDeniedEntityTypes(): array {
    return array_values(array_filter($this->denied_entity_types));
  }

  /**
   * {@inheritdoc}
   */
  public function getRedactedFields(): array {
    return array_values(array_filter($this->redacted_fields));
  }

  /**
   * {@inheritdoc}
   */
  public function getRateLimitRequests(): int {
    return (int) $this->rate_limit_requests;
  }

  /**
   * {@inheritdoc}
   */
  public function getRateLimitWindow(): int {
    return (int) $this->rate_limit_window;
  }

  /**
   * {@inheritdoc}
   */
  public function getResultCountCap(): int {
    return (int) $this->result_count_cap;
  }

  /**
   * {@inheritdoc}
   */
  public function getResponseSizeCap(): int {
    return (int) $this->response_size_cap;
  }

  /**
   * {@inheritdoc}
   */
  public function getAllowedIps(): array {
    return array_values(array_filter($this->allowed_ips));
  }

  /**
   * {@inheritdoc}
   */
  public function allowsConfigRead(): bool {
    return (bool) $this->allow_config_read;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsConfigWrite(): bool {
    return (bool) $this->allow_config_write;
  }

  /**
   * {@inheritdoc}
   */
  public function getDeniedConfigTypes(): array {
    return array_values(array_filter($this->denied_config_types));
  }

  /**
   * {@inheritdoc}
   */
  public function deniesPublish(): bool {
    return (bool) $this->deny_publish;
  }

  /**
   * {@inheritdoc}
   */
  public function getMaxModerationState(): string {
    return (string) $this->max_moderation_state;
  }

  /**
   * {@inheritdoc}
   */
  public function deniesExternalRedirects(): bool {
    return (bool) $this->deny_external_redirects;
  }

  /**
   * {@inheritdoc}
   */
  public function getAllowedRedirectHosts(): array {
    return array_values(array_filter($this->allowed_redirect_hosts));
  }

  /**
   * {@inheritdoc}
   */
  public function getEntityRules(): array {
    return $this->entity_rules;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsDeleteForEntityType(string $entity_type): bool {
    $override = $this->entity_rules[$entity_type]['allow_delete'] ?? NULL;
    return $override === NULL ? $this->allowsDelete() : (bool) $override;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsWriteForEntityType(string $entity_type): bool {
    $override = $this->entity_rules[$entity_type]['allow_write'] ?? NULL;
    return $override === NULL ? $this->allowsWrite() : (bool) $override;
  }

}
