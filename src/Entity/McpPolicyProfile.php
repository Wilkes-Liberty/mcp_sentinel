<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * The MCP Sentinel policy profile config entity.
 *
 * Declared as an annotation rather than a #[ConfigEntityType] attribute so the
 * module runs on every core version it claims. Attribute-based entity types
 * arrived in Drupal 11.1: on 10.6 and 11.0, EntityTypeManager uses
 * AnnotatedClassDiscovery and reads annotations only, so an attribute is not
 * ignored gracefully — the entity type simply never exists, and every service
 * touching it fails. From 11.1 discovery is AttributeDiscoveryWithAnnotations,
 * which reads both, so the annotation keeps working there.
 *
 * Revisit when the floor reaches 11.1: annotations are deprecated in Drupal 11
 * and removed in Drupal 12, so this converts back once 10.6/11.0 are out of
 * core_version_requirement — not before.
 *
 * @ConfigEntityType(
 *   id = "mcp_policy_profile",
 *   label = @Translation("MCP policy profile"),
 *   label_collection = @Translation("MCP policy profiles"),
 *   label_singular = @Translation("MCP policy profile"),
 *   label_plural = @Translation("MCP policy profiles"),
 *   config_prefix = "mcp_policy_profile",
 *   admin_permission = "administer mcp sentinel",
 *   entity_keys = {
 *     "id" = "id",
 *     "label" = "label",
 *     "weight" = "weight",
 *     "status" = "status",
 *   },
 *   handlers = {
 *     "list_builder" = "Drupal\mcp_sentinel\McpPolicyProfileListBuilder",
 *     "form" = {
 *       "add" = "Drupal\mcp_sentinel\Form\McpPolicyProfileForm",
 *       "edit" = "Drupal\mcp_sentinel\Form\McpPolicyProfileForm",
 *       "delete" = "Drupal\mcp_sentinel\Form\McpPolicyProfileDeleteForm",
 *     },
 *     "route_provider" = {
 *       "html" = "Drupal\Core\Entity\Routing\AdminHtmlRouteProvider",
 *     },
 *   },
 *   links = {
 *     "collection" = "/admin/config/services/mcp-sentinel/profiles",
 *     "add-form" = "/admin/config/services/mcp-sentinel/profiles/add",
 *     "edit-form" = "/admin/config/services/mcp-sentinel/profiles/{mcp_policy_profile}",
 *     "delete-form" = "/admin/config/services/mcp-sentinel/profiles/{mcp_policy_profile}/delete",
 *   },
 *   config_export = {
 *     "id",
 *     "label",
 *     "weight",
 *     "roles",
 *     "allow_read",
 *     "allow_write",
 *     "allow_delete",
 *     "allow_graphql_mutations",
 *     "allowed_entity_types",
 *     "denied_entity_types",
 *     "redacted_fields",
 *     "rate_limit_requests",
 *     "rate_limit_window",
 *     "result_count_cap",
 *     "response_size_cap",
 *     "allowed_ips",
 *     "allow_config_read",
 *     "allow_config_write",
 *     "denied_config_types",
 *     "deny_publish",
 *     "max_moderation_state",
 *     "deny_external_redirects",
 *     "allowed_redirect_hosts",
 *     "entity_rules",
 *     "forbidden_role_permissions",
 *     "acknowledged_role_permissions",
 *     "allow_raw_sql",
 *     "evidence_required_actions",
 *     "egress_ceilings",
 *   },
 * )
 */
final class McpPolicyProfile extends ConfigEntityBase implements McpPolicyProfileInterface {

  /**
   * Permissions a governed role must not hold, unless acknowledged.
   *
   * Each of these lets its holder act outside the MCP channel, where no policy
   * profile, redaction or audit applies — so holding one makes the profile's
   * guarantees untrue rather than merely weaker. Shipped as the default so an
   * operator inherits the protection without authoring it; the list is
   * per-profile configuration, so a site can extend it with the escape hatches
   * its own contrib modules define.
   */
  public const DEFAULT_FORBIDDEN_ROLE_PERMISSIONS = [
    'bypass file gate',
    'bypass node access',
    'administer users',
    'administer permissions',
    'masquerade as any user',
    'administer site configuration',
  ];

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
   * may carry 'allow_delete', 'allow_write' and/or 'allow_publish' booleans. A
   * present override supersedes the corresponding global flag for that entity
   * type only; an absent override (or absent key) falls back to the global
   * flag. Empty means every type follows the global allow_delete / allow_write
   * / deny_publish flags.
   *
   * Note that 'allow_publish' is stated the positive way round while the global
   * flag it overrides (deny_publish) is negative, so
   * deniesPublishForEntityType() inverts it.
   *
   * @var array<string, array{allow_delete?: bool, allow_write?: bool, allow_publish?: bool}>
   */
  protected array $entity_rules = [];

  /**
   * Permissions the governed role must not hold.
   *
   * Defaults to the shipped list rather than to an empty array: a profile
   * written before this existed, or hand-authored without the key, must
   * inherit the protection instead of asserting nothing.
   *
   * @var string[]
   */
  protected array $forbidden_role_permissions = self::DEFAULT_FORBIDDEN_ROLE_PERMISSIONS;

  /**
   * Deliberate grants, as `role_id:permission` strings.
   *
   * An acknowledgement suppresses one violation for one role. It exists so a
   * considered exception is *recorded in exported configuration* — visible in
   * review and in the config diff — rather than tolerated by deleting the rule
   * that caught it.
   *
   * @var string[]
   */
  protected array $acknowledged_role_permissions = [];

  /**
   * Whether raw SQL is permitted through the governed Drush command.
   *
   * Defaults to FALSE here rather than relying on the config default, so a
   * profile saved before this knob existed — where the key is simply absent —
   * reads as "off" instead of as NULL. Fail closed on the property, not only
   * in the update hook.
   */
  protected bool $allow_raw_sql = FALSE;

  /**
   * Action classes whose execution requires durable keyed evidence.
   *
   * Empty by default and on every profile that predates the knob, so the
   * evidence-required veto is opt-in per profile and an upgrade changes no
   * behavior until an operator marks a class.
   *
   * @var string[]
   */
  protected array $evidence_required_actions = [];

  /**
   * Highest classification label this profile may receive, per surface.
   *
   * Keyed by McpGovernedSurface value. Empty by default and on every profile
   * that predates the knob: an absent surface key is no ceiling, so an
   * upgrade changes no read decision until an operator sets one
   * (d.o #3616540 part 2).
   *
   * @var array<string, string>
   */
  protected array $egress_ceilings = [];

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

  /**
   * {@inheritdoc}
   */
  public function deniesPublishForEntityType(string $entity_type): bool {
    $override = $this->entity_rules[$entity_type]['allow_publish'] ?? NULL;
    return $override === NULL ? $this->deniesPublish() : !(bool) $override;
  }

  /**
   * {@inheritdoc}
   */
  public function getForbiddenRolePermissions(): array {
    return array_values(array_filter($this->forbidden_role_permissions));
  }

  /**
   * {@inheritdoc}
   */
  public function getAcknowledgedRolePermissions(): array {
    return array_values(array_filter($this->acknowledged_role_permissions));
  }

  /**
   * {@inheritdoc}
   */
  public function allowsRawSql(): bool {
    return (bool) $this->allow_raw_sql;
  }

  /**
   * {@inheritdoc}
   */
  public function getEvidenceRequiredActions(): array {
    return array_values(array_filter($this->evidence_required_actions));
  }

  /**
   * {@inheritdoc}
   */
  public function requiresEvidenceFor(string $actionClass): bool {
    return in_array($actionClass, $this->getEvidenceRequiredActions(), TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function getEgressCeilings(): array {
    $ceilings = [];
    foreach ($this->egress_ceilings as $surface => $label) {
      if (is_string($surface) && is_string($label) && $label !== '') {
        $ceilings[$surface] = $label;
      }
    }
    return $ceilings;
  }

  /**
   * {@inheritdoc}
   */
  public function getEgressCeiling(McpGovernedSurface $surface): ?string {
    return $this->getEgressCeilings()[$surface->value] ?? NULL;
  }

}
