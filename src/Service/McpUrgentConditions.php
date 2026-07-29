<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Url;
use Drupal\encrypt\EncryptionProfileInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Evaluates critical/warning/info governance conditions for the dashboard.
 *
 * Pure read; no side effects. Returns a list of
 * `['severity', 'key', 'message', 'url']` entries for:
 *  - chain_broken (critical): the stored last-verify result is FALSE.
 *  - encryption_unresolvable (critical): an audit_encryption_profile is set but
 *    its EncryptionProfile (or its Key) cannot be loaded.
 *  - master_switch_off (warning): governance is OFF yet an agent audit row was
 *    written within the last 24 hours.
 *  - endpoint_key_unresolvable (critical): an enabled webhook endpoint's
 *    secret_key does not resolve via the Key repository.
 *  - role_escape_hatch (critical): a governed role holds a permission its
 *    policy profile forbids, or is an admin role — the profile's guarantees
 *    are not true for that role.
 *  - operator_broadcast (config severity): the dashboard_broadcast message is
 *    non-empty.
 */
final class McpUrgentConditions {

  /**
   * Lookback window (seconds) for "recent" audit rows under master_switch_off.
   */
  private const RECENT_WINDOW = 86400;

  /**
   * Allowed broadcast severities; anything else falls back to 'info'.
   */
  private const BROADCAST_SEVERITIES = ['info', 'warning', 'critical'];

  /**
   * Constructs an McpUrgentConditions service.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\State\StateInterface $state
   *   The state service (stored last-verify result).
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection (recent-audit-row check).
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager (loads the EncryptionProfile entity).
   * @param \Drupal\key\KeyRepositoryInterface $keyRepository
   *   The Key repository (resolves webhook endpoint secret keys).
   * @param \Drupal\mcp_sentinel\Service\McpRoleAssertions $roleAssertions
   *   The role-assertion service (escape-hatch permissions on governed roles).
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StateInterface $state,
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly KeyRepositoryInterface $keyRepository,
    private readonly McpRoleAssertions $roleAssertions,
  ) {}

  /**
   * Evaluates all conditions.
   *
   * @return array<int, array{severity: string, key: string, message: string, url: string|null}>
   *   The fired conditions; an empty array when the site is healthy.
   */
  public function evaluate(): array {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    $conditions = [];

    $this->evaluateChain($conditions);
    $this->evaluateEncryption($config, $conditions);
    $this->evaluateMasterSwitch($config, $conditions);
    $this->evaluateConfigGovernance($config, $conditions);
    $this->evaluateEndpoints($config, $conditions);
    $this->evaluateRoleAssertions($conditions);
    $this->evaluateBroadcast($config, $conditions);

    return $conditions;
  }

  /**
   * Adds role_escape_hatch for each governed role holding a forbidden grant.
   *
   * Critical, not warning: unlike the other conditions here — which say a
   * control is misconfigured — this one says a control that appears configured
   * is not actually a boundary. The profile still reports its deny lists and
   * redactions on the dashboard while the role can step around them entirely.
   *
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateRoleAssertions(array &$conditions): void {
    foreach ($this->roleAssertions->violations() as $violation) {
      $conditions[] = [
        'severity' => 'critical',
        'key' => 'role_escape_hatch',
        'message' => $this->roleAssertions->describe($violation),
        'url' => $this->roleUrl($violation['role']),
      ];
    }
  }

  /**
   * Returns the permission-edit path for a role, or the roles collection.
   *
   * Links straight at the screen where the grant is revoked; falls back to the
   * roles collection when the specific route cannot be built.
   *
   * @param string $roleId
   *   The role ID.
   *
   * @return string|null
   *   An internal path, or NULL when neither route can be built.
   */
  private function roleUrl(string $roleId): ?string {
    try {
      return Url::fromRoute('entity.user_role.edit_permissions_form', ['user_role' => $roleId])->toString();
    }
    catch (\Throwable $e) {
      return $this->routeUrl('entity.user_role.collection');
    }
  }

  /**
   * Asserts config governance is live; never fails open.
   *
   * Config write is "reachable" when at least one enabled policy profile grants
   * allow_config_write. When it is reachable, config governance MUST be live:
   * the master switch on (so checkConfigAccess enforces) and auditing on (the
   * ConfigEvents::SAVE subscriber records every mutation). A critical condition
   * fires when config write is reachable but either guarantee is missing, so
   * status report can never silently imply config governance is active when it
   * is not.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The settings config.
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateConfigGovernance(ImmutableConfig $config, array &$conditions): void {
    if (!$this->configWriteReachable()) {
      return;
    }
    if (!(bool) $config->get('enabled')) {
      $conditions[] = [
        'severity' => 'critical',
        'key' => 'config_governance',
        'message' => 'A policy profile grants configuration write, but MCP Sentinel governance is OFF. Agent configuration changes would be ungoverned.',
        'url' => $this->routeUrl('mcp_sentinel.settings'),
      ];
      return;
    }
    if (!(bool) $config->get('audit_enabled')) {
      $conditions[] = [
        'severity' => 'critical',
        'key' => 'config_governance',
        'message' => 'A policy profile grants configuration write, but audit logging is OFF. Agent configuration changes would not be recorded.',
        'url' => $this->routeUrl('mcp_sentinel.settings'),
      ];
    }
  }

  /**
   * Returns TRUE when any enabled policy profile grants config write.
   *
   * @return bool
   *   TRUE when configuration write is reachable by a governed agent.
   */
  private function configWriteReachable(): bool {
    try {
      $profiles = $this->entityTypeManager
        ->getStorage('mcp_policy_profile')
        ->loadByProperties(['status' => TRUE]);
    }
    catch (\Throwable $e) {
      return FALSE;
    }
    foreach ($profiles as $profile) {
      if ($profile instanceof McpPolicyProfileInterface && $profile->allowsConfigWrite()) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Adds the chain_broken critical condition when the last verify failed.
   *
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateChain(array &$conditions): void {
    $last = $this->state->get('mcp_sentinel.last_verify');
    if (is_array($last) && array_key_exists('ok', $last) && $last['ok'] === FALSE) {
      $brokenAt = isset($last['broken_at']) ? (int) $last['broken_at'] : NULL;
      $conditions[] = [
        'severity' => 'critical',
        'key' => 'chain_broken',
        'message' => $brokenAt !== NULL
          ? sprintf('Audit hash chain integrity check FAILED at row %d. Tampering or data loss is indicated.', $brokenAt)
          : 'Audit hash chain integrity check FAILED. Tampering or data loss is indicated.',
        'url' => $this->routeUrl('mcp_sentinel.audit_log'),
      ];
    }
  }

  /**
   * Adds encryption_unresolvable when a configured profile cannot be loaded.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The settings config.
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateEncryption(ImmutableConfig $config, array &$conditions): void {
    // The chain owns this setting now; reading the stale mcp_sentinel key
    // would report "no encryption configured" on a site that has it enabled.
    $profileId = (string) ($this->configFactory
      ->get('audit_chain.settings')
      ->get('encryption_profile') ?? '');
    if ($profileId === '') {
      return;
    }
    if (!$this->encryptionProfileResolvable($profileId)) {
      $conditions[] = [
        'severity' => 'critical',
        'key' => 'encryption_unresolvable',
        'message' => sprintf("Audit encryption profile '%s' is configured but cannot be resolved. New audit metadata cannot be encrypted and historical rows may be unreadable.", $profileId),
        'url' => $this->routeUrl('mcp_sentinel.settings'),
      ];
    }
  }

  /**
   * Adds master_switch_off when governance is off but recent rows exist.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The settings config.
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateMasterSwitch(ImmutableConfig $config, array &$conditions): void {
    if ((bool) $config->get('enabled')) {
      return;
    }
    $since = $this->time->getRequestTime() - self::RECENT_WINDOW;
    $recent = (int) $this->database->select('audit_chain_log', 'l')
      ->condition('l.channel', McpAuditLogger::READ_CHANNELS, 'IN')
      ->condition('l.timestamp', $since, '>=')
      ->countQuery()
      ->execute()
      ->fetchField();
    if ($recent > 0) {
      $conditions[] = [
        'severity' => 'warning',
        'key' => 'master_switch_off',
        'message' => 'MCP Sentinel governance is OFF, yet agent operations were recorded in the last 24 hours. Traffic is ungoverned.',
        'url' => $this->routeUrl('mcp_sentinel.settings'),
      ];
    }
  }

  /**
   * Adds endpoint_key_unresolvable for each enabled endpoint with a bad key.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The settings config.
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateEndpoints(ImmutableConfig $config, array &$conditions): void {
    foreach ((array) ($config->get('webhook_endpoints') ?? []) as $endpoint) {
      if (!is_array($endpoint) || empty($endpoint['enabled'])) {
        continue;
      }
      $secretKey = (string) ($endpoint['secret_key'] ?? '');
      if ($secretKey === '' || $this->keyRepository->getKey($secretKey) !== NULL) {
        continue;
      }
      $label = (string) ($endpoint['label'] ?? $endpoint['id'] ?? 'unnamed');
      $conditions[] = [
        'severity' => 'critical',
        'key' => 'endpoint_key_unresolvable',
        'message' => sprintf("Webhook endpoint '%s' is enabled but its signing key '%s' cannot be resolved. Deliveries cannot be signed.", $label, $secretKey),
        'url' => $this->routeUrl('mcp_sentinel.settings'),
      ];
    }
  }

  /**
   * Adds the operator broadcast condition when a message is configured.
   *
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The settings config.
   * @param array $conditions
   *   The condition list, modified by reference.
   */
  private function evaluateBroadcast(ImmutableConfig $config, array &$conditions): void {
    $broadcast = (array) ($config->get('dashboard_broadcast') ?? []);
    $message = trim((string) ($broadcast['message'] ?? ''));
    if ($message === '') {
      return;
    }
    $severity = (string) ($broadcast['severity'] ?? 'info');
    if (!in_array($severity, self::BROADCAST_SEVERITIES, TRUE)) {
      $severity = 'info';
    }
    $conditions[] = [
      'severity' => $severity,
      'key' => 'operator_broadcast',
      'message' => $message,
      'url' => NULL,
    ];
  }

  /**
   * Returns whether an EncryptionProfile and its key both resolve.
   *
   * @param string $profileId
   *   The encryption profile entity ID.
   *
   * @return bool
   *   TRUE when the profile loads and its key is resolvable.
   */
  private function encryptionProfileResolvable(string $profileId): bool {
    try {
      $profile = $this->entityTypeManager
        ->getStorage('encryption_profile')
        ->load($profileId);
    }
    catch (\Throwable $e) {
      return FALSE;
    }
    if (!$profile instanceof EncryptionProfileInterface) {
      return FALSE;
    }
    // A profile may load but reference a deleted key; resolve it via the Key
    // repository to confirm the underlying Key entity still exists.
    try {
      $keyId = (string) $profile->getEncryptionKeyId();
    }
    catch (\Throwable $e) {
      return FALSE;
    }
    return $keyId !== '' && $this->keyRepository->getKey($keyId) !== NULL;
  }

  /**
   * Returns the internal path for a route name, or NULL on failure.
   *
   * @param string $routeName
   *   The route machine name.
   *
   * @return string|null
   *   The internal path, or NULL when the route cannot be built.
   */
  private function routeUrl(string $routeName): ?string {
    try {
      return Url::fromRoute($routeName)->toString();
    }
    catch (\Throwable $e) {
      return NULL;
    }
  }

}
