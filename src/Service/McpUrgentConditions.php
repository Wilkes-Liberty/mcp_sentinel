<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\State\StateInterface;
use Drupal\Core\Url;
use Drupal\encrypt\EncryptionProfileInterface;
use Drupal\key\KeyRepositoryInterface;

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
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StateInterface $state,
    private readonly Connection $database,
    private readonly TimeInterface $time,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly KeyRepositoryInterface $keyRepository,
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
    $this->evaluateEndpoints($config, $conditions);
    $this->evaluateBroadcast($config, $conditions);

    return $conditions;
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
  private function evaluateEncryption(object $config, array &$conditions): void {
    $profileId = (string) ($config->get('audit_encryption_profile') ?? '');
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
  private function evaluateMasterSwitch(object $config, array &$conditions): void {
    if ((bool) $config->get('enabled')) {
      return;
    }
    $since = $this->time->getRequestTime() - self::RECENT_WINDOW;
    $recent = (int) $this->database->select('mcp_sentinel_audit_log', 'l')
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
  private function evaluateEndpoints(object $config, array &$conditions): void {
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
  private function evaluateBroadcast(object $config, array &$conditions): void {
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
