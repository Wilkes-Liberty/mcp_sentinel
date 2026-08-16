<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\EventSubscriber;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\Config\ConfigException;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\StorageInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel_approval\Entity\McpAdminGrantInterface;
use Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Audits config changes made while a break-glass grant is active.
 *
 * Break-glass proves who held mcp_admin and for how long. Without this
 * subscriber, nothing they change while elevated is recorded: cookie-session
 * humans are never "governed", so McpConfigSaveSubscriber::onConfigSave()
 * early-returns. That silence is the gap — especially for audit_enabled and
 * enabled, which are self-concealing when flipped off.
 *
 * Lives in the approval submodule (not the parent) so the parent stays free of
 * a hard dependency on break-glass. Scope is deliberately all config while
 * elevated: the grant is time-boxed and rare, so volume is bounded, and an
 * exhaustive record cannot be gamed by moving a change to an unexpected object.
 *
 * Fail closed: if the audit write throws, the just-written config is reverted
 * (same post-SAVE revert pattern as the parent's denylist). That asymmetry
 * with onRoleSave (fail open) is deliberate — an active grant cannot exist
 * mid-install, and a privileged change through unrecorded is worse than a
 * refused save.
 *
 * @see \Drupal\mcp_sentinel\EventSubscriber\McpConfigSaveSubscriber
 */
final class McpBreakGlassConductSubscriber implements EventSubscriberInterface {

  /**
   * Constructs a McpBreakGlassConductSubscriber.
   *
   * The break-glass manager is resolved from the container at event time, not
   * constructor-injected. Kernel tests freeze datetime.time and rebind the
   * manager after boot; a constructor reference would keep the pre-mock clock
   * and make TTL/reaper tests silently wrong. Looking the service up per event
   * always sees the live container binding.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   The policy resolver (skip when already governed — parent audits that).
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger (logAlways so audit_enabled:false is itself recorded).
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory (reset after revert).
   * @param \Drupal\Core\Config\StorageInterface $configStorage
   *   Active config storage for post-SAVE revert without re-dispatch.
   * @param \Symfony\Component\DependencyInjection\ContainerInterface $container
   *   The container, used to resolve the break-glass manager at event time.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpAuditLogger $auditLogger,
    private readonly AccountProxyInterface $currentUser,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StorageInterface $configStorage,
    private readonly ContainerInterface $container,
  ) {}

  /**
   * Config object that holds break-glass TTL and related control settings.
   */
  private const SETTINGS_NAME = 'mcp_sentinel_approval.settings';

  /**
   * Prefix of policy-profile config objects.
   */
  private const POLICY_PREFIX = 'mcp_sentinel.mcp_policy_profile.';

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      ConfigEvents::SAVE => ['onConfigSave', -20],
      ConfigEvents::DELETE => ['onConfigDelete', -20],
    ];
  }

  /**
   * Records a config_save_break_glass audit row when elevation is live.
   *
   * @param \Drupal\Core\Config\ConfigCrudEvent $event
   *   The config CRUD event.
   *
   * @throws \Drupal\Core\Config\ConfigException
   *   When the audit write fails (after reverting the save).
   */
  public function onConfigSave(ConfigCrudEvent $event): void {
    // Parent already audits governed agent traffic as config_save.
    if ($this->policyResolver->isGoverned()) {
      return;
    }

    $config = $event->getConfig();
    $name = $config->getName();
    $new = $config->getRawData();
    $original = $config instanceof Config
      ? $config->getOriginal('', FALSE)
      : (array) $config->getOriginal('');
    if (!is_array($original)) {
      $original = [];
    }
    $changedKeys = $this->changedTopLevelKeys($original, $new);
    // No-op saves (identical data) leave no useful record.
    if ($changedKeys === []) {
      return;
    }

    // Configuration of the control is a distinct elevated event from use.
    if ($name === self::SETTINGS_NAME) {
      $this->recordConfigured($name, $changedKeys);
      return;
    }

    $grant = $this->activeGrant();
    if ($grant === NULL) {
      return;
    }

    if (str_starts_with($name, self::POLICY_PREFIX)) {
      if ($this->liftsPublishFloor($new)) {
        $this->refuse(
          $name,
          $original,
          'break_glass_publish_floor',
          'Break-glass cannot lift the no-agent-publish floor.',
        );
      }
      $this->refuse(
        $name,
        $original,
        'break_glass_policy_promotion',
        'Break-glass cannot promote policy.',
      );
    }
    if ($this->liftsPublishFloor($new)) {
      $this->refuse(
        $name,
        $original,
        'break_glass_publish_floor',
        'Break-glass cannot lift the no-agent-publish floor.',
      );
    }

    try {
      // logAlways: flipping audit_enabled off must itself leave a row.
      $this->auditLogger->logAlways('config_save_break_glass', [
        'entity_type' => 'config',
        'id' => $name,
        'changed_keys' => $changedKeys,
        'grant_id' => (int) $grant->id(),
        'uid' => (int) $this->currentUser->id(),
      ]);
    }
    catch (\Throwable $e) {
      $this->revert($name, $original);
      throw new ConfigException(sprintf(
        "MCP Sentinel: break-glass config save of '%s' refused because the audit row could not be written: %s",
        $name,
        $e->getMessage(),
      ), 0, $e);
    }
  }

  /**
   * Refuses policy-profile deletion while a grant is live.
   *
   * @param \Drupal\Core\Config\ConfigCrudEvent $event
   *   The config CRUD event.
   *
   * @throws \Drupal\Core\Config\ConfigException
   *   When an elevated account tries to remove a policy profile.
   */
  public function onConfigDelete(ConfigCrudEvent $event): void {
    if ($this->policyResolver->isGoverned()) {
      return;
    }
    $grant = $this->activeGrant();
    if ($grant === NULL) {
      return;
    }
    $config = $event->getConfig();
    $name = $config->getName();
    if (!str_starts_with($name, self::POLICY_PREFIX)) {
      return;
    }
    $this->refuse(
      $name,
      $config->getRawData(),
      'break_glass_policy_promotion',
      'Break-glass cannot promote policy.',
    );
  }

  /**
   * Returns the live break-glass manager from the container.
   *
   * @return \Drupal\mcp_sentinel_approval\Service\McpBreakGlassManager
   *   The manager.
   */
  private function breakGlass(): McpBreakGlassManager {
    return $this->container->get('mcp_sentinel_approval.break_glass');
  }

  /**
   * Top-level key names that differ between original and new raw data.
   *
   * Values are never returned — secrets (webhook_secret_key, audit_hash_key)
   * must not accumulate in the audit trail.
   *
   * @param array $original
   *   Pre-save raw data.
   * @param array $new
   *   Post-save raw data.
   *
   * @return list<string>
   *   Sorted changed top-level key names.
   */
  private function changedTopLevelKeys(array $original, array $new): array {
    $keys = array_unique(array_merge(array_keys($original), array_keys($new)));
    $changed = [];
    foreach ($keys as $key) {
      $had = array_key_exists($key, $original);
      $has = array_key_exists($key, $new);
      if ($had !== $has || ($had && $original[$key] !== $new[$key])) {
        $changed[] = (string) $key;
      }
    }
    sort($changed);
    return $changed;
  }

  /**
   * The live grant for the current user, if elevation is in effect.
   */
  private function activeGrant(): ?McpAdminGrantInterface {
    $uid = (int) $this->currentUser->id();
    if ($uid <= 0 || !in_array(McpBreakGlassManager::ROLE_ID, $this->currentUser->getRoles(), TRUE)) {
      return NULL;
    }
    return $this->breakGlass()->findActiveGrantFor($uid);
  }

  /**
   * Records a change to break-glass control settings.
   *
   * @param string $name
   *   Config object name.
   * @param list<string> $changedKeys
   *   Changed top-level keys.
   *
   * @throws \Drupal\Core\Config\ConfigException
   *   When the audit write fails.
   */
  private function recordConfigured(string $name, array $changedKeys): void {
    try {
      $this->auditLogger->logAlways('break_glass_configured', [
        'entity_type' => 'config',
        'id' => $name,
        'changed_keys' => $changedKeys,
        'uid' => (int) $this->currentUser->id(),
      ]);
    }
    catch (\Throwable $e) {
      throw new ConfigException(sprintf(
        "MCP Sentinel: break-glass configuration of '%s' refused because the audit row could not be written: %s",
        $name,
        $e->getMessage(),
      ), 0, $e);
    }
  }

  /**
   * Whether the new raw data turns deny_publish off.
   *
   * @param array<string, mixed> $new
   *   Post-save raw data.
   */
  private function liftsPublishFloor(array $new): bool {
    return array_key_exists('deny_publish', $new) && $new['deny_publish'] === FALSE;
  }

  /**
   * Reverts a save and refuses it as a break-glass elevation overreach.
   *
   * @param string $name
   *   Config object name.
   * @param array $original
   *   Pre-save raw data.
   * @param string $reason
   *   Stable reason code.
   * @param string $message
   *   Exception message.
   *
   * @throws \Drupal\Core\Config\ConfigException
   *   Always.
   */
  private function refuse(string $name, array $original, string $reason, string $message): never {
    $this->revert($name, $original);
    $grant = $this->activeGrant();
    $this->auditLogger->logAlways('break_glass_refused', [
      'entity_type' => 'config',
      'id' => $name,
      'reason' => $reason,
      'uid' => (int) $this->currentUser->id(),
      'grant_id' => $grant !== NULL ? (int) $grant->id() : 0,
    ]);
    throw new ConfigException(sprintf('MCP Sentinel: %s (%s)', $message, $name));
  }

  /**
   * Reverts a just-written config object without re-dispatching SAVE.
   *
   * @param string $name
   *   Config object name.
   * @param array $original
   *   Pre-save raw data ([] deletes a newly-created object).
   */
  private function revert(string $name, array $original): void {
    if ($original === []) {
      $this->configStorage->delete($name);
    }
    else {
      $this->configStorage->write($name, $original);
    }
    $this->configFactory->reset($name);
  }

}
