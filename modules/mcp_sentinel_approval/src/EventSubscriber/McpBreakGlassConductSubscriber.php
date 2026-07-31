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
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      ConfigEvents::SAVE => ['onConfigSave', -20],
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

    $uid = (int) $this->currentUser->id();
    if ($uid <= 0 || !$this->currentUser->hasRole(McpBreakGlassManager::ROLE_ID)) {
      return;
    }

    $grant = $this->breakGlass()->findActiveGrantFor($uid);
    if ($grant === NULL) {
      return;
    }

    $config = $event->getConfig();
    $name = $config->getName();
    $new = $config->getRawData();
    $original = $config instanceof Config
      ? $config->getOriginal('', FALSE)
      : (array) $config->getOriginal('');
    $changedKeys = $this->changedTopLevelKeys($original, $new);
    // No-op saves (identical data) leave no useful record.
    if ($changedKeys === []) {
      return;
    }

    try {
      // logAlways: flipping audit_enabled off must itself leave a row.
      $this->auditLogger->logAlways('config_save_break_glass', [
        'entity_type' => 'config',
        'id' => $name,
        'changed_keys' => $changedKeys,
        'grant_id' => (int) $grant->id(),
        'uid' => $uid,
      ]);
    }
    catch (\Throwable $e) {
      $this->revert($name, is_array($original) ? $original : []);
      throw new ConfigException(sprintf(
        "MCP Sentinel: break-glass config save of '%s' refused because the audit row could not be written: %s",
        $name,
        $e->getMessage(),
      ), 0, $e);
    }
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
