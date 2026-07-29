<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\Core\Config\Config;
use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Config\ConfigEvents;
use Drupal\Core\Config\ConfigException;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\StorageInterface;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Service\McpRoleAssertions;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Audits — and hard-denies denied — configuration writes by governed agents.
 *
 * This is the defense-in-depth backstop named in the governance design (§4.2).
 * The config tools already gate writes at the tool boundary, but a direct
 * Config::save() during a governed (TokenAuthUser) request would bypass that
 * gate. This subscriber closes the gap on ConfigEvents::SAVE:
 *
 * 1. AUDIT — every config save during a governed request is recorded as
 *    'config_save' with a redaction- and DLP-aware diff, so any config mutation
 *    an agent causes is in the hash-chained audit log.
 * 2. HARD-DENY — a save to a config name matching the resolved profile's
 *    denied_config_types denylist is reverted and an exception is thrown.
 *
 * Important platform note: ConfigEvents::SAVE is dispatched AFTER the value is
 * written to config storage, so to make the deny effective the subscriber
 * reverts the persisted value (re-writing the original via raw storage, or
 * deleting a newly-created object) before throwing. Raw-storage writes do not
 * re-dispatch SAVE, so there is no re-entrancy. Reverting raw config storage is
 * best-effort for config entities whose secondary caches are not refreshed; the
 * authoritative preventive gate remains checkConfigAccess() at the tool seam.
 */
final class McpConfigSaveSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an McpConfigSaveSubscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPolicyResolver $policyResolver
   *   The MCP Sentinel policy resolver.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The MCP Sentinel audit logger.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory, used to reset the static cache after a revert.
   * @param \Drupal\Core\Config\StorageInterface $configStorage
   *   The active config storage, used to revert a denied write without
   *   re-dispatching ConfigEvents::SAVE.
   * @param \Drupal\mcp_sentinel\Service\McpRoleAssertions $roleAssertions
   *   The role-assertion service, used to notice a governed role gaining an
   *   escape-hatch permission.
   * @param \Psr\Log\LoggerInterface $logger
   *   The mcp_sentinel logger channel.
   */
  public function __construct(
    private readonly McpPolicyResolver $policyResolver,
    private readonly McpAuditLogger $auditLogger,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly StorageInterface $configStorage,
    private readonly McpRoleAssertions $roleAssertions,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      ConfigEvents::SAVE => [
        ['onConfigSave', 0],
        ['onRoleSave', -10],
      ],
    ];
  }

  /**
   * Reports a governed role gaining a permission its profile forbids.
   *
   * Unlike onConfigSave() this deliberately does NOT early-return for
   * ungoverned requests: the grant that matters is the one a human admin or a
   * config import makes, not one an agent makes. The live case behind #65 was
   * exactly that — `bypass file gate` sitting in an exported role config,
   * invisible to the module until someone read the YAML.
   *
   * It records and shouts; it does not block. Refusing the save would break
   * config import and would put this module in the way of an operator changing
   * their own site's permissions. The gate that *fails* is
   * `drush mcp-sentinel:role-audit`, which a deploy runs after import — by
   * which point every role and profile is in its final state, so it also
   * avoids the ordering problem this listener has (during an import a role may
   * be saved before the profile that governs it).
   *
   * @param \Drupal\Core\Config\ConfigCrudEvent $event
   *   The config CRUD event.
   */
  public function onRoleSave(ConfigCrudEvent $event): void {
    $name = $event->getConfig()->getName();
    if (!str_starts_with($name, 'user.role.')) {
      return;
    }
    $roleId = substr($name, strlen('user.role.'));
    // Read the permissions out of the config being saved, not by re-loading the
    // role: this event fires before the entity static cache is refreshed, so a
    // load here returns the pre-save permissions and the check sees nothing.
    $data = $event->getConfig()->getRawData();
    $permissions = (array) ($data['permissions'] ?? []);
    $isAdmin = (bool) ($data['is_admin'] ?? FALSE);

    // Never let the detector break the save it is watching. This listener fires
    // on *every* role save, including ones core makes while modules are being
    // installed or uninstalled — moments when this module's own audit table or
    // profile storage may not exist yet, or may already be gone. The
    // authoritative checks are the status report and
    // `drush mcp-sentinel:role-audit`, both of which run against a settled
    // site; this one is an early warning, and an early warning that can fatal
    // an install is worse than no early warning.
    try {
      $violations = $this->roleAssertions->violationsForSavedRole($roleId, $permissions, $isAdmin);
      foreach ($violations as $violation) {
        $this->logger->error($this->roleAssertions->describe($violation));
        $this->auditLogger->log('role_escape_hatch', [
          'entity_type' => 'user_role',
          'id' => $violation['role'],
          'permission' => $violation['permission'],
          'profile' => $violation['profile'],
          'via' => $violation['via'],
          'detected_on_save_of' => $name,
        ]);
      }
    }
    catch (\Throwable $e) {
      $this->logger->warning(
        'MCP Sentinel could not check role @role for escape-hatch permissions on save: @message. The status report and drush mcp-sentinel:role-audit still cover it.',
        ['@role' => $roleId, '@message' => $e->getMessage()],
      );
    }
  }

  /**
   * Audits, and hard-denies a denied, governed configuration write.
   *
   * @param \Drupal\Core\Config\ConfigCrudEvent $event
   *   The config CRUD event.
   *
   * @throws \Drupal\Core\Config\ConfigException
   *   When a governed write targets a denied config name (after revert).
   */
  public function onConfigSave(ConfigCrudEvent $event): void {
    // Only governed (policy-resolved agent) requests are subject to this gate.
    // Non-agent traffic (cron, drush deploys, human admins) is never touched.
    if (!$this->policyResolver->isGoverned()) {
      return;
    }
    $profile = $this->policyResolver->resolve();
    if ($profile === NULL) {
      return;
    }

    $config = $event->getConfig();
    $name = $config->getName();
    $new = $config->getRawData();
    // The runtime type is always Config, which exposes the raw (no-overrides)
    // original; fall back to the base one-arg signature for static analysis.
    $original = $config instanceof Config
      ? $config->getOriginal('', FALSE)
      : (array) $config->getOriginal('');
    $redacted = $profile->getRedactedFields();

    // Hard-deny: a write to a denied config name is reverted and rejected. The
    // SAVE event fires post-write, so revert the persisted value first.
    if ($this->isDeniedName($name, $profile->getDeniedConfigTypes())) {
      $this->auditLogger->log('config_write_denied', [
        'entity_type' => 'config',
        'id' => $name,
        'reason' => 'denied_config_types',
      ]);
      $this->revert($name, $original);
      throw new ConfigException(sprintf(
        "MCP Sentinel: write to denied configuration '%s' is blocked by policy.",
        $name,
      ));
    }

    // Otherwise audit the mutation with a redaction/DLP-aware diff.
    $diff = $this->auditLogger->computeConfigDiff($original, $new, $redacted);
    $this->auditLogger->log('config_save', [
      'entity_type' => 'config',
      'id' => $name,
      'changes' => $diff,
    ]);
  }

  /**
   * Returns TRUE when the config name matches any denylist prefix.
   *
   * @param string $name
   *   The full config object name.
   * @param string[] $deniedPrefixes
   *   The profile's denied_config_types prefixes.
   *
   * @return bool
   *   TRUE when denied.
   */
  private function isDeniedName(string $name, array $deniedPrefixes): bool {
    foreach ($deniedPrefixes as $prefix) {
      if ($prefix !== '' && str_starts_with($name, $prefix)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Reverts a just-written config object to its pre-save state.
   *
   * Writes directly to config storage (no SAVE event, so no re-entrancy) and
   * resets the config factory static cache so the reverted value is visible to
   * the rest of the request. A newly-created object (no original) is deleted.
   *
   * @param string $name
   *   The config object name.
   * @param array $original
   *   The original raw data ([] when the object was newly created).
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
