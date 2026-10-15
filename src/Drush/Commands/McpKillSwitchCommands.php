<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillSwitchResult;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Operator commands for the agent kill switch (DEV-846).
 *
 * No UI in this slice. Permission: administer agent kill switch.
 *
 * currentUser is the Drupal account Drush bootstrap set from --user /
 * --uid (or the site owner). That account is used only for the
 * restricted permission check. It is not a verified operator
 * identity: anyone with shell access can pass --uid=2 then --uid=3
 * and appear as two accounts. The two-person rule binds each
 * approval to a Paladin human key (iss|sub) from the sealed
 * principal context, or to a Drush assertion HMAC of the OS
 * process identity (effective uid and login name) with the site
 * private key. --uid cannot change that assertion. Without a
 * verified identity, confirm is refused (fail closed).
 */
final class McpKillSwitchCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs the command file.
   *
   * @param \Drupal\mcp_sentinel\Service\McpKillSwitch $killSwitch
   *   Kill registry.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   Drupal account for permission only. Not the two-person identity.
   * @param \Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory $operatorIdentities
   *   Paladin or Drush-assertion identity resolver.
   */
  public function __construct(
    #[Autowire(service: 'mcp_sentinel.kill_switch')]
    private readonly McpKillSwitch $killSwitch,
    #[Autowire(service: 'current_user')]
    private readonly AccountProxyInterface $currentUser,
    #[Autowire(service: 'mcp_sentinel.operator_identity')]
    private readonly McpOperatorIdentityFactory $operatorIdentities,
  ) {
    parent::__construct();
  }

  /**
   * Kill one principal, every agent of this person, a tenant, or a mass set.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill', aliases: ['mcps:kill'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor. Repeat for a mass kill.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub: every agent of this person (mass).')]
  #[CLI\Option(name: 'tenant', description: 'Tenant-wide selector (mass).')]
  #[CLI\Option(name: 'reason', description: 'Operator reason. Required. No tokens.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds. Default 86400, max 604800.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill --principal-key=iss|sub|actor --reason="compromise"', description: 'Kill one principal immediately.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill --human-key=iss|sub --reason="mass revoke"', description: 'Mass kill pending second-operator confirm.')]
  public function kill(
    array $options = [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
      'reason' => '',
      'ttl' => NULL,
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $selectors = $this->selectorsFromOptions($options);
      $ttlRaw = $options['ttl'] ?? '';
      $ttl = $ttlRaw === '' ? NULL : (int) $ttlRaw;
      $result = $this->killSwitch->kill(
        $selectors,
        (string) $options['reason'],
        $this->operatorIdentity(),
        $ttl,
      );
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Second operator confirms a pending mass kill.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-confirm', aliases: ['mcps:kill-confirm'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill-confirm BATCH', description: 'Confirm a pending mass kill as a distinct operator.')]
  public function confirmKill(string $batch): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $result = $this->killSwitch->confirm($batch, $this->operatorIdentity());
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Request an un-kill. Always needs a distinct second operator.
   */
  #[CLI\Command(name: 'mcp-sentinel:unkill', aliases: ['mcps:unkill'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub.')]
  #[CLI\Option(name: 'tenant', description: 'Tenant selector.')]
  #[CLI\Option(name: 'reason', description: 'Operator reason. Required. No tokens.')]
  #[CLI\Option(name: 'confirm-batch', description: 'Batch id from an un-kill request, to confirm as the named second person (secondary account holder).')]
  #[CLI\Usage(name: 'drush mcp-sentinel:unkill --principal-key=iss|sub|actor --reason="restored"', description: 'Request an un-kill (pending confirm).')]
  #[CLI\Usage(name: 'drush mcp-sentinel:unkill --confirm-batch=BATCH', description: 'Confirm an un-kill as a distinct operator.')]
  public function unkill(
    array $options = [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
      'reason' => '',
      'confirm-batch' => NULL,
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $confirmBatch = trim((string) ($options['confirm-batch'] ?? ''));
      if ($confirmBatch !== '') {
        $result = $this->killSwitch->confirmUnkill($confirmBatch, $this->operatorIdentity());
        $this->printResult($result);
        return self::EXIT_SUCCESS;
      }
      $result = $this->killSwitch->requestUnkill(
        $this->selectorsFromOptions($options),
        (string) $options['reason'],
        $this->operatorIdentity(),
      );
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Show kill-block status for a selector.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-status', aliases: ['mcps:kill-status'])]
  #[CLI\Option(name: 'principal-key', description: 'iss|sub|actor.')]
  #[CLI\Option(name: 'human-key', description: 'iss|sub.')]
  #[CLI\Option(name: 'tenant', description: 'Tenant selector.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill-status --principal-key=iss|sub|actor', description: 'Print the kill-block row for one principal.')]
  public function status(
    array $options = [
      'principal-key' => [],
      'human-key' => [],
      'tenant' => [],
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $selectors = $this->selectorsFromOptions($options);
      if (count($selectors) !== 1) {
        $this->logger()->error('kill-status requires exactly one selector.');
        return self::EXIT_FAILURE;
      }
      $row = $this->killSwitch->status($selectors[0]);
      if ($row === NULL) {
        $this->io()->writeln('status: active');
        return self::EXIT_SUCCESS;
      }
      $this->io()->table(
        ['Field', 'Value'],
        [
          ['status', (string) $row['status']],
          ['selector_type', (string) $row['selector_type']],
          ['selector_key', (string) $row['selector_key']],
          ['block_until', (string) $row['block_until']],
          ['ttl', (string) $row['ttl']],
          ['batch_id', (string) $row['batch_id']],
          ['requested_by', (string) $row['requested_by']],
          ['confirmed_by', (string) $row['confirmed_by']],
          ['unkill_batch_id', (string) $row['unkill_batch_id']],
        ],
      );
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Builds selectors from repeated Drush options.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @return list<\Drupal\mcp_sentinel\Value\McpKillSelector>
   *   Selectors.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   * @throws \Drupal\mcp_sentinel\Exception\McpPrincipalKeyException
   */
  private function selectorsFromOptions(array $options): array {
    $selectors = [];
    foreach ($this->optionList($options['principal-key'] ?? []) as $key) {
      $selectors[] = McpKillSelector::principalKey($key);
    }
    foreach ($this->optionList($options['human-key'] ?? []) as $key) {
      $selectors[] = McpKillSelector::humanKey($key);
    }
    foreach ($this->optionList($options['tenant'] ?? []) as $key) {
      $selectors[] = McpKillSelector::tenant($key);
    }
    return $selectors;
  }

  /**
   * Normalizes a Drush option that may be a string or a list.
   *
   * @param mixed $value
   *   Option value.
   *
   * @return list<string>
   *   Non-empty strings.
   */
  private function optionList(mixed $value): array {
    if ($value === NULL || $value === '' || $value === []) {
      return [];
    }
    if (!is_array($value)) {
      $value = [$value];
    }
    $out = [];
    foreach ($value as $item) {
      $item = trim((string) $item);
      if ($item !== '') {
        $out[] = $item;
      }
    }
    return $out;
  }

  /**
   * Prints a compact operator-facing result.
   */
  private function printResult(McpKillSwitchResult $result): void {
    $this->io()->writeln('status: ' . $result->status->value);
    $this->io()->writeln('batch: ' . $result->batchId);
    if ($result->needsConfirm) {
      $this->io()->writeln(
        'needs_confirm: yes (named second person / secondary account holder)',
      );
    }
    if ($result->blockUntil > 0) {
      $this->io()->writeln('block_until: ' . (string) $result->blockUntil);
    }
    $this->io()->writeln('ttl: ' . (string) $result->ttl);
  }

  /**
   * Restricted-permission gate. Uses currentUser, not operator identity.
   */
  private function requirePermission(): ?int {
    try {
      $this->killSwitch->assertOperatorAccess($this->currentUser);
    }
    catch (McpKillSwitchException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
    return NULL;
  }

  /**
   * Verified Paladin or Drush-assertion identity. Never currentUser->id().
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function operatorIdentity(): McpOperatorIdentity {
    return $this->operatorIdentities->forDrushCommand();
  }

}
