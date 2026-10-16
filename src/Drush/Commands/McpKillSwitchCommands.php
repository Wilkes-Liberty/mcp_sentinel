<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
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
 * effective uid with the site private key. --uid, the login name,
 * and the USER environment variable cannot change that assertion.
 * Without a verified identity, confirm is refused (fail closed).
 * Mixed-channel confirm (Paladin then Drush, or the reverse) needs
 * mcp-sentinel:operator-bind so both identities resolve to one
 * operator record. Bind introspects a Paladin token (active required)
 * and derives iss|sub from that response, never from --human-key.
 * The token is read from stdin or PALADIN_TOKEN, never --token.
 * Paladin down fails closed. Unbind needs two distinct verified
 * operators. The shell sits outside governance; bind from an
 * individual OS account, not a shared deploy user.
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
   * @param \Drupal\mcp_sentinel\Service\McpOperatorBinding $operatorBindings
   *   Paladin/Drush operator-record bindings.
   */
  public function __construct(
    #[Autowire(service: 'mcp_sentinel.kill_switch')]
    private readonly McpKillSwitch $killSwitch,
    #[Autowire(service: 'current_user')]
    private readonly AccountProxyInterface $currentUser,
    #[Autowire(service: 'mcp_sentinel.operator_identity')]
    private readonly McpOperatorIdentityFactory $operatorIdentities,
    #[Autowire(service: 'mcp_sentinel.operator_binding')]
    private readonly McpOperatorBinding $operatorBindings,
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
   * Bind this OS account to a Paladin identity from token introspection.
   *
   * The iss|sub is taken from an active Paladin introspection response,
   * never from --human-key. Paladin unreachable fails closed. A
   * squatted identity already bound to a different operator is
   * refused. Pipe the token on stdin or set PALADIN_TOKEN; --token
   * is refused. The shell is outside governance: run this from an
   * individual OS account, not a shared deploy user.
   */
  #[CLI\Command(name: 'mcp-sentinel:operator-bind', aliases: ['mcps:operator-bind'])]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-bind', description: 'Bind this shell to the Paladin iss|sub from an active introspection.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:operator-bind < token.txt', description: 'Bind using a token piped on stdin.')]
  public function bindOperator(
    array $options = [
      'token' => '',
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $token = $this->paladinToken($options);
      $operatorId = $this->operatorBindings->bindFromToken($token);
      $this->io()->writeln('operator_id: ' . $operatorId);
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Unbind an operator record. Two distinct Paladin operators required.
   */
  #[CLI\Command(name: 'mcp-sentinel:operator-unbind', aliases: ['mcps:operator-unbind'])]
  #[CLI\Option(name: 'token', description: 'Refused. Pipe the token on stdin or set PALADIN_TOKEN.')]
  #[CLI\Option(name: 'confirm-batch', description: 'Batch id from an unbind request, to confirm as the named second person (secondary account holder).')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-unbind', description: 'Request unbind of this Paladin operator record (pending confirm).')]
  #[CLI\Usage(name: 'PALADIN_TOKEN=ACCESS_TOKEN drush mcp-sentinel:operator-unbind --confirm-batch=BATCH', description: 'Confirm an unbind as a distinct operator.')]
  public function unbindOperator(
    array $options = [
      'token' => '',
      'confirm-batch' => NULL,
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $token = $this->paladinToken($options);
      $confirmBatch = trim((string) ($options['confirm-batch'] ?? ''));
      if ($confirmBatch !== '') {
        $this->operatorBindings->confirmUnbindFromToken($token, $confirmBatch);
        $this->io()->writeln('status: unbound');
        return self::EXIT_SUCCESS;
      }
      $batchId = $this->operatorBindings->requestUnbindFromToken($token);
      $this->io()->writeln('status: unbind_pending');
      $this->io()->writeln('batch: ' . $batchId);
      $this->io()->writeln(
        'needs_confirm: yes (named second person / secondary account holder)',
      );
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
   * Paladin access token from PALADIN_TOKEN or stdin. Never logged.
   *
   * --token is refused: it lands in shell history and in ps. An empty
   * value is passed through so bind and unbind can audit the refusal.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @return string
   *   Access token, or empty when neither source provided one.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When --token is passed.
   */
  private function paladinToken(array $options): string {
    if (trim((string) ($options['token'] ?? '')) !== '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'Do not pass --token. Pipe the token on stdin or set PALADIN_TOKEN.',
      );
    }
    $fromEnv = getenv('PALADIN_TOKEN');
    if (is_string($fromEnv) && trim($fromEnv) !== '') {
      return trim($fromEnv);
    }
    if (!defined('STDIN') || (function_exists('posix_isatty') && posix_isatty(STDIN))) {
      return '';
    }
    $fromStdin = stream_get_contents(STDIN);
    return is_string($fromStdin) ? trim($fromStdin) : '';
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
