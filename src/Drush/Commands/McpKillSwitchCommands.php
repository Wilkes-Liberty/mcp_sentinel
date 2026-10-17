<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBinding;
use Drupal\mcp_sentinel\Service\McpOperatorIdentityFactory;
use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
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
   * @param \Drupal\mcp_sentinel\Service\McpWebhookQueueManager $webhookQueue
   *   Held webhook deliveries.
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
    #[Autowire(service: 'mcp_sentinel.webhook_queue_manager')]
    private readonly McpWebhookQueueManager $webhookQueue,
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
  #[CLI\Usage(name: 'drush mcp-sentinel:kill --human-key=iss|sub --reason="mass revoke"', description: 'Person-wide freeze. In-scope agents are refused immediately; a second operator confirms, extends, or lifts.')]
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
   * Second operator confirms a mass freeze (keeps it).
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-confirm', aliases: ['mcps:kill-confirm'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill-confirm BATCH', description: 'Confirm a mass freeze as a distinct operator.')]
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
   * Second operator extends a mass freeze (7-day cap).
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-extend', aliases: ['mcps:kill-extend'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds from now. Default 86400, max 604800.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill-extend BATCH --ttl=604800', description: 'Extend a mass freeze as a distinct operator.')]
  public function extendKill(
    string $batch,
    array $options = [
      'ttl' => NULL,
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $ttlRaw = $options['ttl'] ?? '';
      $ttl = $ttlRaw === '' ? NULL : (int) $ttlRaw;
      $result = $this->killSwitch->extend($batch, $this->operatorIdentity(), $ttl);
      $this->printResult($result);
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Second operator lifts an unconfirmed mass freeze.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-lift', aliases: ['mcps:kill-lift'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill-lift BATCH', description: 'Lift an unconfirmed mass freeze as a distinct operator. Held deliveries stay held.')]
  public function liftKill(string $batch): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $result = $this->killSwitch->lift($batch, $this->operatorIdentity());
      $this->printResult($result);
      $this->io()->writeln('held_items: unchanged (release or discard explicitly)');
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Break-glass keep, extend, or lift when the second person is unreachable.
   */
  #[CLI\Command(name: 'mcp-sentinel:kill-break-glass', aliases: ['mcps:kill-break-glass'])]
  #[CLI\Argument(name: 'batch', description: 'Batch id printed by mcp-sentinel:kill.')]
  #[CLI\Option(name: 'keep', description: 'Confirm (keep) the freeze.')]
  #[CLI\Option(name: 'extend', description: 'Extend the freeze. Pass seconds with --ttl.')]
  #[CLI\Option(name: 'lift', description: 'Lift the freeze. Held deliveries stay held.')]
  #[CLI\Option(name: 'ttl', description: 'Lifetime in seconds when extending. Default 86400, max 604800.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:kill-break-glass BATCH --keep', description: 'Break-glass keep of a mass freeze.')]
  public function breakGlassKill(
    string $batch,
    array $options = [
      'keep' => FALSE,
      'extend' => FALSE,
      'lift' => FALSE,
      'ttl' => NULL,
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $action = $this->breakGlassAction($options);
      $ttlRaw = $options['ttl'] ?? '';
      $ttl = $ttlRaw === '' ? NULL : (int) $ttlRaw;
      $result = $this->killSwitch->breakGlass(
        $batch,
        $action,
        $this->operatorIdentity(),
        $ttl,
      );
      $this->printResult($result);
      $this->io()->writeln('break_glass: ' . $action->value);
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * List held webhook deliveries.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-held', aliases: ['mcps:webhook-held'])]
  #[CLI\Usage(name: 'drush mcp-sentinel:webhook-held', description: 'List webhook deliveries held by a kill.')]
  public function listHeld(): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    $rows = $this->webhookQueue->listHeld();
    if ($rows === []) {
      $this->io()->writeln('held: none');
      return self::EXIT_SUCCESS;
    }
    $table = [];
    foreach ($rows as $row) {
      $table[] = [
        (string) $row['id'],
        (string) ($row['endpoint_id'] ?? ''),
        (string) ($row['event_name'] ?? ''),
        (string) ($row['principal_key'] ?? ''),
        (string) ($row['human_key'] ?? ''),
        (string) ($row['tenant'] ?? ''),
      ];
    }
    $this->io()->table(
      ['id', 'endpoint', 'event', 'principal_key', 'human_key', 'tenant'],
      $table,
    );
    return self::EXIT_SUCCESS;
  }

  /**
   * Release held webhook deliveries so they deliver as originally queued.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-release', aliases: ['mcps:webhook-release'])]
  #[CLI\Option(name: 'id', description: 'Held delivery id. Repeat for a batch.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:webhook-release --id=12 --id=13', description: 'Release held deliveries. Same payload, id, and body signature.')]
  public function releaseHeld(
    array $options = [
      'id' => [],
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $ids = $this->idList($options['id'] ?? []);
      $released = $this->webhookQueue->releaseHeld($ids, $this->operatorIdentity());
      $this->io()->writeln('released: ' . implode(',', $released));
      return self::EXIT_SUCCESS;
    }
    catch (McpKillSwitchException | McpPrincipalKeyException $e) {
      $this->logger()->error($e->getMessage());
      return self::EXIT_FAILURE;
    }
  }

  /**
   * Discard held webhook deliveries. They are never delivered.
   */
  #[CLI\Command(name: 'mcp-sentinel:webhook-discard', aliases: ['mcps:webhook-discard'])]
  #[CLI\Option(name: 'id', description: 'Held delivery id. Repeat for a batch.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:webhook-discard --id=12', description: 'Discard held deliveries. They are never sent.')]
  public function discardHeld(
    array $options = [
      'id' => [],
    ],
  ): int {
    if (($denied = $this->requirePermission()) !== NULL) {
      return $denied;
    }
    try {
      $ids = $this->idList($options['id'] ?? []);
      $discarded = $this->webhookQueue->discardHeld($ids, $this->operatorIdentity());
      $this->io()->writeln('discarded: ' . implode(',', $discarded));
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
        'needs_confirm: yes (named second person / secondary account holder).',
      );
      $this->io()->writeln(
        'freeze: in force now. Unconfirmed timeout keeps it and escalates.',
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
   * Break-glass action from mutually exclusive flags.
   *
   * @param array<string, mixed> $options
   *   Command options.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function breakGlassAction(array $options): McpKillBreakGlassAction {
    $keep = !empty($options['keep']);
    $extend = !empty($options['extend']);
    $lift = !empty($options['lift']);
    $chosen = (int) $keep + (int) $extend + (int) $lift;
    if ($chosen !== 1) {
      throw new McpKillSwitchException(
        McpKillSwitchException::INVALID_ACTION,
        'Pass exactly one of --keep, --extend, or --lift.',
      );
    }
    if ($keep) {
      return McpKillBreakGlassAction::Keep;
    }
    if ($extend) {
      return McpKillBreakGlassAction::Extend;
    }
    return McpKillBreakGlassAction::Lift;
  }

  /**
   * Positive delivery ids from a repeated Drush option.
   *
   * @param mixed $value
   *   Option value.
   *
   * @return list<int>
   *   Ids.
   */
  private function idList(mixed $value): array {
    $ids = [];
    foreach ($this->optionList($value) as $item) {
      $id = (int) $item;
      if ($id > 0) {
        $ids[] = $id;
      }
    }
    return $ids;
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
