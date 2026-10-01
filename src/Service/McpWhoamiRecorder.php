<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\State\StateInterface;
use Drupal\mcp_sentinel\Value\McpGovernanceReadinessResult;

/**
 * Records the last connector whoami / readiness signal without secrets.
 */
final class McpWhoamiRecorder {

  /**
   * State key for the last whoami snapshot.
   */
  public const STATE_KEY = 'mcp_sentinel.last_whoami';

  /**
   * Constructs the recorder.
   */
  public function __construct(
    private readonly StateInterface $state,
    private readonly TimeInterface $time,
    private readonly AccountProxyInterface $currentUser,
    private readonly McpOauthContext $oauthContext,
  ) {}

  /**
   * Stores a non-secret snapshot of the latest whoami-style call.
   *
   * @param \Drupal\mcp_sentinel\Value\McpGovernanceReadinessResult $result
   *   The readiness decision just evaluated.
   * @param string $surface
   *   One of readiness, context, or tool.
   */
  public function record(McpGovernanceReadinessResult $result, string $surface): void {
    $clientId = $this->oauthContext->clientId();
    $this->state->set(self::STATE_KEY, [
      'time' => $this->time->getRequestTime(),
      'uid' => (int) $this->currentUser->id(),
      'client_id' => $clientId,
      'ready' => $result->isReady(),
      'reason' => $result->reason()?->value,
      'surface' => $surface,
    ]);
  }

  /**
   * Returns the stored snapshot, or NULL when none has been recorded.
   *
   * @return array{time: int, uid: int, client_id: string|null, ready: bool, reason: string|null, surface: string}|null
   *   The last signal, or NULL.
   */
  public function last(): ?array {
    $stored = $this->state->get(self::STATE_KEY);
    if (!is_array($stored) || !isset($stored['time'])) {
      return NULL;
    }
    return [
      'time' => (int) $stored['time'],
      'uid' => (int) ($stored['uid'] ?? 0),
      'client_id' => isset($stored['client_id']) && is_string($stored['client_id']) && $stored['client_id'] !== ''
        ? $stored['client_id']
        : NULL,
      'ready' => (bool) ($stored['ready'] ?? FALSE),
      'reason' => isset($stored['reason']) && is_string($stored['reason']) && $stored['reason'] !== ''
        ? $stored['reason']
        : NULL,
      'surface' => isset($stored['surface']) && is_string($stored['surface'])
        ? $stored['surface']
        : 'readiness',
    ];
  }

}
