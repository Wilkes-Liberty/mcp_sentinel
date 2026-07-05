<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Drush\Commands;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Drush commands for the MCP Sentinel approval / break-glass workflow.
 */
final class McpApprovalCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Constructs a new McpApprovalCommands object.
   */
  public function __construct(
    #[Autowire(service: 'event_dispatcher')]
    private readonly EventDispatcherInterface $eventDispatcher,
    #[Autowire(service: 'current_user')]
    private readonly AccountProxyInterface $currentUser,
  ) {
    parent::__construct();
  }

  /**
   * Request the time-boxed mcp_admin break-glass role for a user.
   *
   * Privilege escalation is always approval-gated: this raises an approval
   * request rather than granting the role directly. An authorized approver
   * grants it via the approvals UI, after which it is auto-revoked at the
   * configured TTL.
   *
   * @param int $uid
   *   The user id to elevate.
   */
  #[CLI\Command(name: 'mcp-sentinel:break-glass', aliases: ['mcps:break-glass'])]
  #[CLI\Argument(name: 'uid', description: 'The user id to grant the break-glass mcp_admin role to.')]
  #[CLI\Usage(name: 'drush mcp-sentinel:break-glass 5', description: 'Request break-glass elevation for user 5 (queued for approval).')]
  public function breakGlass(int $uid): int {
    $event = new McpDestructiveActionEvent('user', (string) $uid, 'grant_mcp_admin', $this->currentUser);
    $this->eventDispatcher->dispatch($event, McpDestructiveActionEvent::NAME);

    if ($event->isVetoed()) {
      $this->logger()->success(sprintf('Break-glass request raised for user %d: %s', $uid, (string) $event->getVetoReason()));
      return self::EXIT_SUCCESS;
    }

    // No subscriber queued it — the approval submodule is the gate, so this
    // means it is not active. Never silently elevate.
    $this->logger()->error('Break-glass request was not queued for approval (approval gate inactive); no role was granted.');
    return self::EXIT_FAILURE;
  }

}
