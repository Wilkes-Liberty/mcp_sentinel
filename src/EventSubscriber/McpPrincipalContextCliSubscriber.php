<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\mcp_sentinel\Service\McpJobScopeHandle;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\Console\Event\ConsoleEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Opens a deny-only overlay for Symfony Console (core/scripts).
 *
 * Drush does not deliver ConsoleEvents to Drupal's event_dispatcher.
 * Per-invocation Drush overlay is
 * McpPrincipalContextCommands (PRE/POST_COMMAND_HOOK).
 *
 * @internal Queue items open the overlay in the worker, not here.
 */
final class McpPrincipalContextCliSubscriber implements EventSubscriberInterface {

  /**
   * Handle for the overlay opened by onCommand().
   */
  private ?McpJobScopeHandle $handle = NULL;

  /**
   * Constructs the subscriber.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextJob $job
   *   Internal job-boundary helper.
   */
  public function __construct(
    private readonly McpPrincipalContextJob $job,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [
      ConsoleEvents::COMMAND => ['onCommand', 100],
      ConsoleEvents::TERMINATE => ['onTerminate', -100],
    ];
  }

  /**
   * Begins a deny-only overlay for one console command invocation.
   *
   * @param \Symfony\Component\Console\Event\ConsoleCommandEvent $event
   *   The console command event.
   */
  public function onCommand(ConsoleCommandEvent $event): void {
    if ($this->isOurCommand($event)) {
      $this->handle = $this->job->begin();
    }
  }

  /**
   * Ends the deny-only overlay after the command returns.
   *
   * @param \Symfony\Component\Console\Event\ConsoleEvent $event
   *   The console terminate event.
   */
  public function onTerminate(ConsoleEvent $event): void {
    if ($this->handle === NULL) {
      return;
    }
    // The handle is the close token. The command name is re-checked
    // so TERMINATE still names the invocation COMMAND opened.
    if (!$this->isOurCommand($event)) {
      return;
    }
    $this->job->end($this->handle);
    $this->handle = NULL;
  }

  /**
   * Whether this invocation is an MCP Sentinel or queue-run command.
   *
   * @param \Symfony\Component\Console\Event\ConsoleEvent $event
   *   The console event.
   *
   * @return bool
   *   TRUE when this command must open the deny-only overlay.
   */
  private function isOurCommand(ConsoleEvent $event): bool {
    $name = $event->getCommand()?->getName() ?? '';
    return str_starts_with($name, 'mcp-sentinel:')
      || $name === 'queue:run'
      || $name === 'queue:process';
  }

}
