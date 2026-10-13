<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\EventSubscriber;

use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Symfony\Component\Console\ConsoleEvents;
use Symfony\Component\Console\Event\ConsoleCommandEvent;
use Symfony\Component\Console\Event\ConsoleEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Resets the job principal at the start and end of a Drush invocation.
 *
 * @internal Queue items are reset in the worker, not here.
 */
final class McpPrincipalContextCliSubscriber implements EventSubscriberInterface {

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
   * Begins a job seal for one Drush command invocation.
   *
   * @param \Symfony\Component\Console\Event\ConsoleCommandEvent $event
   *   The console command event.
   */
  public function onCommand(ConsoleCommandEvent $event): void {
    if ($this->isOurCommand($event)) {
      $this->job->begin();
    }
  }

  /**
   * Ends the job seal after the command returns.
   *
   * @param \Symfony\Component\Console\Event\ConsoleEvent $event
   *   The console terminate event.
   */
  public function onTerminate(ConsoleEvent $event): void {
    if ($this->isOurCommand($event)) {
      $this->job->end();
    }
  }

  /**
   * Whether this invocation is an MCP Sentinel or queue-run command.
   *
   * @param \Symfony\Component\Console\Event\ConsoleEvent $event
   *   The console event.
   *
   * @return bool
   *   TRUE when this command must reset the job principal.
   */
  private function isOurCommand(ConsoleEvent $event): bool {
    $name = $event->getCommand()?->getName() ?? '';
    return str_starts_with($name, 'mcp-sentinel:')
      || $name === 'queue:run'
      || $name === 'queue:process';
  }

}
