<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Consolidation\AnnotatedCommand\Hooks\HookManager;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drush\Attributes as CLI;
use Drush\Commands\AutowireTrait;
use Drush\Commands\DrushCommands;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * Opens a deny-only overlay for every Drush command.
 *
 * Drush dispatches ConsoleEvents::COMMAND / TERMINATE on its own
 * eventDispatcher, not Drupal's event_dispatcher. The Symfony
 * Console subscriber therefore never runs for Drush. These
 * PRE/POST_COMMAND_HOOK methods are the Drush-native overlay.
 * The hook target is `*`, so a Drush-hosted stdio server is
 * never admitted for governed tools. Governed tools refuse
 * (`missing_principal`) until a hop token supplies a Paladin
 * principal.
 *
 * @internal Queue items open the overlay in the worker, not here.
 */
final class McpPrincipalContextCommands extends DrushCommands {

  use AutowireTrait;

  /**
   * Internal job-boundary helper.
   */
  private readonly McpPrincipalContextJob $job;

  /**
   * Constructs the Drush hook command file.
   *
   * The job service is private; construct it from the holder.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   The write-once sealed context.
   */
  public function __construct(
    #[Autowire(service: 'mcp_sentinel.principal_context_holder')]
    McpPrincipalContextHolder $holder,
  ) {
    parent::__construct();
    $this->job = new McpPrincipalContextJob($holder);
  }

  /**
   * Begins a job overlay for this Drush invocation.
   */
  #[CLI\Hook(type: HookManager::PRE_COMMAND_HOOK, target: '*')]
  public function preCommand(): void {
    $this->job->begin();
  }

  /**
   * Ends the job overlay after the command returns.
   */
  #[CLI\Hook(type: HookManager::POST_COMMAND_HOOK, target: '*')]
  public function postCommand(): void {
    $this->job->end();
  }

}
