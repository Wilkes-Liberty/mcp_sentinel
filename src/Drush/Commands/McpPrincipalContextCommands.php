<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Drush\Commands;

use Consolidation\AnnotatedCommand\Hooks\HookManager;
use Drupal\mcp_sentinel\Service\McpJobScopeHandle;
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
   * Handle for the overlay opened by preCommand().
   */
  private ?McpJobScopeHandle $handle = NULL;

  /**
   * Constructs the Drush hook command file.
   *
   * Autowire reaches the public job helper. The holder is
   * public:false and is not retrieved from the container here.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextJob $job
   *   Opens and closes the deny-only overlay for this invocation.
   */
  public function __construct(
    #[Autowire(service: 'mcp_sentinel.principal_context_job')]
    private readonly McpPrincipalContextJob $job,
  ) {
    parent::__construct();
  }

  /**
   * Begins a job overlay for this Drush invocation.
   */
  #[CLI\Hook(type: HookManager::PRE_COMMAND_HOOK, target: '*')]
  public function preCommand(): void {
    $this->handle = $this->job->begin();
  }

  /**
   * Ends the job overlay after the command returns.
   */
  #[CLI\Hook(type: HookManager::POST_COMMAND_HOOK, target: '*')]
  public function postCommand(): void {
    if ($this->handle === NULL) {
      throw new \LogicException(
        'postCommand() requires a matching preCommand().',
      );
    }
    $this->job->end($this->handle);
    $this->handle = NULL;
  }

}
