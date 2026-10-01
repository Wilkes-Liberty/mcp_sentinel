<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Url;

/**
 * Builds the admin MCP status strip (DEV-761).
 *
 * Visible facts only: master switch, designated clients/consumers,
 * source-governance readiness, and the last whoami signal. No secrets.
 */
final class McpAdminStatus {

  /**
   * Constructs the status assembler.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ModuleHandlerInterface $moduleHandler,
    private readonly McpGovernanceReadiness $readiness,
    private readonly McpWhoamiRecorder $whoamiRecorder,
    private readonly TimeInterface $time,
    private readonly AccountProxyInterface $currentUser,
  ) {}

  /**
   * Returns render-ready strip data.
   *
   * @return array<string, mixed>
   *   Strip fields for the theme hook.
   */
  public function build(): array {
    $settings = $this->configFactory->get('mcp_sentinel.settings');
    $enabled = (bool) $settings->get('enabled');
    $contract = $this->readiness->contractStatus();
    $reason = $contract->reason();
    $clients = $this->designatedClients((array) ($settings->get('agent_oauth_clients') ?? []));
    $consumerTotal = $this->consumerCount();
    $last = $this->whoamiRecorder->last();

    $gate = $enabled
      ? ($contract->isReady()
        ? 'Source-governance contract is ready. This is not a posture or evidence claim.'
        : ($reason?->operatorMessage() ?? 'Source-governance contract is not ready.'))
      : 'MCP API access is off. All MCP requests receive 403.';
    $next = !$enabled
      ? 'Turn on Enable MCP API access.'
      : ($contract->isReady() ? '' : ($reason?->nextStep() ?? ''));

    return [
      'enabled' => $enabled,
      'enabled_label' => $enabled ? 'On' : 'Off',
      'ready' => $contract->isReady(),
      'gate' => $reason?->value,
      'gate_message' => $gate,
      'next_step' => $next,
      'clients' => $clients,
      'client_count' => count($clients),
      'consumer_count' => $consumerTotal,
      'last_whoami' => $last === NULL ? NULL : [
        'time' => $last['time'],
        'age' => $this->ageLabel($last['time']),
        'uid' => $last['uid'],
        'client_id' => $last['client_id'],
        'ready' => $last['ready'],
        'reason' => $last['reason'],
        'surface' => $last['surface'],
      ],
      'add_client_url' => $this->addClientUrl(),
      'settings_url' => $this->safeUrl('mcp_sentinel.settings'),
      'mint_url' => $this->safeUrl('mcp_sentinel.sealed_token'),
    ];
  }

  /**
   * Resolves designated client ids to Consumer labels when possible.
   *
   * @param mixed[] $clientIds
   *   Configured agent_oauth_clients values.
   *
   * @return array<int, array{id: string, label: string, present: bool, enabled: bool}>
   *   Client rows.
   */
  private function designatedClients(array $clientIds): array {
    $rows = [];
    foreach ($clientIds as $clientId) {
      if (!is_string($clientId) || trim($clientId) === '') {
        continue;
      }
      $present = FALSE;
      $enabled = FALSE;
      $label = $clientId;
      if ($this->entityTypeManager->hasDefinition('consumer')) {
        $found = $this->entityTypeManager
          ->getStorage('consumer')
          ->loadByProperties(['client_id' => $clientId]);
        $consumer = $found ? reset($found) : NULL;
        if ($consumer instanceof ConsumerInterface) {
          $present = TRUE;
          $enabled = $consumer->isPublished();
          $label = (string) $consumer->label();
        }
      }
      $rows[] = [
        'id' => $clientId,
        'label' => $label,
        'present' => $present,
        'enabled' => $enabled,
      ];
    }
    return $rows;
  }

  /**
   * Counts Consumer entities when the type exists.
   */
  private function consumerCount(): int {
    if (!$this->entityTypeManager->hasDefinition('consumer')) {
      return 0;
    }
    return (int) $this->entityTypeManager->getStorage('consumer')->getQuery()
      ->accessCheck(FALSE)
      ->count()
      ->execute();
  }

  /**
   * Deep link to add a Consumer, else the OAuth settings tab.
   */
  private function addClientUrl(): string {
    if ($this->moduleHandler->moduleExists('consumers')) {
      $url = $this->safeUrl('entity.consumer.add_form');
      if ($url !== '') {
        return $url;
      }
      $url = $this->safeUrl('entity.consumer.collection');
      if ($url !== '') {
        return $url;
      }
    }
    return $this->safeUrl('mcp_sentinel.settings');
  }

  /**
   * Generates a route URL, or '' when the route is missing or forbidden.
   */
  private function safeUrl(string $routeName): string {
    try {
      $url = Url::fromRoute($routeName);
      if (!$url->access($this->currentUser)) {
        return '';
      }
      return $url->toString();
    }
    catch (\Throwable) {
      return '';
    }
  }

  /**
   * Compact age label for the last whoami timestamp.
   */
  private function ageLabel(int $timestamp): string {
    $delta = max(0, $this->time->getRequestTime() - $timestamp);
    if ($delta < 60) {
      return 'just now';
    }
    if ($delta < 3600) {
      $minutes = (int) floor($delta / 60);
      return $minutes === 1 ? '1 minute ago' : $minutes . ' minutes ago';
    }
    if ($delta < 86400) {
      $hours = (int) floor($delta / 3600);
      return $hours === 1 ? '1 hour ago' : $hours . ' hours ago';
    }
    $days = (int) floor($delta / 86400);
    return $days === 1 ? '1 day ago' : $days . ' days ago';
  }

}
