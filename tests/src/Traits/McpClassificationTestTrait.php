<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel-test helpers for the classification egress tests (d.o #3616540).
 *
 * The three things every seam test needs: a way to make a request current
 * without losing the kernel's master request (and its session), a way to set
 * the default profile's ceilings with every cache cleared, and the decoded
 * classification evidence rows with the columns audit_chain lifts out of the
 * metadata folded back in.
 */
trait McpClassificationTestTrait {

  /**
   * Whether a request of this test's own is on top of the stack.
   */
  private bool $pushedRequest = FALSE;

  /**
   * Makes a request current, keeping the kernel's master request underneath.
   *
   * Only the request this helper pushed last time is replaced; the master
   * request stays at the bottom so anything that needs its session still
   * finds one.
   */
  protected function pushRequest(Request $request): void {
    $stack = $this->container->get('request_stack');
    if ($this->pushedRequest) {
      $stack->pop();
    }
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    $this->pushedRequest = TRUE;
    if (\Drupal::entityTypeManager()->hasDefinition('node')) {
      \Drupal::entityTypeManager()->getAccessControlHandler('node')->resetCache();
    }
  }

  /**
   * Builds and pushes a request for a path with optional headers/attributes.
   */
  protected function onRequest(string $path, array $headers = [], array $attributes = [], string $method = 'GET'): Request {
    $request = Request::create($path, $method);
    foreach ($headers as $name => $value) {
      $request->headers->set($name, $value);
    }
    foreach ($attributes as $name => $value) {
      $request->attributes->set($name, $value);
    }
    $this->pushRequest($request);
    return $request;
  }

  /**
   * Sets a profile's ceilings and clears every cache that could hide it.
   *
   * @param array<string, string> $ceilings
   *   Surface value => label.
   * @param string $profileId
   *   The profile to edit.
   */
  protected function setCeilings(array $ceilings, string $profileId = 'default'): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.' . $profileId)
      ->set('egress_ceilings', $ceilings)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    if (\Drupal::entityTypeManager()->hasDefinition('node')) {
      \Drupal::entityTypeManager()->getAccessControlHandler('node')->resetCache();
    }
  }

  /**
   * Decoded classification evidence rows, oldest first.
   *
   * The audit_chain module lifts entity_type/bundle/id/label into columns;
   * the columns are folded back so a row reads as one map.
   */
  protected function evidenceRows(): array {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $rows = [];
    $result = $this->container->get('database')->select('audit_chain_log', 'a')
      ->fields('a', ['operation', 'entity_type', 'bundle', 'entity_id', 'entity_label', 'metadata'])
      ->condition('operation', McpClassificationResolver::DENIAL_CODE)
      ->orderBy('id')
      ->execute();
    foreach ($result as $record) {
      $rows[] = $logger->decodeMetadata((string) $record->metadata) + [
        'entity_type' => $record->entity_type,
        'bundle' => $record->bundle,
        'entity_id' => (string) $record->entity_id,
        'entity_label' => $record->entity_label,
      ];
    }
    return $rows;
  }

}
