<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\Core\Entity\FieldableEntityInterface;

/**
 * Shared helpers for MCP Sentinel content tool plugins.
 */
trait McpEntityToolTrait {

  /**
   * Returns the denial reason for a forbidden access result, or NULL.
   */
  protected function denyReason(AccessResultInterface $result): ?string {
    if (!$result->isForbidden()) {
      return NULL;
    }
    return $result instanceof AccessResultReasonInterface && $result->getReason()
      ? (string) $result->getReason()
      : 'denied by policy';
  }

  /**
   * Validates an entity and returns human-readable violation messages.
   *
   * @return string[]
   *   Violation messages (empty when the entity is valid).
   */
  protected function validationMessages(FieldableEntityInterface $entity): array {
    $messages = [];
    foreach ($entity->validate() as $violation) {
      $messages[] = $violation->getPropertyPath() . ': ' . strip_tags((string) $violation->getMessage());
    }
    return $messages;
  }

}
