<?php

namespace Drupal\mcp_sentinel\Event;

use Drupal\Core\Entity\EntityInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Event fired when an MCP operation modifies a Drupal entity.
 *
 * Event names: mcp.entity.presave, mcp.entity.delete.
 */
class McpEntityEvent extends Event {

  public function __construct(
    private readonly EntityInterface $entity,
    private readonly string $eventName,
  ) {}

  /**
   * Gets the entity that changed.
   */
  public function getEntity(): EntityInterface {
    return $this->entity;
  }

  /**
   * Gets the MCP event name.
   */
  public function getEventName(): string {
    return $this->eventName;
  }

}
