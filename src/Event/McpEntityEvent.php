<?php

namespace Drupal\mcp_sentinel\Event;

use Drupal\Core\Entity\EntityInterface;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Notifies subscribers that an MCP operation has modified a Drupal entity.
 *
 * Unlike McpDestructiveOpEvent, this event is purely informational: it is fired
 * after a change has occurred and carries no veto mechanism. Subscribers use it
 * for side effects such as audit logging or outbound webhook dispatch. The
 * concrete event name (passed to the constructor and returned by
 * getEventName()) is one of 'mcp.entity.presave' or 'mcp.entity.delete'.
 */
class McpEntityEvent extends Event {

  /**
   * Constructs an McpEntityEvent.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity that was created, updated, or deleted by the operation.
   * @param string $eventName
   *   The MCP event name, e.g. 'mcp.entity.presave' or 'mcp.entity.delete'.
   */
  public function __construct(
    private readonly EntityInterface $entity,
    private readonly string $eventName,
  ) {}

  /**
   * Gets the entity that changed.
   *
   * @return \Drupal\Core\Entity\EntityInterface
   *   The affected entity.
   */
  public function getEntity(): EntityInterface {
    return $this->entity;
  }

  /**
   * Gets the MCP event name describing the kind of change.
   *
   * @return string
   *   The event name, e.g. 'mcp.entity.presave' or 'mcp.entity.delete'.
   */
  public function getEventName(): string {
    return $this->eventName;
  }

}
