<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval;

use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityListBuilder;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Lists MCP approval requests, pending first.
 */
final class McpApprovalRequestListBuilder extends EntityListBuilder {

  /**
   * The date formatter.
   */
  protected DateFormatterInterface $dateFormatter;

  /**
   * The user storage (for resolving requester labels).
   */
  protected EntityStorageInterface $userStorage;

  /**
   * {@inheritdoc}
   */
  public static function createInstance(ContainerInterface $container, EntityTypeInterface $entity_type): static {
    $instance = parent::createInstance($container, $entity_type);
    $instance->dateFormatter = $container->get('date.formatter');
    $instance->userStorage = $container->get('entity_type.manager')->getStorage('user');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function getEntityIds(): array {
    // List pending requests first (newest first), then decided ones, so the
    // queue an operator must act on is always at the top of the page.
    $pending = $this->getStorage()->getQuery()
      ->accessCheck(TRUE)
      ->condition('status', 'pending')
      ->sort('id', 'DESC')
      ->execute();
    $decided = $this->getStorage()->getQuery()
      ->accessCheck(TRUE)
      ->condition('status', 'pending', '<>')
      ->sort('id', 'DESC')
      ->execute();
    return array_merge(array_values($pending), array_values($decided));
  }

  /**
   * {@inheritdoc}
   */
  public function buildHeader(): array {
    return [
      'id'        => $this->t('ID'),
      'operation' => $this->t('Operation'),
      'target'    => $this->t('Target'),
      'requested_by' => $this->t('Requested by'),
      'status'    => $this->t('Status'),
      'created'   => $this->t('Created'),
    ] + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity): array {
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $entity */
    $requester = $this->userStorage->load((int) ($entity->get('requested_by')->target_id ?? 0));
    $created = (int) ($entity->get('created')->value ?? 0);
    return [
      'id'        => $entity->id(),
      'operation' => $entity->getOperation(),
      'target'    => $entity->getTargetEntityTypeId() . ':' . $entity->getTargetEntityId(),
      'requested_by' => $requester ? $requester->label() : $this->t('(unknown)'),
      'status'    => $entity->getStatus(),
      'created'   => $created ? $this->dateFormatter->format($created, 'short') : '',
    ] + parent::buildRow($entity);
  }

  /**
   * {@inheritdoc}
   */
  public function getDefaultOperations(EntityInterface $entity): array {
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $entity */
    $operations = [];
    if ($entity->isPending()) {
      $operations['approve'] = [
        'title'  => $this->t('Approve'),
        'weight' => 0,
        'url'    => Url::fromRoute('mcp_sentinel_approval.approve', ['mcp_approval_request' => $entity->id()]),
      ];
      $operations['deny'] = [
        'title'  => $this->t('Deny'),
        'weight' => 1,
        'url'    => Url::fromRoute('mcp_sentinel_approval.deny', ['mcp_approval_request' => $entity->id()]),
      ];
    }
    return $operations;
  }

}
