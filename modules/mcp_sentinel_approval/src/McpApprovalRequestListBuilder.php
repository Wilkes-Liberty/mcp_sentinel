<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityListBuilder;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Form\FormBuilderInterface;
use Drupal\Core\Url;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Lists MCP approval requests, pending first.
 *
 * Provides requester, age, target, and reason columns. A simple GET status
 * filter is rendered above the table via the form builder. Pending requests
 * are always shown first so the actionable queue is at the top of the page.
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
   * The form builder (for the status filter form).
   */
  protected FormBuilderInterface $formBuilder;

  /**
   * The request stack (for reading filter query parameters).
   */
  protected RequestStack $requestStack;

  /**
   * The time service (for computing age intervals).
   */
  protected TimeInterface $time;

  /**
   * {@inheritdoc}
   */
  public static function createInstance(
    ContainerInterface $container,
    EntityTypeInterface $entity_type,
  ): static {
    $instance = parent::createInstance($container, $entity_type);
    $instance->dateFormatter = $container->get('date.formatter');
    $instance->userStorage = $container->get('entity_type.manager')
      ->getStorage('user');
    $instance->formBuilder = $container->get('form_builder');
    $instance->requestStack = $container->get('request_stack');
    $instance->time = $container->get('datetime.time');
    return $instance;
  }

  /**
   * {@inheritdoc}
   *
   * Returns entity IDs with pending requests first, then decided ones, both
   * newest-first. Optionally narrows to a single status from the request
   * query parameter ?status=.
   */
  protected function getEntityIds(): array {
    $requestStatus = trim(
      (string) $this->requestStack->getCurrentRequest()
        ->query->get('status', '')
    );

    if ($requestStatus !== '') {
      return array_values(
        $this->getStorage()->getQuery()
          ->accessCheck(TRUE)
          ->condition('status', $requestStatus)
          ->sort('id', 'DESC')
          ->execute()
      );
    }

    // Default: pending first (newest first within each group), then decided.
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
      'id'           => $this->t('ID'),
      'operation'    => $this->t('Operation'),
      'target'       => $this->t('Target'),
      'requested_by' => $this->t('Requested by'),
      'age'          => $this->t('Age'),
      'reason'       => $this->t('Reason'),
      'status'       => $this->t('Status'),
      'created'      => $this->t('Created'),
    ] + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity): array {
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $entity */
    $requester = $this->userStorage->load(
      (int) ($entity->get('requested_by')->target_id ?? 0)
    );
    $created = (int) ($entity->get('created')->value ?? 0);
    $now = $this->time->getRequestTime();
    $age = $created
      ? $this->dateFormatter->formatInterval($now - $created, 1)
      : $this->t('—');

    // Extract reason from the payload when available; fall back to '—'.
    $payload = $entity->getPayload();
    $reason = isset($payload['reason']) && $payload['reason'] !== ''
      ? (string) $payload['reason']
      : (string) $this->t('—');

    return [
      'id'           => $entity->id(),
      'operation'    => $entity->getOperation(),
      'target'       => $entity->getTargetEntityTypeId() . ':' . $entity->getTargetEntityId(),
      'requested_by' => $requester
        ? $requester->label()
        : $this->t('(unknown)'),
      'age'          => $age,
      'reason'       => $reason,
      'status'       => $entity->getStatus(),
      'created'      => $created
        ? $this->dateFormatter->format($created, 'short')
        : '',
    ] + parent::buildRow($entity);
  }

  /**
   * {@inheritdoc}
   *
   * The $cacheability parameter arrived in Drupal 11.3, which is this module's
   * D11 floor, so core passes it on every supported 11.x site and an override
   * without it silently drops what core handed down. It is optional here so the
   * signature stays valid on 10.6, where core calls this with one argument.
   *
   * These operations vary with nothing but the entity's own pending state, and
   * the list builder already carries that entity's cache tags — so there is
   * nothing to add. Accepting the parameter is what matters: it keeps the
   * override honest about the contract rather than quietly narrowing it.
   */
  public function getDefaultOperations(EntityInterface $entity, ?CacheableMetadata $cacheability = NULL): array {
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $entity */
    $operations = [];
    if ($entity->isPending()) {
      $operations['approve'] = [
        'title'  => $this->t('Approve'),
        'weight' => 0,
        'url'    => Url::fromRoute('mcp_sentinel_approval.approve', [
          'mcp_approval_request' => $entity->id(),
        ]),
      ];
      $operations['deny'] = [
        'title'  => $this->t('Deny'),
        'weight' => 1,
        'url'    => Url::fromRoute('mcp_sentinel_approval.deny', [
          'mcp_approval_request' => $entity->id(),
        ]),
      ];
    }
    return $operations;
  }

  /**
   * {@inheritdoc}
   *
   * Prepends a simple GET status filter form to the entity list table.
   */
  public function render(): array {
    $build = parent::render();

    $currentStatus = trim(
      (string) $this->requestStack->getCurrentRequest()
        ->query->get('status', '')
    );

    $statusOptions = [
      ''         => $this->t('— All statuses —'),
      'pending'  => $this->t('Pending'),
      'approved' => $this->t('Approved'),
      'denied'   => $this->t('Denied'),
    ];

    $filterForm = [
      '#type'   => 'container',
      '#prefix' => '<form method="get" class="mcp-approval-filter">',
      '#suffix' => '</form>',
      'status'  => [
        '#type'          => 'select',
        '#title'         => $this->t('Status'),
        '#options'       => $statusOptions,
        '#default_value' => $currentStatus,
        '#name'          => 'status',
        '#id'            => 'mcp-approval-filter-status',
      ],
      'submit' => [
        '#type'       => 'html_tag',
        '#tag'        => 'button',
        '#value'      => $this->t('Filter'),
        '#attributes' => ['type' => 'submit'],
      ],
    ];

    return [
      'filter' => $filterForm,
    ] + $build;
  }

}
