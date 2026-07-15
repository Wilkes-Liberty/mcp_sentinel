<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityListBuilder;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Lists time-boxed mcp_admin break-glass grants, active first.
 *
 * A read-only audit surface answering "who holds break-glass right now, and
 * until when?". Revocation is handled by the cron reaper (and the role removal
 * it performs), so this list intentionally exposes no row operations.
 */
final class McpAdminGrantListBuilder extends EntityListBuilder {

  /**
   * The date formatter.
   */
  protected DateFormatterInterface $dateFormatter;

  /**
   * The user storage (for resolving grantee labels).
   */
  protected EntityStorageInterface $userStorage;

  /**
   * The time service (for the active/expired determination).
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
    $instance->time = $container->get('datetime.time');
    return $instance;
  }

  /**
   * {@inheritdoc}
   *
   * Active (non-revoked, not-yet-expired) grants first, then expired, then
   * revoked.
   */
  protected function getEntityIds(): array {
    return array_values(
      $this->getStorage()->getQuery()
        ->accessCheck(TRUE)
        ->sort('revoked', 'ASC')
        ->sort('expires', 'DESC')
        ->sort('id', 'DESC')
        ->pager($this->limit)
        ->execute()
    );
  }

  /**
   * {@inheritdoc}
   */
  public function buildHeader(): array {
    return [
      'id'      => $this->t('ID'),
      'grantee' => $this->t('Grantee'),
      'granted' => $this->t('Granted'),
      'expires' => $this->t('Expires'),
      'status'  => $this->t('Status'),
    ] + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity): array {
    /** @var \Drupal\mcp_sentinel_approval\Entity\McpAdminGrantInterface $entity */
    $grantee = $this->userStorage->load($entity->getUserId());
    $granted = (int) ($entity->get('granted')->value ?? 0);
    $expires = $entity->getExpires();
    $now = $this->time->getRequestTime();

    if ($entity->isRevoked()) {
      $status = $this->t('Revoked');
    }
    elseif ($expires > 0 && $expires <= $now) {
      $status = $this->t('Expired (pending reap)');
    }
    else {
      $status = $this->t('Active — expires in @interval', [
        '@interval' => $this->dateFormatter->formatInterval(max(0, $expires - $now), 1),
      ]);
    }

    return [
      'id'      => $entity->id(),
      'grantee' => $grantee ? $grantee->label() : $this->t('(unknown)'),
      'granted' => $granted
        ? $this->dateFormatter->format($granted, 'short')
        : $this->t('—'),
      'expires' => $expires
        ? $this->dateFormatter->format($expires, 'short')
        : $this->t('—'),
      'status'  => $status,
    ] + parent::buildRow($entity);
  }

}
