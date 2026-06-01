<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel;

use Drupal\Core\Config\Entity\ConfigEntityListBuilder;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Lists MCP Sentinel policy profiles on the admin overview page.
 */
final class McpPolicyProfileListBuilder extends ConfigEntityListBuilder {

  /**
   * The user role storage.
   */
  protected EntityStorageInterface $roleStorage;

  /**
   * {@inheritdoc}
   */
  public static function createInstance(ContainerInterface $container, EntityTypeInterface $entity_type): static {
    $instance = parent::createInstance($container, $entity_type);
    $instance->roleStorage = $container->get('entity_type.manager')->getStorage('user_role');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function buildHeader(): array {
    return [
      'label' => $this->t('Profile'),
      'roles' => $this->t('Roles'),
      'weight' => $this->t('Weight'),
    ] + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity): array {
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $entity */
    $roles = $entity->getRoles();
    $labels = [];
    foreach ($roles as $rid) {
      $role = $this->roleStorage->load($rid);
      $labels[] = $role ? (string) $role->label() : $rid;
    }
    return [
      'label' => $entity->label(),
      'roles' => $labels
        ? implode(', ', $labels)
        : $this->t('(default — all governed roles)'),
      'weight' => $entity->getWeight(),
    ] + parent::buildRow($entity);
  }

}
