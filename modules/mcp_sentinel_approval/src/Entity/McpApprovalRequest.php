<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Entity;

use Drupal\Core\Entity\Attribute\ContentEntityType;
use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel_approval\McpApprovalRequestListBuilder;

/**
 * Defines the MCP approval request content entity.
 *
 * Each row records a governed destructive operation that was queued for human
 * approval instead of executing immediately. An authorized human approves or
 * denies it; on approval the stored operation is replayed.
 */
#[ContentEntityType(
  id: 'mcp_approval_request',
  label: new TranslatableMarkup('MCP approval request'),
  label_collection: new TranslatableMarkup('MCP approval requests'),
  label_singular: new TranslatableMarkup('MCP approval request'),
  label_plural: new TranslatableMarkup('MCP approval requests'),
  base_table: 'mcp_approval_request',
  admin_permission: 'approve mcp sentinel operations',
  entity_keys: [
    'id' => 'id',
    'uuid' => 'uuid',
    'label' => 'id',
  ],
  handlers: [
    'list_builder' => McpApprovalRequestListBuilder::class,
    'route_provider' => [
      'html' => 'Drupal\Core\Entity\Routing\AdminHtmlRouteProvider',
    ],
  ],
  links: [
    'collection' => '/admin/reports/mcp-sentinel/approvals',
  ],
)]
final class McpApprovalRequest extends ContentEntityBase implements McpApprovalRequestInterface {

  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type): array {
    $fields = parent::baseFieldDefinitions($entity_type);

    $fields['requested_by'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(new TranslatableMarkup('Requested by'))
      ->setDescription(new TranslatableMarkup('The governed account that requested the operation.'))
      ->setSetting('target_type', 'user')
      ->setRequired(TRUE);

    $fields['operation'] = BaseFieldDefinition::create('string')
      ->setLabel(new TranslatableMarkup('Operation'))
      ->setDescription(new TranslatableMarkup('The destructive operation identifier (e.g. delete).'))
      ->setSetting('max_length', 64)
      ->setRequired(TRUE);

    $fields['entity_type'] = BaseFieldDefinition::create('string')
      ->setLabel(new TranslatableMarkup('Target entity type'))
      ->setSetting('max_length', 64)
      ->setRequired(TRUE);

    $fields['entity_id'] = BaseFieldDefinition::create('string')
      ->setLabel(new TranslatableMarkup('Target entity ID'))
      ->setSetting('max_length', 255)
      ->setRequired(TRUE);

    $fields['payload'] = BaseFieldDefinition::create('string_long')
      ->setLabel(new TranslatableMarkup('Payload'))
      ->setDescription(new TranslatableMarkup('JSON-encoded replay data for the operation.'));

    $fields['status'] = BaseFieldDefinition::create('string')
      ->setLabel(new TranslatableMarkup('Status'))
      ->setSetting('max_length', 32)
      ->setDefaultValue(McpApprovalRequestInterface::STATUS_PENDING)
      ->setRequired(TRUE);

    $fields['created'] = BaseFieldDefinition::create('created')
      ->setLabel(new TranslatableMarkup('Created'));

    $fields['decided_by'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(new TranslatableMarkup('Decided by'))
      ->setDescription(new TranslatableMarkup('The account that approved or denied the request.'))
      ->setSetting('target_type', 'user');

    $fields['decided'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(new TranslatableMarkup('Decided'))
      ->setDescription(new TranslatableMarkup('When the request was approved or denied.'));

    return $fields;
  }

  /**
   * {@inheritdoc}
   */
  public function getOperation(): string {
    return (string) $this->get('operation')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getTargetEntityTypeId(): string {
    return (string) $this->get('entity_type')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getTargetEntityId(): string {
    return (string) $this->get('entity_id')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function getPayload(): array {
    $raw = (string) ($this->get('payload')->value ?? '');
    if ($raw === '') {
      return [];
    }
    $decoded = json_decode($raw, TRUE);
    return is_array($decoded) ? $decoded : [];
  }

  /**
   * {@inheritdoc}
   */
  public function getStatus(): string {
    return (string) $this->get('status')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function setStatus(string $status): static {
    $this->set('status', $status);
    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public function isPending(): bool {
    return $this->getStatus() === McpApprovalRequestInterface::STATUS_PENDING;
  }

  /**
   * {@inheritdoc}
   */
  public function setDecision(int $uid, int $timestamp): static {
    $this->set('decided_by', $uid);
    $this->set('decided', $timestamp);
    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public static function preCreate(EntityStorageInterface $storage, array &$values): void {
    parent::preCreate($storage, $values);
    $values += ['status' => McpApprovalRequestInterface::STATUS_PENDING];
  }

}
