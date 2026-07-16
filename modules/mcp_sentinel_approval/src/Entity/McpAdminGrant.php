<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Entity;

use Drupal\Core\Entity\ContentEntityBase;
use Drupal\Core\Entity\EntityTypeInterface;
use Drupal\Core\Field\BaseFieldDefinition;
use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * Defines the time-boxed mcp_admin break-glass grant entity.
 *
 * Each row records a temporary grant of the break-glass admin role to a user.
 * The grant is non-standing: it carries an expiry, and a cron reaper revokes
 * role and marks the row revoked once the expiry passes. The entity gives an
 * admin list/audit surface for who currently holds break-glass and until when.
 *
 * Annotation rather than a #[ContentEntityType] attribute: attribute-based
 * entity types require Drupal 11.1, and on 10.6/11.0 an attribute yields no
 * entity type at all. See McpPolicyProfile for the full reasoning and the
 * condition for converting back.
 *
 * @ContentEntityType(
 *   id = "mcp_admin_grant",
 *   label = @Translation("MCP admin grant"),
 *   label_collection = @Translation("MCP admin grants"),
 *   label_singular = @Translation("MCP admin grant"),
 *   label_plural = @Translation("MCP admin grants"),
 *   base_table = "mcp_admin_grant",
 *   admin_permission = "approve mcp sentinel operations",
 *   entity_keys = {
 *     "id" = "id",
 *     "uuid" = "uuid",
 *     "label" = "id",
 *   },
 *   handlers = {
 *     "list_builder" = "Drupal\mcp_sentinel_approval\McpAdminGrantListBuilder",
 *     "route_provider" = {
 *       "html" = "Drupal\Core\Entity\Routing\AdminHtmlRouteProvider",
 *     },
 *   },
 *   links = {
 *     "collection" = "/admin/reports/mcp-sentinel/grants",
 *   },
 * )
 */
final class McpAdminGrant extends ContentEntityBase implements McpAdminGrantInterface {

  /**
   * {@inheritdoc}
   */
  public static function baseFieldDefinitions(EntityTypeInterface $entity_type): array {
    $fields = parent::baseFieldDefinitions($entity_type);

    $fields['uid'] = BaseFieldDefinition::create('entity_reference')
      ->setLabel(new TranslatableMarkup('Grantee'))
      ->setDescription(new TranslatableMarkup('The account granted the break-glass role.'))
      ->setSetting('target_type', 'user')
      ->setRequired(TRUE);

    $fields['granted'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(new TranslatableMarkup('Granted'))
      ->setDescription(new TranslatableMarkup('When the role was granted.'))
      ->setRequired(TRUE);

    $fields['expires'] = BaseFieldDefinition::create('timestamp')
      ->setLabel(new TranslatableMarkup('Expires'))
      ->setDescription(new TranslatableMarkup('When the grant expires and is auto-revoked.'))
      ->setRequired(TRUE);

    $fields['revoked'] = BaseFieldDefinition::create('boolean')
      ->setLabel(new TranslatableMarkup('Revoked'))
      ->setDescription(new TranslatableMarkup('Whether the role has been revoked.'))
      ->setDefaultValue(FALSE);

    return $fields;
  }

  /**
   * {@inheritdoc}
   */
  public function getUserId(): int {
    return (int) $this->get('uid')->target_id;
  }

  /**
   * {@inheritdoc}
   */
  public function getExpires(): int {
    return (int) $this->get('expires')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function isRevoked(): bool {
    return (bool) $this->get('revoked')->value;
  }

  /**
   * {@inheritdoc}
   */
  public function setRevoked(bool $revoked = TRUE): static {
    $this->set('revoked', $revoked);
    return $this;
  }

}
