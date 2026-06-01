<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Entity;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Entity\Attribute\ConfigEntityType;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Form\McpPolicyProfileDeleteForm;
use Drupal\mcp_sentinel\Form\McpPolicyProfileForm;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\McpPolicyProfileListBuilder;

/**
 * The MCP Sentinel policy profile config entity.
 */
#[ConfigEntityType(
  id: 'mcp_policy_profile',
  label: new TranslatableMarkup('MCP policy profile'),
  label_collection: new TranslatableMarkup('MCP policy profiles'),
  label_singular: new TranslatableMarkup('MCP policy profile'),
  label_plural: new TranslatableMarkup('MCP policy profiles'),
  config_prefix: 'mcp_policy_profile',
  admin_permission: 'administer mcp sentinel',
  entity_keys: [
    'id' => 'id',
    'label' => 'label',
    'weight' => 'weight',
    'status' => 'status',
  ],
  handlers: [
    'list_builder' => McpPolicyProfileListBuilder::class,
    'form' => [
      'add' => McpPolicyProfileForm::class,
      'edit' => McpPolicyProfileForm::class,
      'delete' => McpPolicyProfileDeleteForm::class,
    ],
    'route_provider' => [
      'html' => 'Drupal\Core\Entity\Routing\AdminHtmlRouteProvider',
    ],
  ],
  links: [
    'collection' => '/admin/config/services/mcp-sentinel/profiles',
    'add-form' => '/admin/config/services/mcp-sentinel/profiles/add',
    'edit-form' => '/admin/config/services/mcp-sentinel/profiles/{mcp_policy_profile}',
    'delete-form' => '/admin/config/services/mcp-sentinel/profiles/{mcp_policy_profile}/delete',
  ],
  config_export: [
    'id',
    'label',
    'weight',
    'roles',
    'allow_read',
    'allow_write',
    'allow_delete',
    'allow_graphql_mutations',
    'allowed_entity_types',
    'denied_entity_types',
    'redacted_fields',
  ],
)]
final class McpPolicyProfile extends ConfigEntityBase implements McpPolicyProfileInterface {

  /**
   * The machine name.
   */
  protected string $id;

  /**
   * The human-readable label.
   */
  protected string $label;

  /**
   * Resolution weight; higher wins when several profiles match.
   */
  protected int $weight = 0;

  /**
   * Role IDs this profile applies to.
   *
   * @var string[]
   */
  protected array $roles = [];

  /**
   * Whether read operations are permitted.
   */
  protected bool $allow_read = TRUE;

  /**
   * Whether write (create/update) operations are permitted.
   */
  protected bool $allow_write = FALSE;

  /**
   * Whether delete operations are permitted.
   */
  protected bool $allow_delete = FALSE;

  /**
   * Whether GraphQL mutations are permitted.
   */
  protected bool $allow_graphql_mutations = FALSE;

  /**
   * Allowed entity type IDs (empty = all allowed).
   *
   * @var string[]
   */
  protected array $allowed_entity_types = [];

  /**
   * Denied entity type IDs.
   *
   * @var string[]
   */
  protected array $denied_entity_types = [];

  /**
   * Field machine names redacted from MCP responses.
   *
   * @var string[]
   */
  protected array $redacted_fields = [];

  /**
   * {@inheritdoc}
   */
  public function getRoles(): array {
    return array_values($this->roles);
  }

  /**
   * {@inheritdoc}
   */
  public function getWeight(): int {
    return (int) $this->weight;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsRead(): bool {
    return (bool) $this->allow_read;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsWrite(): bool {
    return (bool) $this->allow_write;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsDelete(): bool {
    return (bool) $this->allow_delete;
  }

  /**
   * {@inheritdoc}
   */
  public function allowsGraphqlMutations(): bool {
    return (bool) $this->allow_graphql_mutations;
  }

  /**
   * {@inheritdoc}
   */
  public function getAllowedEntityTypes(): array {
    return array_values(array_filter($this->allowed_entity_types));
  }

  /**
   * {@inheritdoc}
   */
  public function getDeniedEntityTypes(): array {
    return array_values(array_filter($this->denied_entity_types));
  }

  /**
   * {@inheritdoc}
   */
  public function getRedactedFields(): array {
    return array_values(array_filter($this->redacted_fields));
  }

}
