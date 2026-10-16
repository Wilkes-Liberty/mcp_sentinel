<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpEntityFieldReservedAllowlist;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Exception\RequirementsException;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Creates a media entity under MCP Sentinel policy.
 *
 * The source value populates the media type's configured source field — a file
 * ID for file/image media, or a URL for oEmbed (remote video) media. Gated by
 * McpAccessChecker and core access.
 */
#[Tool(
  id: 'mcp_sentinel_media_create',
  label: new TranslatableMarkup('Create a media entity'),
  description: new TranslatableMarkup('Creates a media entity of a given type. Provide the source value for the media type source field (a file ID for image/file media, a URL for remote video). Respects MCP Sentinel policy.'),
  operation: ToolOperation::Write,
  input_definitions: [
    'bundle' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Media type'),
      description: new TranslatableMarkup('Media type machine name, e.g. image or remote_video.'),
      required: TRUE,
    ),
    'name' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Name'),
      description: new TranslatableMarkup('The media entity name/label.'),
      required: TRUE,
    ),
    'source_value' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Source value'),
      description: new TranslatableMarkup('Value for the source field: a file ID for file/image media, or a URL for oEmbed media.'),
      required: TRUE,
    ),
    'fields' => new InputDefinition(
      data_type: 'map',
      label: new TranslatableMarkup('Additional fields'),
      description: new TranslatableMarkup('Map of additional field machine name to value.'),
      required: FALSE,
    ),
  ],
)]
final class McpMediaUploadTool extends McpGovernedToolBase {

  use McpEntityToolTrait;

  /**
   * Storage for the media entity this tool creates.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * Field-definition allowlist for the fields map.
   */
  protected McpEntityFieldReservedAllowlist $fieldReservedAllowlist;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->fieldReservedAllowlist = $container->get('mcp_sentinel.entity_field_reserved_allowlist');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function reservedNestedMapAllowlists(array $values): array {
    $bundle = $values['bundle'] ?? '';
    if (!is_string($bundle) || $bundle === '') {
      return [];
    }
    return [
      'fields' => $this->fieldReservedAllowlist->forBundle('media', $bundle),
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function checkRequirements(): void {
    if (!$this->entityTypeManager->hasDefinition('media')) {
      throw new RequirementsException('The Media module is not installed.');
    }
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $bundle = $values['bundle'] ?? '';
    $media_type = $this->entityTypeManager->getStorage('media_type')->load($bundle);
    if ($media_type === NULL) {
      return ExecutableResult::failure($this->t('Unknown media type "@type".', ['@type' => $bundle]));
    }

    $source_field = $media_type->getSource()->getSourceFieldDefinition($media_type)?->getName();
    if (!$source_field) {
      return ExecutableResult::failure($this->t('Media type "@type" has no configured source field.', ['@type' => $bundle]));
    }

    /** @var \Drupal\media\MediaInterface $media */
    $media = $this->entityTypeManager->getStorage('media')->create([
      'bundle' => $bundle,
      'name' => $values['name'] ?? '',
      'uid' => $this->currentUser->id(),
    ]);

    $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('@msg', [
        '@msg' => $this->governanceDenyExplainer?->refuse(
          'MCP Sentinel denied: no governance profile applies to this account.',
        ) ?? McpDenyExplainer::CALLER_MESSAGE,
      ]));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_media_create')) {
      return $rateLimited;
    }
    $policyResult = $this->governanceAccessChecker->checkEntityAccess($media, 'create', $profile, FALSE);
    if ($reason = $this->denyReason($policyResult)) {
      $this->logDeniedAccess('mcp_sentinel_media_create', 'media', '(new)', 'create', $reason);
      return ExecutableResult::failure($this->t('MCP access is denied.'));
    }
    $core = $this->entityTypeManager->getAccessControlHandler('media')->createAccess($bundle, $this->currentUser, [], TRUE);
    if (!$core->isAllowed()) {
      $this->logDeniedAccess('mcp_sentinel_media_create', 'media', '(new)', 'create', 'core access denied');
      return ExecutableResult::failure($this->t('You do not have permission to create @bundle media.', ['@bundle' => $bundle]));
    }

    // Media is published by default, which under a deny-publish profile would
    // be a go-live the agent never asked for — the publish gate reports it as a
    // violation and the upload fails. Create the item unpublished instead, so
    // the tool states the invariant it has always relied on (an agent uploads,
    // a human publishes) rather than depending on the presave backstop to
    // silently rewrite the status after the fact.
    if ($profile->deniesPublish()) {
      $media->setUnpublished();
    }

    try {
      $media->set($source_field, $values['source_value'] ?? '');
      foreach (($values['fields'] ?? []) as $name => $value) {
        if ($media->hasField($name)) {
          $media->set($name, $value);
        }
      }
      if ($violations = $this->validationMessages($media)) {
        return ExecutableResult::failure($this->t('Validation failed: @errors', ['@errors' => implode('; ', $violations)]));
      }
      $media->save();
    }
    catch (\Exception $e) {
      return ExecutableResult::failure($this->t('@msg', [
        '@msg' => $this->governanceDenyExplainer?->refuse(
          'Failed to create media: ' . $e->getMessage(),
        ) ?? McpDenyExplainer::CALLER_MESSAGE,
      ]));
    }

    return ExecutableResult::success(
      $this->t('Media created.'),
      ['id' => $media->id(), 'uuid' => $media->uuid(), 'bundle' => $media->bundle(), 'name' => $media->label()],
    );
  }

}
