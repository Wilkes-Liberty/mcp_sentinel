<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\content_moderation\ModerationInformationInterface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Exception\RequirementsException;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Transitions a moderated entity to a new Content Moderation state.
 *
 * Requires the Content Moderation module. The transition is validated against
 * the entity's workflow, MCP Sentinel policy, core access, and content locks.
 */
#[Tool(
  id: 'mcp_sentinel_workflow_transition',
  label: new TranslatableMarkup('Transition moderation state'),
  description: new TranslatableMarkup('Moves a Content Moderation-managed entity to a new state (e.g. draft, published, archived). The transition must be valid for the configured workflow and permitted by policy.'),
  operation: ToolOperation::Trigger,
  input_definitions: [
    'entity_type' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Entity type'),
      description: new TranslatableMarkup('Entity type ID. Defaults to node.'),
      required: FALSE,
      default_value: 'node',
    ),
    'id' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Entity ID'),
      description: new TranslatableMarkup('The entity ID to transition.'),
      required: TRUE,
    ),
    'state' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Target state'),
      description: new TranslatableMarkup('Machine name of the target moderation state.'),
      required: TRUE,
    ),
  ],
)]
final class McpWorkflowTransitionTool extends ToolBase {

  use McpEntityToolTrait;

  /**
   * The entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * The MCP Sentinel access checker.
   */
  protected McpAccessChecker $accessChecker;

  /**
   * The MCP Sentinel content lock service.
   */
  protected McpContentLock $contentLock;

  /**
   * The MCP Sentinel policy resolver.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * The moderation information service, if Content Moderation is installed.
   */
  protected ?ModerationInformationInterface $moderationInformation = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->contentLock = $container->get('mcp_sentinel.content_lock');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    // Content Moderation is optional; the service only exists when it is on.
    // @phpstan-ignore-next-line phpstan-drupal treats $container->has() as always true.
    if ($container->has('content_moderation.moderation_information')) {
      $instance->moderationInformation = $container->get('content_moderation.moderation_information');
    }
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function checkRequirements(): void {
    if ($this->moderationInformation === NULL) {
      throw new RequirementsException('The Content Moderation module is not installed.');
    }
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    if ($this->moderationInformation === NULL) {
      return ExecutableResult::failure($this->t('Content Moderation is not installed.'));
    }
    $entity_type = $values['entity_type'] ?? 'node';
    $id = (string) ($values['id'] ?? '');
    $state = $values['state'] ?? '';

    if (!$this->entityTypeManager->hasDefinition($entity_type)) {
      return ExecutableResult::failure($this->t('Unknown entity type "@type".', ['@type' => $entity_type]));
    }
    // Resolve profile and enforce rate limit before any DB reads so that an
    // over-limit agent is throttled without paying the entity-load cost.
    $profile = $this->policyResolver->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied: no governance profile applies to this account.'));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_workflow_transition')) {
      return $rateLimited;
    }
    $entity = $this->entityTypeManager->getStorage($entity_type)->load($id);
    if (!$entity instanceof ContentEntityInterface) {
      return ExecutableResult::failure($this->t('@type "@id" not found.', ['@type' => $entity_type, '@id' => $id]));
    }
    if (!$this->moderationInformation->isModeratedEntity($entity)) {
      return ExecutableResult::failure($this->t('This entity is not under Content Moderation.'));
    }
    if ($this->contentLock->isLocked($entity_type, $id)) {
      return ExecutableResult::failure($this->t('Entity @id is locked against MCP writes.', ['@id' => $id]));
    }
    $policyResult = $this->accessChecker->checkEntityAccess($entity, 'update', $profile);
    if ($reason = $this->denyReason($policyResult)) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied the transition: @reason', ['@reason' => $reason]));
    }
    if (!$entity->access('update', $this->currentUser)) {
      return ExecutableResult::failure($this->t('You do not have permission to update this entity.'));
    }

    $from = $entity->get('moderation_state')->value;
    try {
      $entity->set('moderation_state', $state);
      // The ModerationState constraint validates the transition.
      if ($violations = $this->validationMessages($entity)) {
        return ExecutableResult::failure($this->t('Invalid transition: @errors', ['@errors' => implode('; ', $violations)]));
      }
      $entity->save();
    }
    catch (\Exception $e) {
      return ExecutableResult::failure($this->t('Transition failed: @message', ['@message' => $e->getMessage()]));
    }

    return ExecutableResult::success(
      $this->t('Moderation state changed from @from to @to.', ['@from' => $from, '@to' => $state]),
      ['id' => $entity->id(), 'entity_type' => $entity_type, 'from_state' => $from, 'to_state' => $state],
    );
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    return $return_as_object ? $access : $access->isAllowed();
  }

}
