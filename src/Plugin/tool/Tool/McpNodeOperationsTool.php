<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel\Service\McpContentLock;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\node\NodeInterface;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolBase;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Creates or updates nodes, with full field support, under MCP Sentinel policy.
 *
 * Every operation is gated by McpAccessChecker (entity-type allow/deny lists
 * and the global write switch), core entity access, and content locks.
 */
#[Tool(
  id: 'mcp_sentinel_node_operations',
  label: new TranslatableMarkup('Create or update a node'),
  description: new TranslatableMarkup('Creates or updates a node. Provide bundle + fields to create; provide id + fields to update. Respects MCP Sentinel policy, content locks, and field validation.'),
  operation: ToolOperation::Write,
  input_definitions: [
    'action' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Action'),
      description: new TranslatableMarkup('Either "create" or "update".'),
      required: TRUE,
      constraints: ['AllowedValues' => ['choices' => ['create', 'update']]],
    ),
    'bundle' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Content type'),
      description: new TranslatableMarkup('Node type machine name (required for create).'),
      required: FALSE,
    ),
    'id' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Node ID'),
      description: new TranslatableMarkup('Node ID or UUID (required for update).'),
      required: FALSE,
    ),
    'title' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Title'),
      description: new TranslatableMarkup('Node title.'),
      required: FALSE,
    ),
    'fields' => new InputDefinition(
      data_type: 'map',
      label: new TranslatableMarkup('Fields'),
      description: new TranslatableMarkup('Map of field machine name to value, e.g. {"body": {"value": "...", "format": "basic_html"}}.'),
      required: FALSE,
    ),
    'published' => new InputDefinition(
      data_type: 'boolean',
      label: new TranslatableMarkup('Published'),
      description: new TranslatableMarkup('Whether the node should be published.'),
      required: FALSE,
    ),
  ],
)]
final class McpNodeOperationsTool extends ToolBase {

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
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->entityTypeManager = $container->get('entity_type.manager');
    $instance->accessChecker = $container->get('mcp_sentinel.access_checker');
    $instance->contentLock = $container->get('mcp_sentinel.content_lock');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    // Resolve the profile and enforce the rate limit before any business logic
    // so throttled agents are blocked regardless of input validity.
    $profile = $this->policyResolver->resolve($this->currentUser);
    if ($profile === NULL) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied: no governance profile applies to this account.'));
    }
    if ($rateLimited = $this->checkRateLimit($profile, 'mcp_sentinel_node_operations')) {
      return $rateLimited;
    }
    return ($values['action'] ?? '') === 'create'
      ? $this->createNode($values, $profile)
      : $this->updateNode($values, $profile);
  }

  /**
   * Creates a node.
   *
   * @param array $values
   *   Tool input values.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The already-resolved policy profile.
   *
   * @return \Drupal\tool\ExecutableResult
   *   The execution result.
   */
  private function createNode(array $values, McpPolicyProfileInterface $profile): ExecutableResult {
    $bundle = $values['bundle'] ?? '';
    if ($bundle === '') {
      return ExecutableResult::failure($this->t('A bundle (content type) is required to create a node.'));
    }
    $storage = $this->entityTypeManager->getStorage('node');

    /** @var \Drupal\node\NodeInterface $node */
    $node = $storage->create([
      'type' => $bundle,
      'title' => $values['title'] ?? '',
      'uid' => $this->currentUser->id(),
    ]);

    $policyResult = $this->accessChecker->checkEntityAccess($node, 'create', $profile);
    if ($policy = $this->denyReason($policyResult)) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied node creation: @reason', ['@reason' => $policy]));
    }
    $core = $this->entityTypeManager->getAccessControlHandler('node')->createAccess($bundle, $this->currentUser, [], TRUE);
    if (!$core->isAllowed()) {
      return ExecutableResult::failure($this->t('You do not have permission to create @bundle nodes.', ['@bundle' => $bundle]));
    }

    return $this->applyAndSave($node, $values, $this->t('created'));
  }

  /**
   * Updates a node.
   *
   * @param array $values
   *   Tool input values.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The already-resolved policy profile.
   *
   * @return \Drupal\tool\ExecutableResult
   *   The execution result.
   */
  private function updateNode(array $values, McpPolicyProfileInterface $profile): ExecutableResult {
    $node = $this->loadNode((string) ($values['id'] ?? ''));
    if (!$node instanceof NodeInterface) {
      return ExecutableResult::failure($this->t('Node "@id" not found.', ['@id' => $values['id'] ?? '']));
    }
    if ($this->contentLock->isLocked('node', (string) $node->id())) {
      return ExecutableResult::failure($this->t('Node @id is locked against MCP writes (a human may be editing it).', ['@id' => $node->id()]));
    }
    $policyResult = $this->accessChecker->checkEntityAccess($node, 'update', $profile);
    if ($policy = $this->denyReason($policyResult)) {
      return ExecutableResult::failure($this->t('MCP Sentinel denied the update: @reason', ['@reason' => $policy]));
    }
    if (!$node->access('update', $this->currentUser)) {
      return ExecutableResult::failure($this->t('You do not have permission to edit this node.'));
    }
    if (isset($values['title'])) {
      $node->setTitle($values['title']);
    }
    return $this->applyAndSave($node, $values, $this->t('updated'));
  }

  /**
   * Applies fields + published state, validates, and saves the node.
   */
  private function applyAndSave(NodeInterface $node, array $values, TranslatableMarkup $verb): ExecutableResult {
    try {
      foreach (($values['fields'] ?? []) as $name => $value) {
        if ($node->hasField($name)) {
          $node->set($name, $value);
        }
      }
      if (isset($values['published'])) {
        $values['published'] ? $node->setPublished() : $node->setUnpublished();
      }
      if ($violations = $this->validationMessages($node)) {
        return ExecutableResult::failure($this->t('Validation failed: @errors', ['@errors' => implode('; ', $violations)]));
      }
      $node->save();
    }
    catch (\Exception $e) {
      return ExecutableResult::failure($this->t('Failed to save node: @message', ['@message' => $e->getMessage()]));
    }

    return ExecutableResult::success(
      $this->t('Node @verb.', ['@verb' => $verb]),
      ['id' => $node->id(), 'uuid' => $node->uuid(), 'bundle' => $node->bundle(), 'title' => $node->label()],
    );
  }

  /**
   * Loads a node by numeric ID or UUID.
   */
  private function loadNode(string $id): ?NodeInterface {
    if ($id === '') {
      return NULL;
    }
    $storage = $this->entityTypeManager->getStorage('node');
    if (ctype_digit($id)) {
      $node = $storage->load($id);
    }
    else {
      $nodes = $storage->loadByProperties(['uuid' => $id]);
      $node = $nodes ? reset($nodes) : NULL;
    }
    return $node instanceof NodeInterface ? $node : NULL;
  }

  /**
   * {@inheritdoc}
   */
  protected function checkAccess(array $values, AccountInterface $account, bool $return_as_object = FALSE): bool|AccessResultInterface {
    $access = AccessResult::allowedIfHasPermission($account, 'access mcp sentinel context');
    return $return_as_object ? $access : $access->isAllowed();
  }

}
