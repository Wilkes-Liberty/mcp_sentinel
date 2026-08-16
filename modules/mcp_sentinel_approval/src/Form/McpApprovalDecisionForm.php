<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Form;

use Drupal\Core\Form\ConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\mcp_sentinel_approval\Service\McpApprovalExecutor;
use Drupal\mcp_sentinel_approval\Service\McpReviewerContext;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Confirm form to approve or deny an MCP approval request.
 *
 * The decision (approve|deny) is fixed per route via the buildForm $decision
 * argument supplied by the routing definition.
 */
final class McpApprovalDecisionForm extends ConfirmFormBase {

  /**
   * The approval request being decided.
   */
  protected ?McpApprovalRequestInterface $request = NULL;

  /**
   * The decision: 'approve' or 'deny'.
   */
  protected string $decision = 'approve';

  /**
   * Constructs the form.
   *
   * Protected and NOT readonly, both deliberately. FormBase brings in
   * DependencySerializationTrait, whose __wakeup() cannot restore a private
   * property from a child class — and on PHP below 8.4 cannot reinitialize a
   * readonly one either, because it is out of the declaring scope. Drupal
   * caches form objects and unserializes them on rebuild, so either modifier
   * is a fatal on supported PHP rather than a style preference.
   * menu_autopilot 1.0.1 fixed the same defect.
   *
   * @param \Drupal\mcp_sentinel_approval\Service\McpApprovalExecutor $executor
   *   The approval executor service.
   * @param \Drupal\mcp_sentinel_approval\Service\McpReviewerContext $reviewerContext
   *   Builds the sealed-vs-live context the reviewer must see.
   */
  public function __construct(
    protected McpApprovalExecutor $executor,
    protected McpReviewerContext $reviewerContext,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('mcp_sentinel_approval.executor'),
      $container->get('mcp_sentinel_approval.reviewer_context'),
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'mcp_approval_decision_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, ?McpApprovalRequestInterface $mcp_approval_request = NULL, string $decision = 'approve'): array {
    $this->request = $mcp_approval_request;
    $this->decision = $decision === 'deny' ? 'deny' : 'approve';
    $form = parent::buildForm($form, $form_state);
    if ($this->request === NULL) {
      return $form;
    }
    $context = $this->reviewerContext->build($this->request);
    $form['reviewer_context'] = $this->reviewerContext->toRenderArray($context);
    if ($this->decision === 'approve' && empty($context['visible'])) {
      $form['actions']['submit']['#access'] = FALSE;
    }
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    if ($this->request === NULL) {
      return $this->t('Decide on this request?');
    }
    return $this->decision === 'deny'
      ? $this->t('Deny request #@id (@op on @target)?', [
        '@id' => $this->request->id(),
        '@op' => $this->request->getOperation(),
        '@target' => $this->request->getTargetEntityTypeId() . ':' . $this->request->getTargetEntityId(),
      ])
      : $this->t('Approve request #@id (@op on @target)? This will execute the operation.', [
        '@id' => $this->request->id(),
        '@op' => $this->request->getOperation(),
        '@target' => $this->request->getTargetEntityTypeId() . ':' . $this->request->getTargetEntityId(),
      ]);
  }

  /**
   * {@inheritdoc}
   */
  public function getConfirmText() {
    return $this->decision === 'deny' ? $this->t('Deny') : $this->t('Approve');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelUrl(): Url {
    return Url::fromRoute('entity.mcp_approval_request.collection');
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    if ($this->request === NULL || !$this->request->isPending()) {
      $this->messenger()->addWarning($this->t('Request is not pending; no action taken.'));
      $form_state->setRedirectUrl($this->getCancelUrl());
      return;
    }

    if ($this->decision === 'deny') {
      $this->executor->deny($this->request);
      $this->messenger()->addStatus($this->t('Request #@id denied.', ['@id' => $this->request->id()]));
    }
    else {
      $result = $this->executor->approve($this->request);
      if (!empty($result['error'])) {
        // Recoverable block (e.g. approver lacks delete access): the request
        // stays pending so an authorized approver can retry.
        $this->messenger()->addError($this->t('Request #@id not approved. @msg', [
          '@id' => $this->request->id(),
          '@msg' => $result['message'],
        ]));
      }
      else {
        $this->messenger()->addStatus($this->t('Request #@id approved. @msg', [
          '@id' => $this->request->id(),
          '@msg' => $result['message'],
        ]));
      }
    }

    $form_state->setRedirectUrl($this->getCancelUrl());
  }

}
