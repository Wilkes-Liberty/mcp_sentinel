<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * GET filter form for the webhook delivery log (status + endpoint).
 *
 * Mirrors McpAuditFilterForm in design: submits via GET so filter values
 * become URL query parameters, enabling bookmarkable filtered views.
 */
final class McpWebhookFilterForm extends FormBase {

  /**
   * Known delivery statuses for the status select.
   *
   * Note: 'sent' is labeled 'Delivered' so the word 'sent' only appears in
   * the badge/table context, keeping filter and content text distinguishable.
   */
  private const STATUSES = [
    ''            => '-- Any --',
    'pending'     => 'Pending',
    'in_progress' => 'In progress',
    'sent'        => 'Delivered',
    'failed'      => 'Failed',
    'failed_ssrf' => 'Failed (SSRF blocked)',
    'failed_redirect' => 'Failed (endpoint redirects)',
  ];

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'mcp_sentinel_webhook_filter';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $request = $this->getRequest();

    $form['#method'] = 'get';
    $form['#token'] = FALSE;
    $form['#process'][] = '\\Drupal\\mcp_sentinel\\Form\\McpWebhookFilterForm::removeHiddenTokens';

    $form['filters'] = [
      '#type'  => 'details',
      '#title' => $this->t('Filter deliveries'),
      '#open'  => $this->hasActiveFilters($request),
    ];

    $form['filters']['status'] = [
      '#type'          => 'select',
      '#title'         => $this->t('Status'),
      '#options'       => self::STATUSES,
      '#default_value' => $request->query->get('status', ''),
    ];

    $form['filters']['endpoint_id'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('Endpoint ID'),
      '#default_value' => $request->query->get('endpoint_id', ''),
      '#size'          => 30,
      '#description'   => $this->t('Filter by webhook endpoint identifier.'),
    ];

    $form['filters']['actions'] = ['#type' => 'actions'];
    $form['filters']['actions']['submit'] = [
      '#type'  => 'submit',
      '#value' => $this->t('Filter'),
      '#name'  => '',
    ];

    return $form;
  }

  /**
   * Removes the hidden form_build_id and form_id inputs from GET forms.
   *
   * @param array $element
   *   The form element being processed.
   *
   * @return array
   *   The processed element with hidden system fields removed.
   */
  public static function removeHiddenTokens(array $element): array {
    unset($element['form_build_id'], $element['form_id'], $element['form_token']);
    return $element;
  }

  /**
   * Whether any filter parameter is currently active.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return bool
   *   TRUE if at least one filter query parameter is non-empty.
   */
  private function hasActiveFilters(
    Request $request,
  ): bool {
    foreach (['status', 'endpoint_id'] as $param) {
      if ($request->query->get($param, '') !== '') {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    // GET form — no server-side submit handling needed.
  }

}
