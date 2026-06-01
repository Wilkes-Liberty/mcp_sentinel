<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Symfony\Component\HttpFoundation\Request;

/**
 * Exposed filter form for the MCP Sentinel audit log listing.
 *
 * Submits via GET so filter values become URL query parameters, allowing
 * users to share filtered views by URL and bookmarking filter state.
 */
final class McpAuditFilterForm extends FormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'mcp_sentinel_audit_filter';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $request = $this->getRequest();

    $form['#method'] = 'get';
    // Prevent the form_build_id / form_token / form_id hidden fields from
    // polluting the query string on GET submission.
    $form['#token'] = FALSE;
    $form['#process'][] = '\\Drupal\\mcp_sentinel\\Form\\McpAuditFilterForm::removeHiddenTokens';

    $form['filters'] = [
      '#type'       => 'details',
      '#title'      => $this->t('Filter audit log'),
      '#open'       => $this->hasActiveFilters($request),
    ];

    $form['filters']['operation'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('Operation'),
      '#default_value' => $request->query->get('operation', ''),
      '#size'          => 30,
      '#description'   => $this->t('Filter by operation name.'),
    ];

    $form['filters']['entity_type'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('Entity type'),
      '#default_value' => $request->query->get('entity_type', ''),
      '#size'          => 30,
    ];

    $form['filters']['uid'] = [
      '#type'          => 'number',
      '#title'         => $this->t('User ID'),
      '#default_value' => $request->query->get('uid', ''),
      '#size'          => 10,
      '#min'           => 0,
    ];

    $form['filters']['from'] = [
      // Use textfield with datetime-local HTML attribute so BrowserTestBase
      // field detection works and the value is a plain YYYY-MM-DDTHH:MM string.
      '#type'          => 'textfield',
      '#title'         => $this->t('From'),
      '#default_value' => $request->query->get('from', ''),
      '#size'          => 20,
      '#attributes'    => ['type' => 'datetime-local'],
      '#description'   => $this->t('Show entries at or after this date/time.'),
    ];

    $form['filters']['to'] = [
      '#type'          => 'textfield',
      '#title'         => $this->t('To'),
      '#default_value' => $request->query->get('to', ''),
      '#size'          => 20,
      '#attributes'    => ['type' => 'datetime-local'],
      '#description'   => $this->t('Show entries at or before this date/time.'),
    ];

    $form['filters']['actions'] = [
      '#type'       => 'actions',
    ];

    $form['filters']['actions']['submit'] = [
      '#type'   => 'submit',
      '#value'  => $this->t('Filter'),
      '#name'   => '',
    ];

    $form['filters']['actions']['reset'] = [
      '#type'       => 'link',
      '#title'      => $this->t('Reset'),
      '#url'        => Url::fromRoute('mcp_sentinel.audit_log'),
    ];

    return $form;
  }

  /**
   * Removes the hidden form_build_id and form_id inputs from GET forms.
   *
   * These hidden fields would clutter the query string. Called as a
   * #process callback so it runs after the default form processing.
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
   * Determines whether any filter parameter is active.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return bool
   *   TRUE if at least one filter query parameter is non-empty.
   */
  private function hasActiveFilters(Request $request): bool {
    foreach (['operation', 'entity_type', 'uid', 'from', 'to'] as $param) {
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
    // GET form — no server-side submit handling needed; the browser navigates
    // to the listing URL with query parameters appended.
  }

}
