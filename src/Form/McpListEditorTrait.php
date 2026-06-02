<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Form\FormStateInterface;

/**
 * Reusable AJAX multi-row editor for in-form sequence config.
 *
 * Tracks a per-editor row count in form-state storage and provides generic
 * add/remove AJAX callbacks. The host form supplies a per-row render builder
 * and assembles the stored sequence in its own submitForm(); this trait owns
 * only the row-count bookkeeping and the AJAX wrapper plumbing.
 */
trait McpListEditorTrait {

  /**
   * Returns (and lazily seeds) the row count for an editor in form storage.
   *
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $key
   *   A unique storage key for this editor (e.g. 'dlp_rows').
   * @param int $stored_count
   *   The number of items currently in stored config; used only to seed the
   *   count on the very first build (one blank trailing row is added).
   *
   * @return int
   *   The number of rows to render.
   */
  protected function rowCount(FormStateInterface $form_state, string $key, int $stored_count): int {
    $storage = $form_state->getStorage();
    if (!isset($storage['mcp_list_rows'][$key])) {
      $storage['mcp_list_rows'][$key] = max($stored_count + 1, 1);
      $form_state->setStorage($storage);
    }
    return (int) $storage['mcp_list_rows'][$key];
  }

  /**
   * Increments the row count for an editor (the "Add row" AJAX submit).
   *
   * @param array $form
   *   The form render array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $key
   *   The editor's storage key.
   */
  protected function addRow(array &$form, FormStateInterface $form_state, string $key): void {
    $storage = $form_state->getStorage();
    $storage['mcp_list_rows'][$key] = ($storage['mcp_list_rows'][$key] ?? 1) + 1;
    $form_state->setStorage($storage);
    $form_state->setRebuild();
  }

  /**
   * Decrements the row count for an editor (the "Remove row" AJAX submit).
   *
   * @param array $form
   *   The form render array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   * @param string $key
   *   The editor's storage key.
   */
  protected function removeRow(array &$form, FormStateInterface $form_state, string $key): void {
    $storage = $form_state->getStorage();
    $storage['mcp_list_rows'][$key] = max(($storage['mcp_list_rows'][$key] ?? 1) - 1, 1);
    $form_state->setStorage($storage);
    $form_state->setRebuild();
  }

  /**
   * AJAX callback returning the editor's wrapper element for replacement.
   *
   * @param array $form
   *   The rebuilt form render array.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   The form state.
   *
   * @return array
   *   The render sub-array keyed by the triggering element's #ajax wrapper.
   */
  public function listEditorAjax(array &$form, FormStateInterface $form_state): array {
    $element = $form_state->getTriggeringElement();
    // The wrapper element's parents are stored on the button via
    // #mcp_editor_parents.
    $parents = $element['#mcp_editor_parents'] ?? [];
    $slice = $form;
    foreach ($parents as $parent) {
      $slice = $slice[$parent] ?? [];
    }
    return $slice;
  }

}
