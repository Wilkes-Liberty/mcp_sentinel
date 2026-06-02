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
   * Removes a row for an editor (the "Remove row" AJAX submit).
   *
   * Decrements the editor's row count and, when the triggering button carries a
   * concrete row index in #mcp_editor_row, removes that specific row from the
   * submitted user input and re-indexes the remaining rows so the clicked row
   * (not merely the last one) disappears. The render parents to the input are
   * taken from the button's #mcp_editor_parents.
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

    $trigger = $form_state->getTriggeringElement();
    $index = $trigger['#mcp_editor_row'] ?? NULL;
    // The user-input path mirrors the rendered field names, which may differ
    // from the render-array path when the editor sits under a non-#tree parent.
    $parents = $trigger['#mcp_editor_input'] ?? $trigger['#mcp_editor_parents'] ?? [];
    if ($index !== NULL && $parents !== []) {
      $input = $form_state->getUserInput();
      $rows = $this->nestedGet($input, $parents);
      if (is_array($rows)) {
        unset($rows[$index]);
        // Re-index the data rows so there are no gaps; preserve any non-numeric
        // sibling keys (e.g. the trailing "add" button) untouched.
        $reindexed = [];
        foreach ($rows as $row_key => $row_value) {
          if (is_int($row_key) || ctype_digit((string) $row_key)) {
            $reindexed[] = $row_value;
          }
          else {
            $reindexed[$row_key] = $row_value;
          }
        }
        $this->nestedSet($input, $parents, $reindexed);
        $form_state->setUserInput($input);
      }
    }
    $form_state->setRebuild();
  }

  /**
   * Reads a nested value from an array by a list of parent keys.
   *
   * @param array $array
   *   The source array.
   * @param array $parents
   *   The parent key path.
   *
   * @return mixed
   *   The value at the path, or NULL when absent.
   */
  private function nestedGet(array $array, array $parents): mixed {
    $ref = $array;
    foreach ($parents as $parent) {
      if (!is_array($ref) || !array_key_exists($parent, $ref)) {
        return NULL;
      }
      $ref = $ref[$parent];
    }
    return $ref;
  }

  /**
   * Writes a nested value into an array by a list of parent keys.
   *
   * @param array $array
   *   The array to mutate, by reference.
   * @param array $parents
   *   The parent key path.
   * @param mixed $value
   *   The value to set.
   */
  private function nestedSet(array &$array, array $parents, mixed $value): void {
    $ref = &$array;
    foreach ($parents as $parent) {
      if (!isset($ref[$parent]) || !is_array($ref[$parent])) {
        $ref[$parent] = [];
      }
      $ref = &$ref[$parent];
    }
    $ref = $value;
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
