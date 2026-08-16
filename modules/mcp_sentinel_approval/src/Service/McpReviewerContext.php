<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_approval\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\RevisionableInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel\Service\McpActionManifestSealer;
use Drupal\mcp_sentinel\Value\McpActionManifest;
use Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface;
use Drupal\user\UserInterface;

/**
 * Builds the exact sealed-vs-live context a reviewer must see.
 *
 * Slice 5 of #3616538. A reviewer who cannot see what they are
 * approving is not a control: missing or invalid manifests produce
 * a non-visible result and the approve form hides the confirm action.
 */
final class McpReviewerContext {

  /**
   * Constructs the reviewer context builder.
   *
   * @param \Drupal\mcp_sentinel\Service\McpActionManifestSealer $sealer
   *   Opens the stored seal.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   Loads the live target.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Reads live config for config_import diffs.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Reports whether a module_disable target is installed.
   */
  public function __construct(
    private readonly McpActionManifestSealer $sealer,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ModuleHandlerInterface $moduleHandler,
  ) {}

  /**
   * Builds reviewer context for one request.
   *
   * @param \Drupal\mcp_sentinel_approval\Entity\McpApprovalRequestInterface $request
   *   The pending request.
   *
   * @return array<string, mixed>
   *   visible is TRUE when the sealed action can be shown.
   */
  public function build(McpApprovalRequestInterface $request): array {
    $raw = $request->getSealedManifest();
    if ($raw === '') {
      return $this->hidden('This request has no sealed action manifest. It cannot be approved.');
    }
    $manifest = $this->sealer->open($raw);
    if ($manifest === NULL) {
      return $this->hidden('The stored action manifest is not valid for the current signing key. It cannot be approved.');
    }

    $target = $manifest->target();
    return [
      'visible' => TRUE,
      'message' => '',
      'operation' => $manifest->operation(),
      'target' => $target['type'] . ':' . $target['id'],
      'target_uuid' => $target['uuid'],
      'target_revision' => $target['revision'],
      'actor_uid' => $manifest->actorUid(),
      'expires' => $manifest->expires(),
      'policy_digest' => $manifest->policyDigest(),
      'obligations' => $this->obligations($manifest),
      'rows' => $this->rows($manifest),
    ];
  }

  /**
   * Render array for the decision form.
   *
   * @param array<string, mixed> $context
   *   Result of build().
   *
   * @return array<string, mixed>
   *   A render array.
   */
  public function toRenderArray(array $context): array {
    if (empty($context['visible'])) {
      return [
        '#type' => 'container',
        '#weight' => -10,
        '#attributes' => ['class' => ['messages', 'messages--error']],
        'message' => [
          '#type' => 'html_tag',
          '#tag' => 'p',
          '#value' => (string) $context['message'],
        ],
      ];
    }

    $items = [
      'Operation: ' . (string) $context['operation'],
      'Target: ' . (string) $context['target'],
    ];
    if (!empty($context['target_uuid'])) {
      $items[] = 'Sealed uuid: ' . (string) $context['target_uuid'];
    }
    if (!empty($context['target_revision'])) {
      $items[] = 'Sealed revision: ' . (string) $context['target_revision'];
    }
    $items[] = 'Actor uid: ' . (string) $context['actor_uid'];
    $items[] = 'Expires: ' . (string) $context['expires'];
    if (!empty($context['policy_digest'])) {
      $items[] = 'Policy digest: ' . (string) $context['policy_digest'];
    }
    $obligations = $context['obligations'] ?? [];
    $items[] = 'Obligations: ' . ($obligations === [] ? 'none' : implode(', ', $obligations));

    $rows = [];
    foreach ($context['rows'] ?? [] as $row) {
      $rows[] = [
        (string) ($row['field'] ?? ''),
        (string) ($row['sealed'] ?? ''),
        (string) ($row['live'] ?? ''),
      ];
    }

    return [
      '#type' => 'container',
      '#weight' => -10,
      'heading' => [
        '#markup' => '<h2>Sealed action</h2>',
      ],
      'summary' => [
        '#theme' => 'item_list',
        '#items' => $items,
      ],
      'diff' => [
        '#type' => 'table',
        '#header' => ['Field', 'Sealed', 'Live'],
        '#rows' => $rows,
        '#empty' => 'No field-level difference is available for this operation.',
      ],
    ];
  }

  /**
   * Hidden (approve-blocked) context.
   *
   * @return array<string, mixed>
   *   Non-visible context.
   */
  private function hidden(string $message): array {
    return [
      'visible' => FALSE,
      'message' => $message,
      'operation' => '',
      'target' => '',
      'target_uuid' => NULL,
      'target_revision' => NULL,
      'actor_uid' => 0,
      'expires' => 0,
      'policy_digest' => NULL,
      'obligations' => [],
      'rows' => [],
    ];
  }

  /**
   * Obligations from the sealed arguments only.
   *
   * The request payload can be edited after queue; slice 3 executes the seal.
   *
   * @return list<string>
   *   Obligation codes.
   */
  private function obligations(McpActionManifest $manifest): array {
    $raw = $manifest->arguments()['obligations'] ?? NULL;
    if (!is_array($raw)) {
      return [];
    }
    $codes = [];
    foreach ($raw as $item) {
      if (is_string($item) && trim($item) !== '') {
        $codes[] = trim($item);
      }
    }
    return $codes;
  }

  /**
   * Field-level sealed-vs-live rows.
   *
   * @return list<array{field: string, sealed: string, live: string}>
   *   Diff rows.
   */
  private function rows(McpActionManifest $manifest): array {
    return match ($manifest->operation()) {
      'delete' => $this->entityRows($manifest),
      'config_import' => $this->configRows($manifest),
      'module_disable' => $this->moduleRows($manifest),
      'grant_mcp_admin' => $this->grantRows($manifest),
      default => $this->genericArgumentRows($manifest),
    };
  }

  /**
   * Delete: sealed identity vs the live entity.
   *
   * @return list<array{field: string, sealed: string, live: string}>
   *   Diff rows.
   */
  private function entityRows(McpActionManifest $manifest): array {
    $target = $manifest->target();
    $live = $this->loadTarget($target['type'], $target['id']);
    $rows = [
      $this->row('action', 'delete', $live === NULL ? 'missing' : 'present'),
      $this->row('uuid', (string) ($target['uuid'] ?? ''), $live !== NULL ? (string) $live->uuid() : 'missing'),
    ];
    $sealedRevision = (string) ($target['revision'] ?? '');
    $liveRevision = '';
    if ($live instanceof RevisionableInterface) {
      $liveRevision = (string) $live->getRevisionId();
    }
    if ($sealedRevision !== '' || $liveRevision !== '') {
      $rows[] = $this->row('revision', $sealedRevision, $liveRevision === '' ? 'n/a' : $liveRevision);
    }
    $sealedLabel = (string) ($manifest->arguments()['label'] ?? '');
    $liveLabel = $live !== NULL ? (string) $live->label() : 'missing';
    if ($sealedLabel !== '' || $live !== NULL) {
      $rows[] = $this->row('label', $sealedLabel, $liveLabel);
    }
    return $rows;
  }

  /**
   * Config import: each sealed key vs the live config value.
   *
   * @return list<array{field: string, sealed: string, live: string}>
   *   Diff rows.
   */
  private function configRows(McpActionManifest $manifest): array {
    $name = $manifest->target()['id'];
    $live = $this->configFactory->get($name)->getRawData();
    $data = (array) ($manifest->arguments()['data'] ?? []);
    $keys = array_unique(array_merge(array_keys($data), array_keys($live)));
    sort($keys);
    $rows = [];
    foreach ($keys as $key) {
      $key = (string) $key;
      $sealed = array_key_exists($key, $data) ? $data[$key] : NULL;
      $current = array_key_exists($key, $live) ? $live[$key] : NULL;
      if ($sealed === $current) {
        continue;
      }
      $rows[] = $this->row(
        $key,
        $this->displayValue($key, $sealed),
        $this->displayValue($key, $current),
      );
    }
    return $rows;
  }

  /**
   * Module disable: sealed uninstall vs live install state.
   *
   * @return list<array{field: string, sealed: string, live: string}>
   *   Diff rows.
   */
  private function moduleRows(McpActionManifest $manifest): array {
    $module = $manifest->target()['id'];
    return [
      $this->row(
        $module,
        'uninstall',
        $this->moduleHandler->moduleExists($module) ? 'installed' : 'not installed',
      ),
    ];
  }

  /**
   * Break-glass grant: sealed uid vs live account.
   *
   * @return list<array{field: string, sealed: string, live: string}>
   *   Diff rows.
   */
  private function grantRows(McpActionManifest $manifest): array {
    $uid = (string) ($manifest->arguments()['uid'] ?? $manifest->target()['id']);
    $user = $this->entityTypeManager->getStorage('user')->load((int) $uid);
    $live = $user instanceof UserInterface
      ? $user->getAccountName() . ' roles=' . implode(',', $user->getRoles())
      : 'missing';
    return [
      $this->row('grantee', 'uid ' . $uid, $live),
    ];
  }

  /**
   * Fallback: each sealed argument vs empty live.
   *
   * @return list<array{field: string, sealed: string, live: string}>
   *   Diff rows.
   */
  private function genericArgumentRows(McpActionManifest $manifest): array {
    $rows = [];
    foreach ($manifest->arguments() as $key => $value) {
      $rows[] = $this->row((string) $key, $this->displayValue((string) $key, $value), '');
    }
    return $rows;
  }

  /**
   * Loads a live target entity when the type is known.
   */
  private function loadTarget(string $type, string $id): ?EntityInterface {
    if (!$this->entityTypeManager->hasDefinition($type)) {
      return NULL;
    }
    $entity = $this->entityTypeManager->getStorage($type)->load($id);
    return $entity instanceof EntityInterface ? $entity : NULL;
  }

  /**
   * One table row.
   *
   * @return array{field: string, sealed: string, live: string}
   *   A row.
   */
  private function row(string $field, string $sealed, string $live): array {
    return [
      'field' => $field,
      'sealed' => $sealed,
      'live' => $live,
    ];
  }

  /**
   * Stringifies a value, redacting secret-looking keys at any depth.
   */
  private function displayValue(string $key, mixed $value): string {
    $redacted = $this->redact($key, $value);
    if ($redacted === NULL) {
      return '';
    }
    if (is_bool($redacted)) {
      return $redacted ? 'true' : 'false';
    }
    if (is_scalar($redacted)) {
      return (string) $redacted;
    }
    return (string) json_encode($redacted, JSON_UNESCAPED_SLASHES);
  }

  /**
   * Replaces secret-looking keys with a redaction marker.
   */
  private function redact(string $key, mixed $value): mixed {
    if (preg_match('/secret|password|token|hash_key|key_value/i', $key) === 1) {
      return $value === NULL ? NULL : '[REDACTED]';
    }
    if (!is_array($value)) {
      return $value;
    }
    $out = [];
    foreach ($value as $childKey => $child) {
      $out[$childKey] = $this->redact((string) $childKey, $child);
    }
    return $out;
  }

}
