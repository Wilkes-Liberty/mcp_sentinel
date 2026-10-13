<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;

/**
 * Declares a token sub input that a reviewed exception cannot exempt.
 */
#[Tool(
  id: 'mcp_sentinel_reserved_never_exempt_probe',
  label: new TranslatableMarkup('Reserved-key never-exempt probe'),
  description: new TranslatableMarkup('Declares sub so a never-exempt exception can be tested.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'sub' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Token sub attempt'),
      description: new TranslatableMarkup('A declared identity claim; never exempted.'),
      required: FALSE,
    ),
  ],
)]
final class ReservedKeyNeverExemptProbeTool extends McpGovernedToolBase {

  /**
   * {@inheritdoc}
   */
  protected function reservedArgumentExceptions(): array {
    return ['sub'];
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    return ExecutableResult::success($this->t('Never-exempt probe ran.'), [
      'sub' => $values['sub'] ?? '',
    ]);
  }

}
