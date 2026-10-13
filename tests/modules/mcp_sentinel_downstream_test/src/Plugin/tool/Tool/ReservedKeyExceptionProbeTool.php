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
 * Declares a subject input that a reviewed exception may exempt.
 */
#[Tool(
  id: 'mcp_sentinel_reserved_exception_probe',
  label: new TranslatableMarkup('Reserved-key exception probe'),
  description: new TranslatableMarkup('Declares a subject input a reviewed exception may exempt.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'subject' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Email subject'),
      description: new TranslatableMarkup('A declared non-identity subject.'),
      required: FALSE,
    ),
  ],
)]
final class ReservedKeyExceptionProbeTool extends McpGovernedToolBase {

  /**
   * {@inheritdoc}
   */
  protected function reservedArgumentExceptions(): array {
    return ['subject', 'user'];
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    return ExecutableResult::success($this->t('Exception probe ran.'), [
      'subject' => $values['subject'] ?? '',
    ]);
  }

}
