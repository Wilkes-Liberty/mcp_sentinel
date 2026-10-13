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
 * Records the frozen principal + tenant context a governed tool receives.
 */
#[Tool(
  id: 'mcp_sentinel_principal_context_probe',
  label: new TranslatableMarkup('Principal context probe'),
  description: new TranslatableMarkup('Returns the token-derived principal and tenant context. Test only.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'note' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Note'),
      description: new TranslatableMarkup('Optional marker. "mutate" attempts to change the context.'),
      required: FALSE,
    ),
  ],
)]
final class PrincipalContextProbeTool extends McpGovernedToolBase {

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    $ctx = $this->principalContext();
    $mutation = 'not-attempted';
    if (($values['note'] ?? '') === 'mutate') {
      try {
        $property = new \ReflectionProperty($ctx, 'tenant');
        $property->setValue($ctx, 'spoofed-tenant');
        $mutation = 'mutated';
      }
      catch (\Throwable $e) {
        $mutation = 'rejected';
      }
    }
    return ExecutableResult::success($this->t('Context received.'), [
      'subject' => $ctx->subject(),
      'client_id' => $ctx->clientId(),
      'azp' => $ctx->azp(),
      'scopes' => $ctx->scopes(),
      'tenant' => $ctx->tenant(),
      'act' => $ctx->actChain(),
      'network' => $ctx->isNetwork(),
      'mutation' => $mutation,
    ]);
  }

}
