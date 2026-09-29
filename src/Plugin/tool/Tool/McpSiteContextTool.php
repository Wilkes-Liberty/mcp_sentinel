<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\mcp_sentinel\Service\McpSiteSchemaBuilder;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\ExecutableResult;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Returns the full site schema: content types, fields, vocabularies, media.
 *
 * Agents should call this before creating or editing content so they know the
 * available bundles and fields. Mirrors the /drupal-mcp/context endpoint.
 */
#[Tool(
  id: 'mcp_sentinel_site_context',
  label: new TranslatableMarkup('Get site schema context'),
  description: new TranslatableMarkup('Returns all content types with field labels and types, taxonomy vocabularies with term counts, and media types. Call this before creating or editing content to understand the available fields.'),
  operation: ToolOperation::Explain,
)]
final class McpSiteContextTool extends McpGovernedToolBase {

  /**
   * Shared site-schema builder (content types, vocabularies, media types).
   */
  protected McpSiteSchemaBuilder $schemaBuilder;

  /**
   * The policy resolver.
   */
  protected McpPolicyResolver $policyResolver;

  /**
   * Classification egress ceilings (NULL only in the deploy window).
   */
  protected ?McpClassificationResolver $classification = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->schemaBuilder = $container->get('mcp_sentinel.site_schema_builder');
    $instance->policyResolver = $container->get('mcp_sentinel.policy_resolver');
    $instance->classification = $container->has('mcp_sentinel.classification')
      ? $container->get('mcp_sentinel.classification')
      : NULL;
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    // Classification egress ceiling (d.o #3616540 part 2): this document is
    // the same schema the context endpoint serves, judged against the Tool
    // ceiling — refused below the schema label, and over-ceiling bundles are
    // not described.
    // The resolver is NULL only in the deploy window before the container
    // rebuilds; no ceiling is evaluated then, exactly the previous behaviour.
    $profile = $this->policyResolver->resolve();
    $ceiling = ($profile === NULL || $this->classification === NULL)
      ? NULL
      : $this->classification->effectiveCeiling($profile, McpGovernedSurface::Tool);
    if ($profile !== NULL && $this->classification?->schemaDenied($profile, McpGovernedSurface::Tool, $ceiling)) {
      return ExecutableResult::failure($this->t("The site schema is classified above this principal's egress ceiling (@code).", [
        '@code' => McpClassificationResolver::DENIAL_CODE,
      ]));
    }

    $data = $this->schemaBuilder->build(
      fn (string $entity_type_id, string $bundle): bool => $this->describes(
        $profile,
        $ceiling,
        $entity_type_id,
        $bundle,
      ),
    );

    return ExecutableResult::success($this->t('Site schema retrieved.'), $data);
  }

  /**
   * Whether a bundle may be described to the requesting principal.
   *
   * Mirrors the context endpoint through the resolver's shared rule.
   */
  private function describes(?McpPolicyProfileInterface $profile, ?string $ceiling, string $entity_type_id, string $bundle): bool {
    return $this->classification === NULL
      || $this->classification->describesBundle($profile, McpGovernedSurface::Tool, $ceiling, $entity_type_id, $bundle);
  }

}
