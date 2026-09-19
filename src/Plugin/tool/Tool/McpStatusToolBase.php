<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Plugin\tool\Tool;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpExfiltrationGuard;
use Drupal\tool\ExecutableResult;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Shares access, rate limiting and refusal handling for read-only status tools.
 *
 * Refusals are one fixed message. Caller input, exception text, secrets,
 * personal data and URLs never reach a result.
 */
abstract class McpStatusToolBase extends McpGovernedToolBase {

  use McpEntityToolTrait;

  /**
   * Largest JSON result a tool returns, in bytes.
   *
   * The resolved profile's response-size cap applies when it is lower.
   */
  protected const MAX_RESULT_BYTES = 131072;

  /**
   * Sentinel's response-size resolver.
   */
  protected ?McpExfiltrationGuard $exfiltrationGuard = NULL;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->exfiltrationGuard = $container->has('mcp_sentinel.exfiltration_guard')
      ? $container->get('mcp_sentinel.exfiltration_guard')
      : NULL;
    return $instance;
  }

  /**
   * Runs the read against services that already exist.
   *
   * @param array $values
   *   Input values. Only the inputs the tool defines.
   *
   * @return array
   *   Result without secrets, personal data or URLs.
   *
   * @throws \InvalidArgumentException
   *   When an input is not acceptable. The message is never relayed.
   */
  abstract protected function run(array $values): array;

  /**
   * Additional permissions a tool requires beyond the context permission.
   *
   * The context permission is already required by the governed base.
   *
   * @return string[]
   *   Permission names.
   */
  protected function extraPermissions(): array {
    return [];
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedDiscoveryAccess(AccountInterface $account): AccessResultInterface {
    return $this->checkGovernedAccess([], $account);
  }

  /**
   * {@inheritdoc}
   */
  protected function checkGovernedAccess(array $values, AccountInterface $account): AccessResultInterface {
    $extra = $this->extraPermissions();
    if ($extra === []) {
      return AccessResult::allowed()->setCacheMaxAge(0);
    }
    return AccessResult::allowedIfHasPermissions($account, $extra)->setCacheMaxAge(0);
  }

  /**
   * {@inheritdoc}
   */
  protected function doExecute(array $values): ExecutableResult {
    try {
      if (!$this->checkAccess($values, $this->currentUser)) {
        return $this->refused();
      }
      if (array_diff_key($values, $this->getInputDefinitions()) !== []) {
        return $this->refused();
      }
      $profile = $this->governancePolicyResolver?->resolve($this->currentUser);
      if ($profile === NULL) {
        return $this->refused();
      }
      if ($limited = $this->checkRateLimit($profile, $this->getPluginId())) {
        return $limited;
      }
      $result = $this->run($values);
      if (strlen((string) json_encode($result, JSON_THROW_ON_ERROR)) > $this->resultLimit($profile)) {
        return $this->refused();
      }
      return ExecutableResult::success($this->t('MCP Sentinel status read completed.'), $result);
    }
    catch (\Throwable $exception) {
      $this->logger->warning('MCP Sentinel status tool @tool failed with @type at @source:@line.', [
        '@tool' => $this->getPluginId(),
        '@type' => get_class($exception),
        '@source' => basename($exception->getFile()),
        '@line' => $exception->getLine(),
      ]);
      return $this->refused();
    }
  }

  /**
   * The smaller of this ceiling and the profile's response-size cap.
   */
  protected function resultLimit(McpPolicyProfileInterface $profile): int {
    $cap = $this->exfiltrationGuard === NULL
      ? 0
      : (int) $this->exfiltrationGuard->effectiveResponseSizeCap($profile);
    return $cap > 0 ? min(static::MAX_RESULT_BYTES, $cap) : static::MAX_RESULT_BYTES;
  }

  /**
   * The refusal this family of tools returns.
   */
  protected function refused(): ExecutableResult {
    return ExecutableResult::failure($this->t('MCP Sentinel status read refused. Check permissions, inputs and limits.'));
  }

}
