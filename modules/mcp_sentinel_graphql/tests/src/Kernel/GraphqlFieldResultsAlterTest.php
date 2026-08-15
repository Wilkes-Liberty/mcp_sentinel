<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Kernel;

use Drupal\Core\Entity\EntityInterface;
use Drupal\graphql\GraphQL\Execution\FieldContext;
use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\graphql_compose\Plugin\GraphQLCompose\GraphQLComposeFieldTypeInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use GraphQL\Type\Definition\ResolveInfo;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests mcp_sentinel_graphql_graphql_compose_field_results_alter().
 *
 * Exercises every code path in the hook:
 *  - field-name redaction replaces governed field values with '[REDACTED]'.
 *  - non-null guard: a governed empty result for a redacted field gets
 *    ['[REDACTED]'] rather than [].
 *  - DLP masks email-pattern values when dlp_enabled = TRUE.
 *  - DLP is a no-op when dlp_enabled = FALSE.
 *  - result-count cap truncates a list to result_count_cap items.
 *  - non-governed requests leave $results completely unchanged.
 *  - cache contexts user.roles + oauth2_scopes are added unconditionally so
 *    governed and non-governed responses are never cross-cached.
 *
 * The hook is a procedural function in mcp_sentinel_graphql.module. Each test
 * invokes it directly, passing a captured FieldContext (spy) so that
 * addCacheContexts() calls can be inspected.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class GraphqlFieldResultsAlterTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
    'graphql',
    'graphql_compose',
    'mcp_sentinel_graphql',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
    // Saving mcp_sentinel.settings in these tests fires the ConfigEvents::SAVE
    // audit subscriber, which reads/writes the audit log; install its schema.
    $this->installSchema('audit_chain', ['audit_chain_log']);
  }

  /**
   * A governed field listed in redacted_fields is replaced with '[REDACTED]'.
   *
   * Profile has redacted_fields=['body']. A non-empty $results array for the
   * 'body' field must have every delta replaced with '[REDACTED]'.
   */
  public function testRedactedFieldReplacedWithToken(): void {
    $this->makeGoverned(['body'], 0);

    $results = ['secret content'];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('body'), $context);

    $this->assertSame(['[REDACTED]'], $results);
  }

  /**
   * An empty result for a redacted field receives the non-null placeholder.
   *
   * When $results === [], the hook must return ['[REDACTED]'] so a required
   * single-value GraphQL field does not trip the non-null guard with an
   * empty list.
   */
  public function testEmptyRedactedResultGetsNonNullPlaceholder(): void {
    $this->makeGoverned(['body'], 0);

    $results = [];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('body'), $context);

    $this->assertSame(['[REDACTED]'], $results);
  }

  /**
   * A string value matching the email DLP pattern is masked when DLP is on.
   *
   * Profile has no redacted_fields; DLP is enabled in 'redact' mode with the
   * built-in email pattern. The field value 'a@b.com' must be replaced with
   * '[REDACTED]' (full-redact mode).
   */
  public function testDlpMasksEmailValue(): void {
    $this->makeGoverned([], 0);
    $this->enableDlpRedact();

    $results = ['a@b.com'];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('title'), $context);

    $this->assertStringNotContainsString(
      'a@b.com',
      (string) $results[0],
      'Raw email must not appear after DLP masking.',
    );
    $this->assertStringContainsString('[REDACTED]', (string) $results[0]);
  }

  /**
   * DLP is a no-op when dlp_enabled = FALSE; the raw value passes through.
   */
  public function testDlpNoOpWhenDisabled(): void {
    $this->makeGoverned([], 0);
    $this->config('mcp_sentinel.settings')->set('dlp_enabled', FALSE)->save();
    // Rebuild container so McpDlp factory reads the disabled flag.
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();

    $results = ['a@b.com'];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('title'), $context);

    $this->assertSame(['a@b.com'], $results, 'DLP disabled: email value must pass through unchanged.');
  }

  /**
   * A multi-value field list is capped to result_count_cap items.
   *
   * Profile has result_count_cap=2 and no redacted_fields. A $results list
   * of 5 items must be truncated to exactly 2 items.
   */
  public function testResultCapTruncatesList(): void {
    $this->makeGoverned([], 2);

    $results = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('title'), $context);

    $this->assertCount(2, $results, 'Result list must be capped to result_count_cap.');
    $this->assertSame(['alpha', 'beta'], $results);
  }

  /**
   * A non-governed request leaves $results completely untouched.
   *
   * No profile is resolved for the current anonymous user (no governed roles
   * configured, role fallback disabled). The hook must return immediately
   * after adding cache contexts, leaving $results unchanged.
   */
  public function testUngovernedRequestUnaffected(): void {
    // Ensure no governed roles are set and fallback is off.
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', [])
      ->set('governed_role_fallback', FALSE)
      ->save();

    $results = ['public content'];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('body'), $context);

    $this->assertSame(['public content'], $results, 'Non-governed results must be untouched.');
  }

  /**
   * Cache contexts user.roles and oauth2_scopes are added unconditionally.
   *
   * Even for a non-governed request, the hook must add both cache contexts so
   * that a cached non-governed response is never incorrectly served to a
   * governed agent (and vice-versa).
   */
  public function testCacheContextsAdded(): void {
    // Use a non-governed request to verify unconditional context addition.
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', [])
      ->set('governed_role_fallback', FALSE)
      ->save();

    $results = [];
    $context = $this->makeFieldContext();

    $this->invokeHook($results, $this->makePlugin('title'), $context);

    $addedContexts = $context->getCacheContexts();
    $this->assertContains('user.roles', $addedContexts, "The 'user.roles' cache context must be added.");
    $this->assertContains('oauth2_scopes', $addedContexts, "The 'oauth2_scopes' cache context must be added.");
  }

  /**
   * Configures a governed role + policy profile with the given settings.
   *
   * Sets governed_role_fallback = TRUE so the role-based path is exercised
   * (no real OAuth token needed in kernel tests). Creates the mcp_api role and
   * a profile that covers it, with the supplied redacted_fields and cap.
   *
   * @param string[] $redactedFields
   *   Field names the profile should redact.
   * @param int $resultCountCap
   *   Profile result_count_cap (0 = unlimited).
   */
  private function makeGoverned(array $redactedFields, int $resultCountCap): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', TRUE)
      ->save();

    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }

    McpPolicyProfile::create([
      'id' => 'test_agent',
      'label' => 'Test Agent',
      'roles' => ['mcp_api'],
      'weight' => 10,
      'allow_read' => TRUE,
      'allow_write' => FALSE,
      'redacted_fields' => $redactedFields,
      'result_count_cap' => $resultCountCap,
    ])->save();

    // Switch the current user to a governed agent account.
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($agent);
  }

  /**
   * Enables DLP with built-in patterns in full-redact mode and rebuilds DI.
   */
  private function enableDlpRedact(): void {
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', 'redact')
      ->set('dlp_patterns', McpDlp::defaultPatterns())
      ->save();
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();
  }

  /**
   * Creates a mock GraphQLComposeFieldTypeInterface for the given field name.
   *
   * Only getFieldName() is called by the hook; all other methods are stubs.
   *
   * @param string $fieldName
   *   The field machine name to return from getFieldName().
   *
   * @return \Drupal\graphql_compose\Plugin\GraphQLCompose\GraphQLComposeFieldTypeInterface
   *   A configured mock plugin.
   */
  private function makePlugin(string $fieldName): GraphQLComposeFieldTypeInterface {
    $plugin = $this->createMock(GraphQLComposeFieldTypeInterface::class);
    $plugin->method('getFieldName')->willReturn($fieldName);
    return $plugin;
  }

  /**
   * Creates a FieldContext whose cache-context methods work correctly.
   *
   * The spy builds a real FieldContext by mocking its two constructor
   * dependencies (ResolveContext and ResolveInfo). This avoids instantiating
   * the full GraphQL execution stack while keeping the real
   * RefinableCacheableDependencyTrait behaviour — addCacheContexts() calls
   * are faithfully recorded and readable via getCacheContexts().
   *
   * @return \Drupal\graphql\GraphQL\Execution\FieldContext
   *   A FieldContext whose getCacheContexts() accumulates everything passed
   *   to addCacheContexts().
   */
  private function makeFieldContext(): FieldContext {
    $resolveContext = $this->createMock(ResolveContext::class);
    // ResolveInfo is a concrete class; mock it so the hook does not need a
    // real FieldNode AST or Schema object — the hook only calls FieldContext
    // methods (addCacheContexts / getCacheContexts), never ResolveInfo.
    $resolveInfo = $this->createMock(ResolveInfo::class);

    return new FieldContext($resolveContext, $resolveInfo);
  }

  /**
   * Invokes the hook function under test.
   *
   * The function is procedural (module .module file) and is loaded by the
   * kernel as part of the mcp_sentinel_graphql module. The $results argument
   * is passed by reference so the hook can modify it in-place.
   *
   * @param array<int|string, mixed> $results
   *   The field results to pass to the hook (passed by reference).
   * @param \Drupal\graphql_compose\Plugin\GraphQLCompose\GraphQLComposeFieldTypeInterface $plugin
   *   The mock field plugin.
   * @param \Drupal\graphql\GraphQL\Execution\FieldContext $context
   *   The field context spy.
   */
  private function invokeHook(
    array &$results,
    GraphQLComposeFieldTypeInterface $plugin,
    FieldContext $context,
  ): void {
    // The entity argument is not used by the hook; pass NULL.
    mcp_sentinel_graphql_graphql_compose_field_results_alter($results, NULL, $plugin, $context);
  }

  /**
   * Labels node/page field_secret restricted and ceilings the graphql surface.
   */
  private function classifySecret(string $ceiling): void {
    $this->config('mcp_sentinel.settings')
      ->set('classification_map', [
        ['entity_type' => 'node', 'bundle' => 'page', 'field' => 'field_secret', 'label' => 'restricted'],
      ])
      ->save();
    $this->config('mcp_sentinel.mcp_policy_profile.test_agent')
      ->set('egress_ceilings', ['graphql' => $ceiling])
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    $stack = $this->container->get('request_stack');
    $request = Request::create('/graphql', 'POST');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
  }

  /**
   * A mock entity of the given type and bundle for the alter hook.
   */
  private function makeEntity(string $type, string $bundle): EntityInterface {
    $entity = $this->createMock(EntityInterface::class);
    $entity->method('getEntityTypeId')->willReturn($type);
    $entity->method('bundle')->willReturn($bundle);
    return $entity;
  }

  /**
   * An over-ceiling field returns the redaction placeholder (§5.3).
   */
  public function testOverCeilingFieldGetsPlaceholder(): void {
    $this->makeGoverned([], 0);
    $this->classifySecret('internal');

    $results = ['top secret'];
    $context = $this->makeFieldContext();
    mcp_sentinel_graphql_graphql_compose_field_results_alter($results, $this->makeEntity('node', 'page'), $this->makePlugin('field_secret'), $context);
    $this->assertSame(['[REDACTED]'], $results);
    $this->assertContains('route', $context->getCacheContexts());
    $this->assertContains('headers:' . McpClassificationResolver::HEADER_DECLARED_CEILING, $context->getCacheContexts());

    // A sibling field of the same entity serializes.
    $other = ['hello'];
    mcp_sentinel_graphql_graphql_compose_field_results_alter($other, $this->makeEntity('node', 'page'), $this->makePlugin('body'), $this->makeFieldContext());
    $this->assertSame(['hello'], $other);

    // The same field on another bundle is unlabelled.
    $article = ['fine'];
    mcp_sentinel_graphql_graphql_compose_field_results_alter($article, $this->makeEntity('node', 'article'), $this->makePlugin('field_secret'), $this->makeFieldContext());
    $this->assertSame(['fine'], $article);
  }

  /**
   * At ceiling the same field returns its data unchanged.
   */
  public function testAtCeilingFieldReturnsData(): void {
    $this->makeGoverned([], 0);
    $this->classifySecret('restricted');

    $results = ['top secret'];
    mcp_sentinel_graphql_graphql_compose_field_results_alter($results, $this->makeEntity('node', 'page'), $this->makePlugin('field_secret'), $this->makeFieldContext());
    $this->assertSame(['top secret'], $results);
  }

}
