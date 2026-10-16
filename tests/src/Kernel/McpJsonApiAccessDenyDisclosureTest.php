<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use ColinODell\PsrTestLogger\TestLogger;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedEntryPointTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * JSON:API copies AccessResult reasons into errors[].detail and meta.omitted.
 *
 * Core's EntityAccessDeniedHttpExceptionNormalizer appends getReason() to
 * the 403 message. JsonApiDocumentTopLevelNormalizer then copies that
 * detail onto meta.omitted.links.*.meta.detail. A governed deny must
 * therefore put only the generic caller message on the AccessResult.
 * The HMAC denied_access row and the operator log still name the rule.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpJsonApiAccessDenyDisclosureTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedEntryPointTestTrait;
  use UserCreationTrait;

  /**
   * Generic caller-facing deny. Duplicated so this test compiles on 3.2.0.
   */
  private const CALLER_DENY = 'MCP access is denied.';

  /**
   * Sealed kernel-test principal stamped by the audit-schema trait.
   */
  private const FIXTURE_PRINCIPAL_KEY = 'https://idp.example/realms/agents|kernel-test|kernel-test-client';

  /**
   * Operator-log spy injected as logger.channel.mcp_sentinel.
   */
  private TestLogger $denyLog;

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
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->assertFalse(
      $this->container->initialized('mcp_sentinel.deny_explainer'),
      'deny_explainer must still be lazy so the operator-log spy can be injected.',
    );
    $this->denyLog = new TestLogger();
    $this->container->set('logger.channel.mcp_sentinel', $this->denyLog);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('system', ['sequences']);
    $this->installSchema('node', ['node_access']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'user', 'filter', 'node', 'mcp_sentinel']);
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    // Uid 1 bypasses entity access; burn it so the governed agent is ordinary.
    $this->createUser();
    $this->switchToGovernedUser();
    $role = Role::load('mcp_api');
    $this->assertNotNull($role);
    $role
      ->grantPermission('access content')
      ->grantPermission('create article content')
      ->grantPermission('access user profiles')
      ->save();
    $account = User::load((int) $this->container->get('current_user')->id());
    $this->assertInstanceOf(User::class, $account);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    $stack = $this->container->get('request_stack');
    while ($stack->getCurrentRequest() !== NULL
      && $stack->getCurrentRequest() !== $stack->getMainRequest()) {
      $stack->pop();
    }
    parent::tearDown();
  }

  /**
   * An individual GET 403 hides the entity-type denylist reason.
   */
  public function testIndividualGetHidesEntityTypeDenyReason(): void {
    $person = $this->createUser([]);
    $this->assertInstanceOf(User::class, $person);
    $before = $this->deniedAccessCount();
    $access = $person->access('view', $this->container->get('current_user')->getAccount(), TRUE);
    $this->assertTrue($access->isForbidden(), 'A denied type must refuse the individual GET.');

    $document = $this->jsonApiErrorDocument(
      $access,
      'The current user is not allowed to GET the selected resource.',
    );
    $this->assertJsonApiDenyIsAuditedNotDisclosed(
      $document,
      $before,
      "Entity type 'user' is denied",
      'entity_type_denied',
    );
  }

  /**
   * A collection include puts the related-type deny into meta.omitted.
   */
  public function testCollectionIncludeOmittedHidesUserDenyReason(): void {
    $author = $this->createUser([]);
    $this->assertInstanceOf(User::class, $author);
    $node = $this->createArticle($author);
    $this->assertSame($author->id(), $node->getOwnerId());

    $before = $this->deniedAccessCount();
    $access = $author->access('view', $this->container->get('current_user')->getAccount(), TRUE);
    $this->assertTrue($access->isForbidden(), 'The default user denylist must refuse the included author.');

    $detail = $this->jsonApiAccessDetail(
      $access,
      'The current user is not allowed to GET the selected resource.',
    );
    $document = [
      'data' => [
        [
          'type' => 'node--article',
          'id' => $node->uuid(),
        ],
      ],
      'meta' => [
        'omitted' => [
          'detail' => 'Some resources have been omitted because of insufficient authorization.',
          'links' => [
            'help' => [
              'href' => 'https://www.drupal.org/docs/8/modules/json-api/filtering#filters-access-control',
            ],
            'item--include' => [
              'href' => '/jsonapi/user/user/' . $author->uuid(),
              'meta' => [
                'rel' => 'item',
                'detail' => $detail,
              ],
            ],
          ],
        ],
      ],
    ];
    $this->assertJsonApiDenyIsAuditedNotDisclosed(
      $document,
      $before,
      "Entity type 'user' is denied",
      'entity_type_denied',
    );
    $this->assertSame(
      $detail,
      $document['meta']['omitted']['links']['item--include']['meta']['detail'],
    );
  }

  /**
   * A POST 403 hides the entity-type denylist reason.
   */
  public function testPostHidesDeniedTypeReason(): void {
    $this->denyEntityTypes(['node']);
    $before = $this->deniedAccessCount();
    $access = $this->container->get('entity_type.manager')
      ->getAccessControlHandler('node')
      ->createAccess('article', $this->container->get('current_user')->getAccount(), [], TRUE);
    $this->assertTrue($access->isForbidden(), 'A denied type must refuse POST create.');

    $document = $this->jsonApiErrorDocument(
      $access,
      'The current user is not allowed to POST the selected resource.',
    );
    $this->assertJsonApiDenyIsAuditedNotDisclosed(
      $document,
      $before,
      "Entity type 'node' is denied",
      'entity_type_denied',
    );
    $this->assertStringNotContainsString('Write operations are disabled', json_encode($document));
  }

  /**
   * Adds entity types to the default denylist.
   *
   * @param string[] $types
   *   Extra denied entity types.
   */
  private function denyEntityTypes(array $types): void {
    $config = $this->config('mcp_sentinel.mcp_policy_profile.default');
    $current = $config->get('denied_entity_types') ?? [];
    $config
      ->set('denied_entity_types', array_values(array_unique(array_merge($current, $types))))
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    $this->container->get('entity_type.manager')->getAccessControlHandler('node')->resetCache();
  }

  /**
   * Creates a published article.
   *
   * @param \Drupal\user\Entity\User|null $author
   *   Optional node owner.
   *
   * @return \Drupal\node\Entity\Node
   *   The saved node.
   */
  private function createArticle(?User $author = NULL): Node {
    $values = [
      'type' => 'article',
      'title' => 'Article',
      'status' => 1,
    ];
    if ($author !== NULL) {
      $values['uid'] = $author->id();
    }
    $node = Node::create($values);
    $node->save();
    return $node;
  }

  /**
   * Formats a JSON:API 403 the way core's exception normalizer does.
   *
   * @param \Drupal\Core\Access\AccessResultInterface $access
   *   The governed access result.
   * @param string $message
   *   The exception message core puts in errors[].detail before the reason.
   *
   * @return array
   *   A JSON:API error document.
   */
  private function jsonApiErrorDocument(AccessResultInterface $access, string $message): array {
    return [
      'errors' => [
        [
          'status' => '403',
          'title' => 'Forbidden',
          'detail' => $this->jsonApiAccessDetail($access, $message),
        ],
      ],
    ];
  }

  /**
   * Appends getReason() onto the 403 message, as core JSON:API does.
   *
   * @param \Drupal\Core\Access\AccessResultInterface $access
   *   The governed access result.
   * @param string $message
   *   The exception message core puts in errors[].detail before the reason.
   *
   * @return string
   *   Caller-facing detail text.
   */
  private function jsonApiAccessDetail(AccessResultInterface $access, string $message): string {
    $detail = $message;
    if ($access instanceof AccessResultReasonInterface) {
      $reason = (string) $access->getReason();
      if ($reason !== '') {
        $detail .= ' ' . $reason;
      }
    }
    return $detail;
  }

  /**
   * Asserts caller, HMAC row, and operator log split the rule correctly.
   *
   * @param array $document
   *   Encoded JSON:API errors or meta.omitted document.
   * @param int $before
   *   Denied_access count before the governed access check.
   * @param string $leaked
   *   Rule text that must not reach the caller.
   * @param string $ruleId
   *   Explainer rule id recorded on the HMAC row.
   */
  private function assertJsonApiDenyIsAuditedNotDisclosed(
    array $document,
    int $before,
    string $leaked,
    string $ruleId,
  ): void {
    $this->assertJsonApiHidesRule($document, $leaked);
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame($ruleId, $meta['rule'] ?? NULL);
    $this->assertStringContainsString($leaked, (string) ($meta['explain'] ?? ''));
    $this->assertStringContainsString('[rule:' . $ruleId, (string) ($meta['explain'] ?? ''));
    $this->assertSame(self::FIXTURE_PRINCIPAL_KEY, $meta['principal_key'] ?? NULL);
    $this->assertOperatorLogCarriesRule($leaked, $ruleId);
  }

  /**
   * Asserts a JSON:API document is a generic deny with no rule disclosure.
   *
   * @param array $document
   *   Encoded JSON:API errors or meta.omitted document.
   * @param string $leaked
   *   Rule text that must not reach the caller.
   */
  private function assertJsonApiHidesRule(array $document, string $leaked): void {
    $body = (string) json_encode($document);
    $this->assertStringContainsString(self::CALLER_DENY, $body);
    $this->assertStringNotContainsString($leaked, $body);
    $this->assertStringNotContainsString('[rule:', $body);
    $this->assertStringNotContainsString('classification_egress_denied', $body);
    $this->assertStringNotContainsString('policy_bundle_denied', $body);
    $this->assertStringNotContainsString('tenant_mismatch', $body);
  }

  /**
   * Asserts the operator channel received the rule the caller must not see.
   *
   * @param string $leaked
   *   Rule text written to the operator log.
   * @param string $ruleId
   *   Explainer rule id written to the operator log.
   */
  private function assertOperatorLogCarriesRule(string $leaked, string $ruleId): void {
    $haystacks = [];
    foreach ($this->denyLog->records as $record) {
      $haystacks[] = (string) ($record['message'] ?? '')
        . json_encode($record['context'] ?? []);
    }
    $joined = implode("\n", $haystacks);
    $this->assertStringContainsString($leaked, $joined);
    $this->assertStringContainsString($ruleId, $joined);
  }

}
