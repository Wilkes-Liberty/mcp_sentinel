<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Upgrading with an empty (or the seeded) classification map denies nothing.
 *
 * The explicit §5.2 regression: with no map, and with the update-10021 seeded
 * state (identity types labelled, every profile without ceilings), every
 * governed read on every seam behaves exactly as before and no
 * classification_egress_denied row is written. A control case proves the
 * same probes DO fail once a label and a ceiling are set — so this test can
 * fail (d.o #3616540 part 2).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpClassificationEmptyMapRegressionTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'taxonomy',
    'audit_chain', 'mcp_sentinel',
  ];

  /**
   * The governed account.
   */
  private UserInterface $agent;

  /**
   * A node in the bundle the control case labels.
   */
  private Node $memo;

  /**
   * Whether a request of this test's own is on top of the stack.
   */
  private bool $pushedRequest = FALSE;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('taxonomy_term');
    $this->installEntitySchema('path_alias');
    $this->installSchema('system', ['sequences']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['filter', 'node', 'mcp_sentinel', 'user']);
    require_once \Drupal::root() . '/' . \Drupal::service('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';

    NodeType::create(['type' => 'memo', 'name' => 'Memo'])->save();
    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access content');
    $role->grantPermission('access mcp sentinel context');
    $role->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();
    // A role-bound profile too, so the "production-oriented" shape is present.
    McpPolicyProfile::create([
      'id' => 'agents',
      'label' => 'Agents',
      'roles' => ['mcp_api'],
      'weight' => 10,
      'allow_read' => TRUE,
      'allow_raw_sql' => TRUE,
    ])->save();
    $this->createUser();
    $this->agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->memo = Node::create(['type' => 'memo', 'title' => 'Memo one', 'status' => 1]);
    $this->memo->save();
    \Drupal::currentUser()->setAccount($this->agent);
  }

  /**
   * Makes a request current, keeping the kernel's master request underneath.
   */
  private function pushRequest(Request $request): void {
    $stack = $this->container->get('request_stack');
    if ($this->pushedRequest) {
      $stack->pop();
    }
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    $this->pushedRequest = TRUE;
    \Drupal::entityTypeManager()->getAccessControlHandler('node')->resetCache();
  }

  /**
   * Number of classification denial rows written so far.
   */
  private function denialCount(): int {
    return (int) $this->container->get('database')->select('audit_chain_log', 'a')
      ->condition('operation', McpClassificationResolver::DENIAL_CODE)
      ->countQuery()->execute()->fetchField();
  }

  /**
   * Runs one governed read through every seam and returns what was refused.
   *
   * @return string[]
   *   The seams that refused, empty when everything read as before.
   */
  private function probeAllSeams(): array {
    $refused = [];
    $profile = $this->container->get('mcp_sentinel.policy_resolver')->resolve($this->agent);
    $this->assertNotNull($profile);

    // Entity access.
    $this->pushRequest(Request::create('/jsonapi/node/memo'));
    if ($this->memo->access('view', $this->agent, TRUE)->isForbidden()) {
      $refused[] = 'entity_access';
    }
    // Field access.
    $field = mcp_sentinel_entity_field_access('view', $this->memo->getFieldDefinition('title'), $this->agent, $this->memo->get('title'));
    if ($field->isForbidden()) {
      $refused[] = 'field_access';
    }
    // JSON:API filter access.
    if ($this->container->get('mcp_sentinel.access_checker')->getJsonApiFilterAccess('node', $profile) !== []) {
      $refused[] = 'filter_access';
    }
    // Request seam.
    $request = Request::create('/jsonapi/node/memo');
    $request->attributes->set('resource_type', $this->container->get('jsonapi.resource_type.repository')->get('node', 'memo'));
    $this->pushRequest($request);
    $event = new RequestEvent($this->container->get('http_kernel'), $request, HttpKernelInterface::MAIN_REQUEST);
    $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber')->onRequest($event);
    if ($event->getResponse() !== NULL) {
      $refused[] = 'request_seam';
    }
    // Response seam.
    $body = (string) json_encode(['data' => [['type' => 'node--memo', 'id' => 'a']]]);
    $request = Request::create('/jsonapi/node/memo');
    $this->pushRequest($request);
    $response = new Response($body, 200, ['Content-Type' => 'application/vnd.api+json']);
    $event = new ResponseEvent($this->container->get('http_kernel'), $request, HttpKernelInterface::MAIN_REQUEST, $response);
    $this->container->get('mcp_sentinel.governed_response_subscriber')->onResponse($event);
    if ($event->getResponse()->getContent() !== $body) {
      $refused[] = 'response_seam';
    }
    // Raw SQL.
    if ($this->container->get('mcp_sentinel.raw_sql_guard')->check('SELECT nid, title FROM node_field_data', $profile) !== []) {
      $refused[] = 'raw_sql';
    }
    // Context endpoint.
    $this->pushRequest(Request::create('/drupal-mcp/context'));
    $context = McpContextController::create($this->container)->context();
    $payload = json_decode((string) $context->getContent(), TRUE);
    if ($context->getStatusCode() !== 200 || !isset($payload['content_types']['memo'])) {
      $refused[] = 'context';
    }
    return $refused;
  }

  /**
   * An empty map with no ceilings refuses nothing on any seam.
   */
  public function testEmptyMapDeniesNothing(): void {
    $this->config('mcp_sentinel.settings')->set('classification_map', [])->save();
    $this->assertSame([], $this->probeAllSeams());
    $this->assertSame(0, $this->denialCount());
  }

  /**
   * The update-10021 seeded state refuses nothing on any seam.
   *
   * The seed labels only identity/credential types and gives every profile
   * an EMPTY ceilings map — so even that labelled data is not refused until
   * an operator sets a ceiling.
   */
  public function testSeededStateDeniesNothing(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->clear('classification_labels')->clear('classification_map')->clear('context_schema_label')->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.agents')->clear('egress_ceilings')->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')->clear('egress_ceilings')->save();
    $this->container->get('config.factory')->reset();
    mcp_sentinel_update_10021();
    $this->container->get('config.factory')->reset();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $this->assertNotEmpty($this->config('mcp_sentinel.settings')->get('classification_map'), 'The seed labels the identity types.');
    $this->assertTrue($this->container->get('mcp_sentinel.classification')->assignsAboveLowest());

    $this->assertSame([], $this->probeAllSeams());
    // Even the seeded restricted types read as before with no ceiling: any
    // refusal here comes from the profile's deny list, never from a label.
    $this->pushRequest(Request::create('/jsonapi/user/user'));
    $result = $this->agent->access('view', $this->agent, TRUE);
    $reason = $result instanceof AccessResultReasonInterface ? (string) $result->getReason() : '';
    $this->assertStringNotContainsString(McpClassificationResolver::DENIAL_CODE, $reason);
    $this->assertSame(0, $this->denialCount());
  }

  /**
   * Control: a label plus a ceiling makes the same probes refuse.
   */
  public function testControlLabelAndCeilingRefuse(): void {
    $this->config('mcp_sentinel.settings')
      ->set('classification_map', [
        ['entity_type' => 'node', 'bundle' => 'memo', 'field' => '', 'label' => 'restricted'],
      ])
      ->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.agents')
      ->set('egress_ceilings', ['jsonapi' => 'internal', 'context' => 'internal', 'drush' => 'internal'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $refused = $this->probeAllSeams();
    foreach (['entity_access', 'field_access', 'filter_access', 'request_seam', 'response_seam', 'raw_sql', 'context'] as $seam) {
      $this->assertContains($seam, $refused, "The $seam probe can fail.");
    }
    $this->assertGreaterThan(0, $this->denialCount());
  }

}
