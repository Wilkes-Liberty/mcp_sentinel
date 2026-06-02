<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Tests the McpJsonApiPageLimitSubscriber.
 *
 * Exercises the subscriber directly to verify that:
 *  - governed requests with page[limit] above the cap throw a 400
 *  - governed requests at/below the cap pass through
 *  - ungoverned requests are not affected
 *  - cap = 0 (unlimited) passes any limit.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpJsonApiPageLimitTest extends KernelTestBase {

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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installSchema('system', ['sequences']);
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * Builds a main RequestEvent for the given path and page params.
   *
   * @param string $path
   *   The request path.
   * @param array $pageParams
   *   The page[] query parameter values.
   *
   * @return \Symfony\Component\HttpKernel\Event\RequestEvent
   *   The event.
   */
  private function makeRequestEvent(string $path, array $pageParams = []): RequestEvent {
    $request = Request::create($path);
    if ($pageParams) {
      $request->query->set('page', $pageParams);
    }
    /** @var \Symfony\Component\HttpKernel\HttpKernelInterface $kernel */
    $kernel = $this->container->get('http_kernel');
    return new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
  }

  /**
   * Enables governance for the current anonymous user via OAuth context mock.
   *
   * Since the kernel test environment cannot issue OAuth tokens, we use the
   * governed_roles approach: add 'mcp_api' to governed_roles in settings and
   * place that role on the current user via the current user mock. The
   * role-fallback path is enabled (governed_role_fallback = TRUE).
   *
   * In kernel tests the current user is anonymous; we switch it to a minimal
   * user entity that holds the mcp_api role, then configure settings to
   * match. The 'mcp_api' role must be listed in governed_roles; the default
   * profile (no roles configured) is the fallback that resolves for any
   * governed account without a more specific match.
   */
  private function switchToGovernedUser(): void {
    // Ensure the mcp_api role exists.
    if (!\Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }

    // Add mcp_api to governed_roles and enable the role-fallback path.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Create an authenticated user holding the mcp_api role and switch to it.
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
  }

  /**
   * Governed request with page[limit] above the cap throws a 400.
   */
  public function testOverCapThrowsBadRequest(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    /** @var \Drupal\mcp_sentinel\EventSubscriber\McpJsonApiPageLimitSubscriber $subscriber */
    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');

    $event = $this->makeRequestEvent('/jsonapi/node/article', ['limit' => 500]);
    $this->expectException(BadRequestHttpException::class);
    $this->expectExceptionMessageMatches('/500.*10|cap.*10/i');
    $subscriber->onRequest($event);
  }

  /**
   * Governed request with page[limit] at the cap passes through.
   */
  public function testAtCapPassesThrough(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/jsonapi/node/article', ['limit' => 10]);
    // Should not throw — BadRequestHttpException would fail the test.
    $subscriber->onRequest($event);
    $this->assertSame(10, (int) $event->getRequest()->query->all('page')['limit'],
      'Request must not be modified when limit is at or below the cap.');
  }

  /**
   * When cap is 0 (unlimited), any limit passes through.
   */
  public function testUnlimitedCapPassesAnyLimit(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 0)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/jsonapi/node/article', ['limit' => 50000]);
    // Should not throw — BadRequestHttpException would fail the test.
    $subscriber->onRequest($event);
    $this->assertSame(50000, (int) $event->getRequest()->query->all('page')['limit'],
      'Request must not be modified when cap is 0 (unlimited).');
  }

  /**
   * Non-governed requests (no fallback, no matching profile) are not capped.
   */
  public function testNonGovernedRequestNotCapped(): void {
    // No governed_role_fallback → policy resolver returns NULL for any user.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', FALSE)
      ->set('governed_roles', [])
      ->save();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/jsonapi/node/article', ['limit' => 50000]);
    // Should not throw for ungoverned request.
    $subscriber->onRequest($event);
    $this->assertSame(50000, (int) $event->getRequest()->query->all('page')['limit'],
      'Ungoverned requests must not be capped.');
  }

  /**
   * Non-JSON:API paths are ignored entirely.
   */
  public function testNonJsonApiPathIgnored(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/api/nodes', ['limit' => 50000]);
    // Should not throw for non-JSON:API path.
    $subscriber->onRequest($event);
    $this->assertSame(50000, (int) $event->getRequest()->query->all('page')['limit'],
      'Non-JSON:API paths must not be affected by the subscriber.');
  }

  /**
   * An /admin path with page[limit] is not affected by the subscriber.
   */
  public function testAdminPathIgnored(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/admin/content', ['limit' => 50000]);
    $subscriber->onRequest($event);
    $this->assertSame(50000, (int) $event->getRequest()->query->all('page')['limit'],
      '/admin path must not be affected by the JSON:API page-limit subscriber.');
  }

  /**
   * Language-prefixed /en/jsonapi/... path is still capped (Fix 2: i18n).
   *
   * URL language negotiation prepends a language code, producing paths like
   * /en/jsonapi/node/article. The original str_starts_with('/jsonapi/') check
   * silently missed these paths. str_contains('/jsonapi/') matches them.
   */
  public function testLanguagePrefixedJsonApiPathIsCapped(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/en/jsonapi/node/article', ['limit' => 500]);
    $this->expectException(BadRequestHttpException::class);
    $this->expectExceptionMessageMatches('/500.*10|cap.*10/i');
    $subscriber->onRequest($event);
  }

  /**
   * Language-prefixed /en/jsonapi/... path at cap passes through.
   */
  public function testLanguagePrefixedJsonApiAtCapPassesThrough(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/en/jsonapi/node/article', ['limit' => 10]);
    $subscriber->onRequest($event);
    $this->assertSame(10, (int) $event->getRequest()->query->all('page')['limit'],
      'Language-prefixed request at the cap must pass through.');
  }

  /**
   * A page[limit]=0 value is ignored (left for JSON:API's own validation).
   *
   * Fix 3: non-positive limits must not trigger a cap comparison.
   */
  public function testZeroPageLimitIsIgnored(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/jsonapi/node/article', ['limit' => 0]);
    // Must not throw — page[limit]=0 is for JSON:API to validate.
    $subscriber->onRequest($event);
    $this->assertSame(0, (int) $event->getRequest()->query->all('page')['limit'],
      'page[limit]=0 must be passed through without a cap exception.');
  }

  /**
   * A negative page[limit] is ignored (left for JSON:API's own validation).
   */
  public function testNegativePageLimitIsIgnored(): void {
    $this->switchToGovernedUser();
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 10)->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $subscriber = $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
    $event = $this->makeRequestEvent('/jsonapi/node/article', ['limit' => -5]);
    // Must not throw.
    $subscriber->onRequest($event);
    $this->assertSame(-5, (int) $event->getRequest()->query->all('page')['limit'],
      'Negative page[limit] must be passed through without a cap exception.');
  }

}
