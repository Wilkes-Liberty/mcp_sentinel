<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\EventSubscriber\AuthenticationSubscriber;
use Drupal\Core\PrivateKey;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Log\LoggerInterface;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpFoundation\Request;

/**
 * Reproduces the downstream DLP cycle on authentication_subscriber.
 *
 * DLP is rebuilt through a factory that takes authentication_subscriber
 * so a live sealed-token manager argument closes the same collector
 * cycle downstream sites hit (DEV-1014). Audit logging treats DLP as
 * optional, so the manager factory is closed through the subscriber
 * as well. The tagged provider must not construct the manager during
 * collector init.
 *
 * The closer is applied after KernelTestBase installs modules. Role
 * creation during install can construct audit logging, and applying
 * the closer on that first container would error setUp instead of
 * failing an assertion.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Authentication\McpSealedTokenAuthProvider
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSealedTokenAuthProvider::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSealedTokenAuthCycleTest extends KernelTestBase {

  /**
   * Whether register() should close DLP back to authentication_subscriber.
   *
   * Static so a container rebuild still sees the flag if Drupal
   * constructs a new service-provider instance of this class.
   */
  private static bool $closeDownstreamDlpCycle = FALSE;

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
    'image',
    'options',
    'path_alias',
    'serialization',
    'jsonapi',
    'tool',
    'key',
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
    self::$closeDownstreamDlpCycle = TRUE;
    // rebuildContainer() alone reloads the dumped container from the first
    // compile, which never ran the three-argument factory. Invalidate so
    // the kernel compiles again with the downstream closer in place.
    $this->container->get('kernel')->invalidateContainer();
    $this->container->get('kernel')->rebuildContainer();
    // @phpstan-ignore assign.propertyType
    $this->container = $this->container->get('kernel')->getContainer();
    \Drupal::setContainer($this->container);
  }

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    self::$closeDownstreamDlpCycle = FALSE;
    parent::tearDown();
  }

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    parent::register($container);
    if (!self::$closeDownstreamDlpCycle
      || !$container->hasDefinition('mcp_sentinel.dlp')
      || !$container->hasDefinition('mcp_sentinel.sealed_token_manager')) {
      return;
    }
    // Extra YAML arguments on the userland factory are dropped by the
    // compiled container. A three-argument factory forces Symfony to
    // resolve authentication_subscriber when DLP is first built.
    // Use Class::method, not [self::class, 'method']: KernelTestBase
    // registers this test class as a synthetic service, and Symfony
    // would treat the array form as an instance factory on that ID.
    $container->getDefinition('mcp_sentinel.dlp')
      ->setFactory(self::class . '::createDlpClosingSubscriberCycle')
      ->setArguments([
        new Reference('config.factory'),
        new Reference('logger.channel.mcp_sentinel'),
        new Reference('authentication_subscriber'),
      ]);
    // McpAuditLogger::$dlp is optional. A live manager can construct
    // without resolving DLP, so the DLP closer never runs. Closing the
    // manager factory through authentication_subscriber forces the
    // collector cycle when the provider takes a live manager.
    $manager = $container->getDefinition('mcp_sentinel.sealed_token_manager');
    $arguments = $manager->getArguments();
    $arguments[] = new Reference('authentication_subscriber');
    $manager
      ->setFactory(self::class . '::createManagerClosingSubscriberCycle')
      ->setArguments($arguments);
  }

  /**
   * Builds DLP after resolving authentication_subscriber.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The mcp_sentinel logger channel.
   * @param object $subscriber
   *   The authentication_subscriber service, resolved to close the
   *   downstream cycle.
   *
   * @return \Drupal\mcp_sentinel\Service\McpDlp
   *   The production DLP service.
   */
  public static function createDlpClosingSubscriberCycle(
    ConfigFactoryInterface $configFactory,
    LoggerInterface $logger,
    object $subscriber,
  ): McpDlp {
    if (!$subscriber instanceof AuthenticationSubscriber) {
      throw new \LogicException(
        'authentication_subscriber is required to close the DLP cycle.',
      );
    }
    return McpDlp::createFromConfig($configFactory, $logger);
  }

  /**
   * Builds the manager after resolving authentication_subscriber.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   The UUID service.
   * @param \Drupal\Core\PrivateKey $privateKey
   *   The site private key.
   * @param \Drupal\Core\Site\Settings $settings
   *   The site settings.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger $auditLogger
   *   The audit logger.
   * @param \Drupal\mcp_sentinel\Service\McpSealedTokenDenialAuditor $denialAuditor
   *   Sealed-token denial auditor.
   * @param object $subscriber
   *   The authentication_subscriber service, resolved to close the
   *   collector cycle.
   *
   * @return \Drupal\mcp_sentinel\Service\McpSealedTokenManager
   *   The production token manager.
   */
  public static function createManagerClosingSubscriberCycle(
    Connection $database,
    ConfigFactoryInterface $configFactory,
    EntityTypeManagerInterface $entityTypeManager,
    TimeInterface $time,
    UuidInterface $uuid,
    PrivateKey $privateKey,
    Settings $settings,
    McpAuditLogger $auditLogger,
    McpSealedTokenDenialAuditor $denialAuditor,
    object $subscriber,
  ): McpSealedTokenManager {
    if (!$subscriber instanceof AuthenticationSubscriber) {
      throw new \LogicException(
        'authentication_subscriber is required to close the manager cycle.',
      );
    }
    return new McpSealedTokenManager(
      $database,
      $configFactory,
      $entityTypeManager,
      $time,
      $uuid,
      $privateKey,
      $settings,
      $auditLogger,
      $denialAuditor,
    );
  }

  /**
   * Resolving authentication_subscriber succeeds when the manager is deferred.
   */
  public function testAuthenticationSubscriberResolvesWithDownstreamDlpCycle(): void {
    $this->assertCycleClosersCompiled();
    try {
      $this->container->get('authentication_subscriber');
    }
    catch (\Throwable $exception) {
      $this->fail(
        'authentication_subscriber must resolve when the '
        . 'sealed-token manager is deferred; got '
        . $exception::class
        . ': '
        . $exception->getMessage(),
      );
    }
    $this->assertTrue(
      $this->container->initialized('authentication_subscriber'),
    );
    $this->assertTrue(
      $this->container->initialized('mcp_sentinel.sealed_token_auth'),
      'sealed_token_auth must be constructed with the collector.',
    );
    $this->assertFalse(
      $this->container->initialized('mcp_sentinel.sealed_token_manager'),
      'sealed_token_manager must stay uninitialized until authenticate().',
    );
  }

  /**
   * A forged mcs1. bearer through the cycled graph is a deny, not an exception.
   */
  public function testForgedBearerThroughCycledGraphReturnsNull(): void {
    $this->assertCycleClosersCompiled();
    try {
      $this->container->get('authentication_subscriber');
    }
    catch (\Throwable $exception) {
      $this->fail(
        'authentication_subscriber must resolve when the '
        . 'sealed-token manager is deferred; got '
        . $exception::class
        . ': '
        . $exception->getMessage(),
      );
    }
    $provider = $this->container->get('mcp_sentinel.sealed_token_auth');
    $request = Request::create('/jsonapi');
    $request->headers->set(
      'Authorization',
      'Bearer ' . McpSealedTokenManager::PREFIX . 'forged.not.real',
    );
    try {
      $account = $provider->authenticate($request);
    }
    catch (\Throwable $exception) {
      $this->fail(
        'forged bearer must deny without throwing; got '
        . $exception::class
        . ': '
        . $exception->getMessage(),
      );
    }
    $this->assertNull($account);
    $this->assertFalse(
      $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE),
    );
  }

  /**
   * Asserts the rebuilt container kept the DLP and manager closers.
   */
  private function assertCycleClosersCompiled(): void {
    $this->assertCloserFactory(
      'mcp_sentinel.dlp',
      'createDlpClosingSubscriberCycle',
      3,
    );
    $this->assertCloserFactory(
      'mcp_sentinel.sealed_token_manager',
      'createManagerClosingSubscriberCycle',
      10,
    );
  }

  /**
   * Asserts a service definition kept its closer factory and argument count.
   *
   * @param string $serviceId
   *   The service ID.
   * @param string $factoryMethod
   *   The closer factory method name.
   * @param int $argumentCount
   *   Expected constructor/factory argument count.
   */
  private function assertCloserFactory(
    string $serviceId,
    string $factoryMethod,
    int $argumentCount,
  ): void {
    $definition = $this->container->getDefinition($serviceId);
    $factory = $definition->getFactory();
    if (is_string($factory)) {
      $this->assertStringContainsString(
        $factoryMethod,
        $factory,
        $serviceId . ' must use the closer factory.',
      );
    }
    else {
      $this->assertIsArray($factory);
      $this->assertArrayHasKey(1, $factory);
      $this->assertSame(
        $factoryMethod,
        $factory[1],
        $serviceId . ' must use the closer factory.',
      );
    }
    $this->assertCount(
      $argumentCount,
      $definition->getArguments(),
      $serviceId . ' closer must keep the authentication_subscriber argument.',
    );
  }

}
