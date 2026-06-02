<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Records per-user dismissals of the site-wide urgent banner.
 *
 * The dismissal is stored in the private tempstore keyed by the urgent
 * condition's machine key. While the condition still holds, the banner
 * reappears once the tempstore entry expires (or in a new session); a dismissal
 * only suppresses the currently visible occurrence for this user.
 */
class McpBannerController extends ControllerBase {

  /**
   * The tempstore collection name.
   */
  private const COLLECTION = 'mcp_sentinel.banner';

  /**
   * The tempstore key holding the dismissed condition keys.
   */
  private const STORE_KEY = 'dismissed';

  /**
   * Constructs an McpBannerController.
   *
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $tempStoreFactory
   *   The private tempstore factory.
   */
  public function __construct(
    private readonly PrivateTempStoreFactory $tempStoreFactory,
  ) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('tempstore.private'),
    );
  }

  /**
   * Records a dismissal of one urgent-condition key for the current user.
   *
   * CSRF-protected (route requirement). Accepts the condition machine key in
   * the `key` request parameter.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return \Symfony\Component\HttpFoundation\JsonResponse
   *   A small JSON acknowledgement.
   */
  public function dismiss(Request $request): JsonResponse {
    // Accept the condition key from either a POST body (the dashboard JS) or a
    // GET query parameter.
    $key = trim((string) ($request->request->get('key') ?? $request->query->get('key', '')));
    if ($key === '') {
      return new JsonResponse(['dismissed' => FALSE], 400);
    }
    $store = $this->tempStoreFactory->get(self::COLLECTION);
    $dismissed = (array) ($store->get(self::STORE_KEY) ?? []);
    $dismissed[$key] = TRUE;
    $store->set(self::STORE_KEY, $dismissed);
    return new JsonResponse(['dismissed' => TRUE]);
  }

  /**
   * Returns the set of condition keys this user has dismissed.
   *
   * @param \Drupal\Core\TempStore\PrivateTempStoreFactory $tempStoreFactory
   *   The private tempstore factory.
   *
   * @return array<string, bool>
   *   A map of dismissed condition keys.
   */
  public static function dismissedKeys(PrivateTempStoreFactory $tempStoreFactory): array {
    $store = $tempStoreFactory->get(self::COLLECTION);
    return (array) ($store->get(self::STORE_KEY) ?? []);
  }

}
