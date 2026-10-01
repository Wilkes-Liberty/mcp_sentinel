<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\TempStore\PrivateTempStoreFactory;
use Drupal\Core\Url;
use Drupal\mcp_sentinel\Service\McpAdminStatus;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Mints a short-lived sealed token bound to a designated agent client.
 *
 * The raw secret is written to private tempstore and shown once on the
 * reveal page. Leaving that page (or refreshing) drops the secret.
 */
final class McpSealedTokenMintForm extends FormBase {

  /**
   * Sealed token manager.
   */
  protected McpSealedTokenManager $tokens;

  /**
   * Admin status strip assembler.
   */
  protected McpAdminStatus $adminStatus;

  /**
   * Private tempstore factory for the copy-once reveal payload.
   */
  protected PrivateTempStoreFactory $tempStoreFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): static {
    $instance = parent::create($container);
    $instance->tokens = $container->get('mcp_sentinel.sealed_token_manager');
    $instance->adminStatus = $container->get('mcp_sentinel.admin_status');
    $instance->tempStoreFactory = $container->get('tempstore.private');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'mcp_sentinel_sealed_token_mint';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $clients = $this->tokens->designatedClientIds();
    if ($clients === []) {
      $form['empty'] = [
        '#markup' => '<p>' . $this->t('No designated agent client is configured. Add a Consumer and list its client_id under OAuth agent channel before minting a token.') . '</p>',
      ];
      $add = $this->adminStatus->build()['add_client_url'] ?? '';
      if (is_string($add) && $add !== '') {
        $form['add'] = [
          '#type' => 'link',
          '#title' => $this->t('Add agent client'),
          '#url' => Url::fromUserInput($add),
          '#attributes' => ['class' => ['button', 'button--primary']],
        ];
      }
      return $form;
    }

    $options = array_combine($clients, $clients);
    $form['client_id'] = [
      '#type' => 'select',
      '#title' => $this->t('Agent client'),
      '#description' => $this->t('The token is bound to this designated client_id. It cannot be used by another Consumer.'),
      '#options' => $options,
      '#required' => TRUE,
      '#default_value' => array_key_first($options),
    ];
    $form['ttl'] = [
      '#type' => 'select',
      '#title' => $this->t('Lifetime'),
      '#description' => $this->t('Short TTL only. Maximum is 24 hours. Revoke the token if it leaks.'),
      '#options' => McpSealedTokenManager::TTL_CHOICES,
      '#default_value' => McpSealedTokenManager::DEFAULT_TTL,
      '#required' => TRUE,
    ];
    $form['actions'] = [
      '#type' => 'actions',
      'submit' => [
        '#type' => 'submit',
        '#value' => $this->t('Mint sealed token'),
        '#button_type' => 'primary',
      ],
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    try {
      $issued = $this->tokens->mint(
        (string) $form_state->getValue('client_id'),
        (int) $form_state->getValue('ttl'),
        $this->currentUser(),
      );
    }
    catch (\InvalidArgumentException $e) {
      $this->messenger()->addError($e->getMessage());
      return;
    }

    $this->tempStoreFactory->get('mcp_sentinel_sealed_token', McpSealedTokenManager::REVEAL_STORE_TTL)->set('reveal', [
      'jti' => $issued['jti'],
      'token' => $issued['token'],
      'client_id' => $issued['client_id'],
      'expires' => $issued['expires'],
      'ttl' => $issued['ttl'],
      'scopes' => $issued['scopes'],
    ]);
    $form_state->setRedirect('mcp_sentinel.sealed_token_reveal');
  }

}
