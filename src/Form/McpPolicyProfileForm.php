<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Form;

use Drupal\Core\Config\Entity\ConfigEntityBase;
use Drupal\Core\Entity\EntityForm;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Form\FormStateInterface;

/**
 * Add/edit form for an MCP policy profile.
 */
final class McpPolicyProfileForm extends EntityForm {

  /**
   * {@inheritdoc}
   */
  public function form(array $form, FormStateInterface $form_state): array {
    $form = parent::form($form, $form_state);
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = $this->entity;

    $form['label'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Label'),
      '#default_value' => $profile->label(),
      '#required' => TRUE,
    ];
    $form['id'] = [
      '#type' => 'machine_name',
      '#default_value' => $profile->id(),
      '#machine_name' => [
        'exists' => '\Drupal\mcp_sentinel\Entity\McpPolicyProfile::load',
      ],
      '#disabled' => !$profile->isNew(),
    ];
    $form['status'] = [
      '#type' => 'checkbox',
      '#title' => $this->t('Enabled'),
      '#description' => $this->t('Disabled profiles are ignored by the resolver; governed agents matching only a disabled profile fall back to the default.'),
      '#default_value' => $profile->status(),
    ];

    /** @var \Drupal\user\RoleInterface[] $roles */
    $roles = $this->entityTypeManager->getStorage('user_role')->loadMultiple();
    $role_options = [];
    foreach ($roles as $rid => $role) {
      $role_options[$rid] = (string) $role->label();
    }
    // anonymous/authenticated would govern all (or unauthenticated) traffic.
    unset($role_options['anonymous'], $role_options['authenticated']);

    $form['roles'] = [
      '#type' => 'checkboxes',
      '#title' => $this->t('Roles'),
      '#description' => $this->t(
        'Apply this profile to agents holding any of these roles. Leave empty for the default profile that applies to every governed agent without a more specific match.'
      ),
      '#options' => $role_options,
      '#default_value' => $profile->getRoles(),
    ];
    $form['weight'] = [
      '#type' => 'number',
      '#title' => $this->t('Weight'),
      '#description' => $this->t(
        'Higher weight wins when multiple profiles match an agent.'
      ),
      '#default_value' => $profile->getWeight(),
    ];

    $form['gates'] = [
      '#type' => 'fieldset',
      '#title' => $this->t('Allowed operations'),
    ];
    foreach ([
      'allow_read' => $this->t('Allow read'),
      'allow_write' => $this->t('Allow write (create, update)'),
      'allow_delete' => $this->t('Allow delete'),
      'allow_graphql_mutations' => $this->t('Allow GraphQL mutations'),
    ] as $key => $label) {
      $form['gates'][$key] = [
        '#type' => 'checkbox',
        '#title' => $label,
        '#default_value' => $profile->get($key),
      ];
    }

    $lines = static fn (array $v): string => implode("\n", $v);
    $form['allowed_entity_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed entity types (empty = all)'),
      '#default_value' => $lines($profile->getAllowedEntityTypes()),
      '#rows' => 3,
    ];
    $form['denied_entity_types'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Denied entity types'),
      '#default_value' => $lines($profile->getDeniedEntityTypes()),
      '#rows' => 3,
    ];
    $form['redacted_fields'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Redacted fields'),
      '#default_value' => $lines($profile->getRedactedFields()),
      '#rows' => 3,
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   *
   * Override the default copy to skip fields that need manual conversion.
   * The textarea and checkboxes fields return strings/arrays that must be
   * converted before assignment to the typed entity properties; they are
   * handled explicitly in save() instead.
   */
  protected function copyFormValuesToEntity(
    EntityInterface $entity,
    array $form,
    FormStateInterface $form_state,
  ): void {
    // These fields need custom conversion in save(); skip auto-copy.
    $manual = [
      'allowed_entity_types',
      'denied_entity_types',
      'redacted_fields',
      'roles',
      'status',
      'allow_read',
      'allow_write',
      'allow_delete',
      'allow_graphql_mutations',
    ];
    assert($entity instanceof ConfigEntityBase);
    foreach ($form_state->getValues() as $key => $value) {
      if (!in_array($key, $manual, TRUE)) {
        $entity->set($key, $value);
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function save(array $form, FormStateInterface $form_state): int {
    /** @var \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile */
    $profile = $this->entity;
    $split = static fn (string $v): array => array_values(
      array_filter(array_map('trim', explode("\n", $v)))
    );

    $profile->setStatus((bool) $form_state->getValue('status'));
    $profile->set(
      'roles',
      array_values(array_filter($form_state->getValue('roles')))
    );
    foreach ([
      'allow_read',
      'allow_write',
      'allow_delete',
      'allow_graphql_mutations',
    ] as $key) {
      $profile->set($key, (bool) $form_state->getValue($key));
    }
    $profile->set(
      'allowed_entity_types',
      $split($form_state->getValue('allowed_entity_types'))
    );
    $profile->set(
      'denied_entity_types',
      $split($form_state->getValue('denied_entity_types'))
    );
    $profile->set(
      'redacted_fields',
      $split($form_state->getValue('redacted_fields'))
    );

    $status = $profile->save();
    $this->messenger()->addStatus(
      $this->t('Saved the %label profile.', ['%label' => $profile->label()])
    );
    $form_state->setRedirectUrl($profile->toUrl('collection'));
    return $status;
  }

}
