<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the DLP patterns multi-row editor on the settings form.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpSettingsDlpEditorTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Stored patterns render as rows and round-trip byte-identically.
   */
  public function testExistingPatternsRenderAsRowsAndRoundTrip(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_patterns', [
        ['label' => 'employee_id', 'regex' => 'EMP-\\d{6}', 'mask' => '*'],
        ['label' => 'badge', 'regex' => 'B-\\d{4}', 'mask' => '#'],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    // Two rows rendered with the stored values.
    $this->assertSession()->fieldValueEquals('dlp_patterns_rows[0][label]', 'employee_id');
    $this->assertSession()->fieldValueEquals('dlp_patterns_rows[0][regex]', 'EMP-\\d{6}');
    $this->assertSession()->fieldValueEquals('dlp_patterns_rows[1][label]', 'badge');
    // Save unchanged → identical stored sequence.
    $this->submitForm([], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('dlp_patterns');
    $this->assertSame([
      ['label' => 'employee_id', 'regex' => 'EMP-\\d{6}', 'mask' => '*'],
      ['label' => 'badge', 'regex' => 'B-\\d{4}', 'mask' => '#'],
    ], $stored);
  }

  /**
   * An optional classification label round-trips; a blank one is omitted.
   */
  public function testClassificationRoundTripsAndBlankIsOmitted(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_patterns', [
        [
          'label' => 'employee_id',
          'regex' => 'EMP-\\d{6}',
          'mask' => '*',
          'classification' => 'restricted',
        ],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->assertSession()->fieldValueEquals('dlp_patterns_rows[0][classification]', 'restricted');
    $this->submitForm([
      'dlp_patterns_rows[1][label]' => 'badge',
      'dlp_patterns_rows[1][regex]' => 'B-\\d{4}',
      'dlp_patterns_rows[1][mask]' => '*',
      'dlp_patterns_rows[1][classification]' => '',
    ], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('dlp_patterns');
    $this->assertSame([
      [
        'label' => 'employee_id',
        'regex' => 'EMP-\\d{6}',
        'mask' => '*',
        'classification' => 'restricted',
      ],
      ['label' => 'badge', 'regex' => 'B-\\d{4}', 'mask' => '*'],
    ], $stored);
  }

  /**
   * Adding a row appends in the same shape; removing a row drops it.
   */
  public function testAddAndRemoveRowMutateStoredSequence(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_patterns', [
        ['label' => 'employee_id', 'regex' => 'EMP-\\d{6}', 'mask' => '*'],
      ])->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    // One stored row + one blank trailing row. Fill the blank row and add a new
    // one via the AJAX button, then fill and save.
    $this->submitForm([
      'dlp_patterns_rows[1][label]' => 'badge',
      'dlp_patterns_rows[1][regex]' => 'B-\\d{4}',
      'dlp_patterns_rows[1][mask]' => '#',
    ], 'Add pattern');
    // A new blank row appeared at index 2; fill it.
    $this->submitForm([
      'dlp_patterns_rows[2][label]' => 'ticket',
      'dlp_patterns_rows[2][regex]' => 'T-\\d{3}',
      'dlp_patterns_rows[2][mask]' => 'x',
    ], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('dlp_patterns');
    $this->assertSame([
      ['label' => 'employee_id', 'regex' => 'EMP-\\d{6}', 'mask' => '*'],
      ['label' => 'badge', 'regex' => 'B-\\d{4}', 'mask' => '#'],
      ['label' => 'ticket', 'regex' => 'T-\\d{3}', 'mask' => 'x'],
    ], $stored);

    // Now remove the MIDDLE data row (badge) via its own Remove button and
    // save. Per-row removal drops exactly that row; the others persist.
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([], 'Remove pattern 2');
    $this->submitForm([], 'Save configuration');
    $stored = \Drupal::config('mcp_sentinel.settings')->get('dlp_patterns');
    $this->assertSame([
      ['label' => 'employee_id', 'regex' => 'EMP-\\d{6}', 'mask' => '*'],
      ['label' => 'ticket', 'regex' => 'T-\\d{3}', 'mask' => 'x'],
    ], $stored);
  }

  /**
   * A row with an invalid regex is rejected.
   */
  public function testInvalidRegexRowRejected(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)->save();
    $this->drupalLogin($this->drupalCreateUser(['administer mcp sentinel']));
    $this->drupalGet('/admin/config/services/mcp-sentinel');
    $this->submitForm([
      'dlp_patterns_rows[0][label]' => 'bad',
      'dlp_patterns_rows[0][regex]' => '(unclosed',
    ], 'Save configuration');
    $this->assertSession()->pageTextContains('invalid regular expression');
  }

}
