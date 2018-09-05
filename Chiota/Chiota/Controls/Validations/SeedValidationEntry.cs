namespace Chiota.Controls.Validations
{
  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  /// <summary>
  /// The seed validation entry.
  /// </summary>
  public class SeedValidationEntry : ValidationEntry
  {
    /// <summary>
    /// The validate.
    /// </summary>
    /// <param name="text">
    /// The text.
    /// </param>
    /// <returns>
    /// The <see cref="bool"/>.
    /// </returns>
    protected override bool Validate(string text)
    {
      this.IsValid = false;
      return !string.IsNullOrEmpty(text) && InputValidator.IsTrytes(text, Seed.Length);
    }
  }
}