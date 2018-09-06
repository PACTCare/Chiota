namespace Chiota.Controls.Validations
{
  using Chiota.ViewModels.Authentication;
  using Chiota.ViewModels.BackUp;

  using Tangle.Net.Entity;
  using Tangle.Net.Utils;

  using Xamarin.Forms;

  /// <summary>
  /// The seed validation entry.
  /// </summary>
  public class SeedValidationEntry : ValidationEntry
  {
    public SeedValidationEntry()
    {
      this.entry.TextChanged += this.OnTextChanged;
    }

    protected override bool Validate(string text)
    {
      this.IsValid = false;
      return !string.IsNullOrEmpty(text) && InputValidator.IsTrytes(text, Seed.Length);
    }

    private void OnTextChanged(object sender, TextChangedEventArgs e)
    {
      if (this.BindingContext is ConfirmSeedViewModel confirmSeedModel)
      {
        confirmSeedModel.Seed = this.entry.Text;
      }

      if (this.BindingContext is SetSeedViewModel setSeedModel)
      {
        setSeedModel.Seed = this.entry.Text;
      }
    }
  }
}