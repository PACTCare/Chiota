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
      entry.TextChanged += OnTextChanged;
    }

    protected override bool Validate(string text)
    {
      IsValid = false;
      return !string.IsNullOrEmpty(text) && InputValidator.IsTrytes(text, Seed.Length);
    }

    private void OnTextChanged(object sender, TextChangedEventArgs e)
    {
      if (BindingContext is ConfirmSeedViewModel confirmSeedModel)
      {
        confirmSeedModel.Seed = entry.Text;
      }

      if (BindingContext is SetSeedViewModel setSeedModel)
      {
        setSeedModel.Seed = entry.Text;
      }
    }
  }
}