namespace Chiota.ViewModels.BackUp
{
  using System.Windows.Input;

  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.Pages.Authentication;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Tangle.Net.Utils;

  using Xamarin.Forms;

  using ZXing.Net.Mobile.Forms;

  /// <summary>
  /// The confirm seed view model.
  /// </summary>
  public class ConfirmSeedViewModel : BaseViewModel
  {
    /// <summary>
    /// The expected seed.
    /// </summary>
    private string seed;

    /// <summary>
    /// Gets the continue command.
    /// </summary>
    public ICommand ContinueCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              // TODO: Seed does not get written to
              await this.PushAsync(new SetPasswordPage(), this.UserProperties);
              return;

              if (!string.IsNullOrEmpty(this.Seed))
              {
                if (!InputValidator.IsTrytes(this.Seed))
                {
                  await new InvalidUserInputException(new ExcInfo(), Details.BackUpInvalidUserInputSeed).ShowAlertAsync();
                  return;
                }

                if (this.Seed != this.UserProperties.Seed.Value)
                {
                  await new BackUpFailedSeedConfirmationException(new ExcInfo()).ShowAlertAsync();
                  return;
                }

                await this.PushAsync(new SetPasswordPage(), this.UserProperties);
                return;
              }

              await new MissingUserInputException(new ExcInfo(), Details.BackUpInvalidUserInputSeed).ShowAlertAsync();
            });
      }
    }

    /// <summary>
    /// Gets the scan qr code command.
    /// </summary>
    public ICommand ScanQrCodeCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              // Scan a qr code and insert the result into the entry.
              var scanPage = new ZXingScannerPage();
              scanPage.OnScanResult += (result) =>
                {
                  scanPage.IsScanning = false;

                  Device.BeginInvokeOnMainThread(
                    () =>
                      {
                        this.Navigation.PopAsync();
                        this.Seed = result.Text;
                      });
                };

              await this.PushAsync(scanPage);
            });
      }
    }

    /// <summary>
    /// Gets or sets the seed.
    /// </summary>
    public string Seed
    {
      get => this.seed;
      set
      {
        this.seed = value;
        this.OnPropertyChanged(nameof(this.Seed));
      }
    }

    private UserCreationProperties UserProperties { get; set; }

    /// <inheritdoc />
    public override void Init(object data = null)
    {
      base.Init(data);
      this.UserProperties = data as UserCreationProperties;
    }

    /// <inheritdoc />
    protected override void ViewIsAppearing()
    {
      base.ViewIsAppearing();

      // Clear the user inputs.
      this.Seed = string.Empty;
    }
  }
}