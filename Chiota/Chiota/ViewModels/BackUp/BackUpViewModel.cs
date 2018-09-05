namespace Chiota.ViewModels.BackUp
{
  using System.Windows.Input;

  using Chiota.Annotations;
  using Chiota.Pages.BackUp;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The back up view model.
  /// </summary>
  public class BackUpViewModel : BaseViewModel
  {
    private bool isContinueVisible;

    public ICommand ContinueCommand => new Command(async () => { await this.PushAsync(new ConfirmSeedPage(), this.UserProperties); });

    [UsedImplicitly]
    public ICommand PrintPaperCommand => new Command(async () => { await this.PushAsync(new PaperCopyPage(), this.UserProperties.Seed.Value); });

    public ICommand QrCodeCommand => new Command(async () => { await this.PushAsync(new QrCodePage(), this.UserProperties.Seed.Value); });

    public ICommand WriteSeedCommand => new Command(async () => { await this.PushAsync(new WriteSeedPage(), this.UserProperties.Seed.Value); });

    private UserCreationProperties UserProperties { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether is continue visible.
    /// </summary>
    public bool IsContinueVisible
    {
      get => this.isContinueVisible;
      set
      {
        this.isContinueVisible = value;
        this.OnPropertyChanged(nameof(this.IsContinueVisible));
      }
    }

    /// <inheritdoc />
    public override void Init(object data = null)
    {
      base.Init(data);

      // Set the generated iota seed.
      if (data != null)
      {
        this.UserProperties = data as UserCreationProperties;
      }

      // Disable the continue button.
      this.IsContinueVisible = true;
    }

    /// <inheritdoc />
    public override void Reverse(object data = null)
    {
      base.Reverse(data);

      // Enable the continue button.
      this.IsContinueVisible = true;
    }
  }
}