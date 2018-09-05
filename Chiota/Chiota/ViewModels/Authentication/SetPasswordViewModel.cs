namespace Chiota.ViewModels.Authentication
{
  using System.Windows.Input;

  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.Pages.Authentication;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;

  using Xamarin.Forms;

  /// <summary>
  /// The set password view model.
  /// </summary>
  public class SetPasswordViewModel : BaseViewModel
  {
    /// <summary>
    /// The _password.
    /// </summary>
    private string password;

    /// <summary>
    /// The _repeat password.
    /// </summary>
    private string repeatPassword;

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
              if (string.IsNullOrEmpty(this.Password) || string.IsNullOrEmpty(this.RepeatPassword))
              {
                await new MissingUserInputException(new ExcInfo(), Details.AuthMissingUserInputPasswordRepeat).ShowAlertAsync();
              }
              else if (this.Password != this.RepeatPassword)
              { 
                  await new AuthFailedPasswordConfirmationException(new ExcInfo()).ShowAlertAsync();
                  return;
              }

              this.UserProperties.Password = this.Password;
              await this.PushAsync(new SetUserPage(), this.UserProperties);
            });
      }
    }

    /// <summary>
    /// Gets or sets the password.
    /// </summary>
    public string Password
    {
      get => this.password;
      set
      {
        this.password = value;
        this.OnPropertyChanged(nameof(this.Password));
      }
    }

    /// <summary>
    /// Gets or sets the repeat password.
    /// </summary>
    public string RepeatPassword
    {
      get => this.repeatPassword;
      set
      {
        this.repeatPassword = value;
        this.OnPropertyChanged(nameof(this.RepeatPassword));
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
      this.Password = string.Empty;
      this.RepeatPassword = string.Empty;
    }
  }
}