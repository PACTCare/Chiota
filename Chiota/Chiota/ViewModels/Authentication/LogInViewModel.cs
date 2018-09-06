namespace Chiota.ViewModels.Authentication
{
  using System.Windows.Input;

  using Chiota.Exceptions;
  using Chiota.Extensions;
  using Chiota.Pages.Authentication;
  using Chiota.Pages.Help;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels.Classes;
  using Chiota.Views;

  using Xamarin.Forms;

  /// <summary>
  /// The log in view model.
  /// </summary>
  public class LogInViewModel : BaseViewModel
  {
    /// <summary>
    /// The _password.
    /// </summary>
    private string password;

    /// <summary>
    /// Gets the log in command.
    /// </summary>
    public ICommand LogInCommand
    {
      get
      {
        return new Command(
          async () =>
            {
              try
              {
                await SecureStorage.LoginUser(this.Password);
                Application.Current.MainPage = new NavigationPage(new ContactPage());
              }
              catch (BaseException exception)
              {
                await exception.ShowAlertAsync();
              }
            });
      }
    }

    public ICommand NewSeedCommand => new Command(async () => { await this.PushAsync(new NewSeedPage()); });

    public ICommand SeedHelpCommand => new Command(async () => { await this.PushAsync(new SeedHelpPage()); });

    public ICommand SetSeedCommand => new Command(async () => { await this.PushAsync(new SetSeedPage()); });

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

    /// <inheritdoc />
    protected override void ViewIsAppearing()
    {
      base.ViewIsAppearing();

      // Clear the user inputs.
      this.Password = string.Empty;
    }
  }
}