namespace Chiota.Views
{
  using System;

  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The login page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class LoginPage : ContentPage
  {
    public LoginPage()
    {
      this.InitializeComponent();
      NavigationPage.SetHasNavigationBar(this, false);
      var vm = new LoginViewModel { Navigation = this.Navigation };

      vm.DisplayInvalidLoginPrompt += () => this.DisplayAlert("Error", "Invalid seed, try again", "OK");

      this.RandomSeed.Completed += (object sender, EventArgs e) =>
        {
          vm.SubmitCommand.Execute(null);
        };
      this.BindingContext = vm;
    }
  }
}