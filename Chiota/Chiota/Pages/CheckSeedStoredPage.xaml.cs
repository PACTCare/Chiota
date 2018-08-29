namespace Chiota.Views
{
  using System;

  using Chiota.Models;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The check seed stored page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class CheckSeedStoredPage : ContentPage
  {
    public CheckSeedStoredPage(User user)
    {
      this.InitializeComponent();
      NavigationPage.SetHasNavigationBar(this, false);
      var vm = new CheckSeedStoredViewModel(user) { Navigation = this.Navigation };

      vm.DisplayInvalidSeedPrompt += () => this.DisplayAlert("Incorrect Seed", "The seed you entered is incorrect. Please try again.", "OK");

      this.SeedInput.Completed += (object sender, EventArgs e) =>
        {
          vm.SubmitCommand.Execute(null);
        };
      this.BindingContext = vm;
    }
  }
}