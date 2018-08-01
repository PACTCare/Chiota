using Chiota.Extensions;
using Chiota.Popups.PopupModels;
using Chiota.Popups.PopupPageModels;
using Chiota.Popups.PopupPages;

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

            vm.DisplayInvalidLoginPrompt += async () =>
            {
                //this.DisplayAlert("Error", "Invalid seed, try again", "OK");
                var alert = new AlertPopupModel()
                {
                    Title = "Error",
                    Message = "Invalid seed, try again"
                };
                await Navigation.DisplayPopupAsync<AlertPopupPageModel, AlertPopupModel>(new AlertPopupPage(), alert);
            };
      vm.DisplaySeedCopiedPrompt += () => this.DisplayAlert("Copied", "The seed has been copied to your clipboard.", "OK");

      this.RandomSeed.Completed += (object sender, EventArgs e) =>
        {
          vm.SubmitCommand.Execute(null);
        };
      this.BindingContext = vm;
    }
  }
}