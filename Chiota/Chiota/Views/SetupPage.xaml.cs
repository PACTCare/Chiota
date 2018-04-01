namespace Chiota.CustomCells
{
  using System;

  using Chiota.Models;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class SetupPage : ContentPage
  {
    public SetupPage(User user)
    {
      this.InitializeComponent();
      NavigationPage.SetHasNavigationBar(this, false);
      var vm = new SetupViewModel(user) { Navigation = this.Navigation };
      vm.DisplayInvalidLoginPrompt += () => this.DisplayAlert("Error", "Invalid user data, try again", "OK");

      this.BindingContext = vm;
    }

    private void Button_OnClicked(object sender, EventArgs e)
    {
      (this.BindingContext as SetupViewModel)?.AddImage();
    }
  }
}