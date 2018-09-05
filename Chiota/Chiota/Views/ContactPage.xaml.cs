namespace Chiota.Views
{
  using System;

  using Chiota.Messenger.Entity;
  using Chiota.Models;
  using Chiota.Services.DependencyInjection;
  using Chiota.Services.Navigation;
  using Chiota.Services.Storage;
  using Chiota.Services.UserServices;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The contact page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class ContactPage : ContentPage
  {
    public ContactPage()
    {
      this.InitializeComponent();

      switch (Device.RuntimePlatform)
      {
        // Android 7 doesn't show searchbar without it, on windows it's too big
        case Device.Android:
          this.SearchBar.HeightRequest = 45;
          break;
      }

      if (UserService.CurrentUser != null)
      {
        this.BindingContext = new ContactViewModel { Navigation = this.Navigation };
      }
    }

    protected override void OnAppearing()
    {
      (this.BindingContext as ContactViewModel)?.OnAppearing();
      base.OnAppearing();
    }

    protected override void OnDisappearing()
    {
      (this.BindingContext as ContactViewModel)?.OnDisappearing();
      base.OnDisappearing();
    }

    private void Handler_TextChanged(object sender, TextChangedEventArgs e)
    {
      (this.BindingContext as ContactViewModel)?.Search(e.NewTextValue);
    }

    private async void HandleItemSelected(object sender, SelectedItemChangedEventArgs e)
    {
      if (!(e?.SelectedItem is ContactListViewModel contactViewModel))
      {
        return;
      }

      if (!(this.BindingContext is ContactViewModel context))
      {
        return;
      }

      await context.OpenChatPageAsync(contactViewModel.Contact);
    }

    private async void HandleNewContactClick(object sender, EventArgs e)
    {
      await this.Navigation.PushAsync(new AddContactPage());
    }

    private async void HandleSettingsClick(object sender, EventArgs e)
    {
      await this.Navigation.PushAsync(new SettingsPage());
    }

    private void ContactsList_OnRefreshing(object sender, EventArgs e)
    {
      (this.BindingContext as ContactViewModel)?.Refreshing();
      this.ContactsList.EndRefresh();
    }

    private async void HandleLogoutClick(object sender, EventArgs e)
    {
      new SecureStorage().DeleteUser();
      Application.Current.MainPage = new NavigationPage(DependencyResolver.Resolve<INavigationService>().LoginEntryPoint);
      await this.Navigation.PopToRootAsync(true);
    }
  }
}