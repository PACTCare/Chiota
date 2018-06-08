namespace Chiota.Views
{
  using System;

  using Chiota.Models;
  using Chiota.Services;
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

    private void HandleItemSelected(object sender, SelectedItemChangedEventArgs e)
    {
      if (!(e.SelectedItem is Contact contact))
      {
        return;
      }

      (this.BindingContext as ContactViewModel)?.OpenChatPage(contact);
    }

    private void HandleNewContactClick(object sender, EventArgs e)
    {
      this.Navigation.PushAsync(new AddContactPage());
    }

    private void HandleSettingsClick(object sender, EventArgs e)
    {
      this.Navigation.PushAsync(new SettingsPage());
    }

    private void ContactsList_OnRefreshing(object sender, EventArgs e)
    {
      (this.BindingContext as ContactViewModel)?.Refreshing();
      this.ContactsList.EndRefresh();
    }

    private void HandleLogoutClick(object sender, EventArgs e)
    {
      new SecureStorage().DeleteUser();
      Application.Current.MainPage = new NavigationPage(new LoginPage());
      this.Navigation.PopToRootAsync(true);
    }
  }
}