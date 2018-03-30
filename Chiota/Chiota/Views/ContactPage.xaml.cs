namespace Chiota.Views
{
  using System;

  using Chiota.Models;
  using Chiota.Services;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class ContactPage : ContentPage
  {
    private readonly User user;

    public ContactPage(User user)
    {
      this.InitializeComponent();
      this.user = user;
      if (user != null)
      {
        this.BindingContext = new ContactViewModel(user);
      }
    }

    void Handler_TextChanged(object sender, TextChangedEventArgs e)
    {
      (this.BindingContext as ContactViewModel)?.Search(e.NewTextValue);
    }

    async void Handle_ItemSelected(object sender, SelectedItemChangedEventArgs e)
    {
      if (!(e.SelectedItem is Contact contact))
      {
        return;
      }

      await this.Navigation.PushAsync(new ChatPage(contact, this.user));
      this.ContactsList.SelectedItem = null;
    }

    private void HandleNewContactClick(object sender, EventArgs e)
    {
      this.Navigation.PushAsync(new AddContact(this.user));
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