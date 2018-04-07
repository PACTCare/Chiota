namespace Chiota.Views
{
  using System;

  using Chiota.Models;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The chat page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class ChatPage : ContentPage
  {
    private ChatViewModel vm;

    public ChatPage(Contact contact, User user)
    {
      this.InitializeComponent();
      if (contact == null)
      {
        throw new ArgumentNullException();
      }

      this.Title = contact.Name;
      this.vm = new ChatViewModel(MessagesListView, contact, user) { Navigation = this.Navigation }; 
      this.vm.DisplayMessageTooLong += () => this.DisplayAlert("Error", "Sorry, only 105 characters per message are allowed!", "OK");
      this.vm.DisplayInvalidPublicKeyPrompt += () => this.DisplayAlert("Error", "Invalid public key! You contact needs to give you a new contact address.", "OK");
      this.BindingContext = this.vm;
    }

    protected override void OnAppearing()
    {
      this.vm.OnAppearing();
      base.OnAppearing();
    }

    protected override void OnDisappearing()
    {
      this.vm.OnDisappearing();
      this.vm.PageIsShown = false;
      this.vm = null;
      this.Navigation.PopAsync();
    }

    private void Handle_Completed(object sender, EventArgs e)
    {
      (this.BindingContext as ChatViewModel)?.SendCommand.Execute(null);
    }
  }
}
