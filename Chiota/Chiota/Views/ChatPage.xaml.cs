namespace Chiota.Views
{
  using System;

  using Chiota.Models;
  using Chiota.ViewModels;

  using Xamarin.Forms;

  public partial class ChatPage : ContentPage
  {
    public ChatPage(Contact contact, User user)
    {
      this.InitializeComponent();
      if (contact == null)
      {
        throw new ArgumentNullException();
      }

      this.Title = contact.Name;
      var vm = new ChatViewModel(contact, user);
      vm.DisplayMessageTooLong += () => this.DisplayAlert("Error", "Sorry, 106 characters per message are allowed!", "OK");
      this.BindingContext = vm;
    }

    private void Handle_Completed(object sender, EventArgs e)
    {
      (this.BindingContext as ChatViewModel)?.SendCommand.Execute(null);
    }
  }
}
