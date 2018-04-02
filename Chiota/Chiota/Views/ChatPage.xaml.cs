namespace Chiota.Views
{
  using System;

  using Chiota.Models;
  using Chiota.ViewModels;

  using Xamarin.Forms;

  public partial class ChatPage : ContentPage
  {
    private readonly ChatViewModel vm;

    public ChatPage(Contact contact, User user)
    {
      this.InitializeComponent();
      if (contact == null)
      {
        throw new ArgumentNullException();
      }

      this.Title = contact.Name;
      this.vm = new ChatViewModel(MessagesListView, contact, user);
      this.vm.DisplayMessageTooLong += () => this.DisplayAlert("Error", "Sorry, only 105 characters per message are allowed!", "OK");
      this.BindingContext = this.vm;
    }

    protected override void OnDisappearing()
    {
      this.vm.MessageLoop = false;
    }

    private void Handle_Completed(object sender, EventArgs e)
    {
      (this.BindingContext as ChatViewModel)?.SendCommand.Execute(null);
    }
  }
}
