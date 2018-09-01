namespace Chiota.Views
{
  using System;

  using Chiota.Messenger.Entity;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  /// <summary>
  /// The chat page.
  /// </summary>
  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class ChatPage : ContentPage
  {
    private readonly ChatViewModel vm;

    public ChatPage(Contact contact)
    {
      this.InitializeComponent();
      if (contact == null)
      {
        throw new ArgumentNullException();
      }

      this.Title = contact.Name;
      (this.MessageEntry as Entry).TextChanged += this.OnTextChanged;
      this.vm = new ChatViewModel(this.MessagesListView, contact) { Navigation = this.Navigation }; 
      this.vm.DisplayMessageTooLong += () => this.DisplayAlert("Error", "Sorry, only 105 characters per message are allowed!", "OK");
      this.vm.DisplayMessageSendErrorPrompt += () => this.DisplayAlert("Error", "Your message couldn’t be sent.", "OK");
      this.BindingContext = this.vm;
    }

    protected override void OnAppearing()
    {
      this.vm?.OnAppearing();
      base.OnAppearing();
    }

    protected override void OnDisappearing()
    {
      this.vm?.OnDisappearing();
      base.OnDisappearing();
    }

    private void OnTextChanged(object sender, EventArgs e)
    {
      if (sender is Entry entry)
      {
        (this.BindingContext as ChatViewModel)?.MessageRestriction(entry);
      }
    }

    private void HandleCompleted(object sender, EventArgs e)
    {
      (this.BindingContext as ChatViewModel)?.SendCommand.Execute(null);
    }
  }
}
