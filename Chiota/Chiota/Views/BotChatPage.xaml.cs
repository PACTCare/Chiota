namespace Chiota.Views
{
  using System;

  using Chiota.Chatbot;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class BotChatPage : ContentPage
  {
    public BotChatPage(BotObject bot)
    {
      this.InitializeComponent();
      this.Title = bot.BotName;
      this.Bot = bot;
    }


    private BotObject Bot { get; }


    private void HandleCompleted(object sender, EventArgs e)
    {
      (this.BindingContext as BotChatViewModel)?.SendCommand.Execute(null);
    }

    /// <inheritdoc />
    protected override void OnAppearing()
    {
      this.BindingContext = new BotChatViewModel(this.Bot, this.MessagesListView, this.QuickReplyStack) { Navigation = this.Navigation };
      base.OnAppearing();
    }
  }
}