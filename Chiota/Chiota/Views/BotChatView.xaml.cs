namespace Chiota.Views
{
  using System;

  using Chiota.Chatbot;
  using Chiota.ViewModels;

  using Xamarin.Forms;
  using Xamarin.Forms.Xaml;

  [XamlCompilation(XamlCompilationOptions.Compile)]
  public partial class BotChatView : ContentPage
  {
    public BotChatView(BotObject bot)
    {
      this.InitializeComponent();
      this.Title = bot.BotName;
      this.BindingContext = new BotChatViewModel(bot, this.MessagesListView, this.QuickReplyStack) { Navigation = this.Navigation };
    }


    private void HandleCompleted(object sender, EventArgs e)
    {
      (this.BindingContext as BotChatViewModel)?.SendCommand.Execute(null);
    }
  }
}