namespace Chiota.Chatbot
{
  using System.Threading.Tasks;

  using Microsoft.Bot.Connector.DirectLine;

  using Plugin.SecureStorage;

  public class BotConnection
  {
    private const string ConversationIdKey = "converstationIdKey";

    private const string WatermarkKey = "watermark";

    private readonly BotObject bot;

    private DirectLineClient directLineClient;

    private string watermark;

    public BotConnection(BotObject bot)
    {
      // Todo: restore previous converstation if there was one 
      // https://github.com/tompaana/twitter-bot-fw-integration/blob/master/TwitterBotFWIntegration/DirectLineManager.cs
      this.bot = bot;
      if (CrossSecureStorage.Current.HasKey(ConversationIdKey))
      {
        if (int.TryParse(CrossSecureStorage.Current.GetValue(WatermarkKey), out var watermarkNumber))
        {
          if (watermarkNumber > 1)
          {
            // shows the last message of Florence when reopened
            this.watermark = (watermarkNumber - 2).ToString();
          }
        }
        else
        {
          this.watermark = watermarkNumber.ToString();
        }
      }
      else
      {
        // Obtain a token using the Direct Line secret
        var tokenResponse = new DirectLineClient(bot.DirectLineSecret).Tokens.GenerateTokenForNewConversation();

        // Use token to create conversation
        using (this.directLineClient = new DirectLineClient(tokenResponse.Token))
        {
          this.directLineClient.Conversations.StartConversation();
          CrossSecureStorage.Current.SetValue(ConversationIdKey, tokenResponse.ConversationId);
        }
      }
    }

    /// <summary>
    /// reconnects plus get activity
    /// </summary>
    /// <returns>Task ActivitySet</returns>
    public async Task<ActivitySet> GetActivitiesAsync()
    {
      ActivitySet activitySet;
      using (this.directLineClient = new DirectLineClient(this.bot.DirectLineSecret))
      {
        this.directLineClient.Conversations.ReconnectToConversation(
          CrossSecureStorage.Current.GetValue(ConversationIdKey),
          this.watermark);
        activitySet = await this.directLineClient.Conversations.GetActivitiesAsync(
                        CrossSecureStorage.Current.GetValue(ConversationIdKey),
                        this.watermark);
      }

      this.watermark = activitySet?.Watermark;
      if (this.watermark != null)
      {
        CrossSecureStorage.Current.SetValue(WatermarkKey, this.watermark);
      }

      return activitySet;
    }

    /// <summary>
    /// Send the message to the bot
    /// </summary>
    /// <param name="message">
    /// Input message to send
    /// </param>
    /// <returns>
    /// The <see cref="Task"/>.
    /// </returns>
    public async Task SendMessageAsync(string message)
    {
      using (this.directLineClient = new DirectLineClient(this.bot.DirectLineSecret))
      {
        var activity = new Activity
        {
          From = new ChannelAccount
          {
            Id = CrossSecureStorage.Current.GetValue(
                                                  ConversationIdKey) + "_direct",
            Name = CrossSecureStorage.Current.GetValue(
                                                    ConversationIdKey) + "_direct"
          },
          Text = message,
          Type = ActivityTypes.Message
        };
        await this.directLineClient.Conversations.PostActivityAsync(CrossSecureStorage.Current.GetValue(ConversationIdKey), activity);
      }
    }
  }
}
