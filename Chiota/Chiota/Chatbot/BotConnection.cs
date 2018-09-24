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
      bot = bot;
      if (CrossSecureStorage.Current.HasKey(ConversationIdKey))
      {
        if (int.TryParse(CrossSecureStorage.Current.GetValue(WatermarkKey), out var watermarkNumber))
        {
          if (watermarkNumber > 1)
          {
            // shows the last message of Florence when reopened
            watermark = (watermarkNumber - 2).ToString();
          }
        }
        else
        {
          watermark = watermarkNumber.ToString();
        }
      }
      else
      {
        // Obtain a token using the Direct Line secret
        var tokenResponse = new DirectLineClient(bot.DirectLineSecret).Tokens.GenerateTokenForNewConversation();

        // Use token to create conversation
        using (directLineClient = new DirectLineClient(tokenResponse.Token))
        {
          directLineClient.Conversations.StartConversation();
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
      using (directLineClient = new DirectLineClient(bot.DirectLineSecret))
      {
        directLineClient.Conversations.ReconnectToConversation(
          CrossSecureStorage.Current.GetValue(ConversationIdKey),
          watermark);
        activitySet = await directLineClient.Conversations.GetActivitiesAsync(
                        CrossSecureStorage.Current.GetValue(ConversationIdKey),
                        watermark);
      }

      watermark = activitySet?.Watermark;
      if (watermark != null)
      {
        CrossSecureStorage.Current.SetValue(WatermarkKey, watermark);
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
      using (directLineClient = new DirectLineClient(bot.DirectLineSecret))
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
        await directLineClient.Conversations.PostActivityAsync(CrossSecureStorage.Current.GetValue(ConversationIdKey), activity);
      }
    }
  }
}
