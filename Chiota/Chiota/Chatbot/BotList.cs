namespace Chiota.Chatbot
{
  using System.Collections.Generic;

  public class BotList
  {
    public static List<BotObject> Bots = new List<BotObject>();

    public List<BotObject> ReturnBotList()
    {
      var bots = new List<BotObject>();
      bots.AddRange(Bots);

      // Add your own microsoft bot-framework bot here:
      //bots.Add(new BotObject()
      //{
      //  BotName = "Florence",
      //  BotSlogan = "Your health assistant",
      //  BotId = "Florence",
      //  DirectLineSecret = "", // <= your direct line secret
      //  ImageUrl = "https://florenceblob.blob.core.windows.net/thumbnails/final_verysmall2.png"
      //});

      return bots;
    }
  }
}
