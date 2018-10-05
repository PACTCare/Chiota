namespace Chiota.Messenger.Cucumber.StepDefinitions
{
  using System;
  using System.Linq;

  using Chiota.Messenger.Cucumber.Drivers;
  using Chiota.Messenger.Usecase;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.Messenger.Usecase.SendMessage;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Tangle.Net.Entity;

  using TechTalk.SpecFlow;

  [Binding]
  public class BaseSteps
  {
    public BaseSteps(UserDriver driver)
    {
      this.Driver = driver ?? throw new ArgumentNullException(nameof(driver));
    }

    protected UserDriver Driver { get; }

    [Given(@"There is a user ""(.*)""")]
    public void GivenThereIsAUser(string username)
    {
      var response = this.Driver.CreateUser(username);
      Assert.AreEqual(ResponseCode.Success, response.Code);
    }

    [Given(@"""(.*)"" and ""(.*)"" are approved contacts")]
    public void GivenAndAreApprovedContacts(string sender, string receiver)
    {
      var requestResponse = this.Driver.RequestContact(sender, receiver);
      Assert.AreEqual(ResponseCode.Success, requestResponse.Code);

      var acceptResponse = this.Driver.AcceptContact(receiver, sender);
      Assert.AreEqual(ResponseCode.Success, acceptResponse.Code);
    }

    [When(@"""(.*)"" sends the message ""(.*)"" to ""(.*)""")]
    public void WhenSendsTheMessage(string sender, string message, string receiver)
    {
      var response = this.Driver.SendMessage(sender, message, receiver);
      Assert.AreEqual(ResponseCode.Success, response.Code);
    }

    [Given(@"""(.*)"" has sent (.*) messages to ""(.*)""")]
    public void GivenHasSentMessagesTo(string sender, int messageCount, string receiver)
    {
      for (var i = 0; i < messageCount; i++)
      {
        var response = this.Driver.SendMessage(sender, Seed.Random().Value, receiver);
        Assert.AreEqual(ResponseCode.Success, response.Code);
      }
    }


    [Then(@"ChatAddress should be changed")]
    public void ThenChatAddressShouldBeChanged()
    {
      Assert.AreNotEqual(
        ((GetMessagesRequest)this.Driver.LastRequest).ChatAddress.Value,
        ((GetMessagesResponse)this.Driver.LastResponse).CurrentChatAddress.Value);
    }

    [Then(@"""(.*)"" should be able to read the message ""(.*)"" from ""(.*)""")]
    public void ThenShouldBeAbleToReadTheMessage(string receiver, string message, string sender)
    {
      var response = this.Driver.GetMessages(receiver, sender);
      Assert.AreEqual(message, response.Messages.Last().Message);
    }
  }
}