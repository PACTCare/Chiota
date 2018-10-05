namespace Chiota.Messenger.Cucumber.StepDefinitions
{
  using System;

  using Chiota.Messenger.Cucumber.Drivers;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using TechTalk.SpecFlow;

  [Binding]
  public class SendAndReceiveMessageSteps
  {
    public SendAndReceiveMessageSteps(UserDriver driver) 
    {
      this.Driver = driver ?? throw new ArgumentNullException(nameof(driver));
    }

    private UserDriver Driver { get; set; }

    [Given(@"""(.*)"" and ""(.*)"" are approved contacts")]
    public void GivenAndAreApprovedContacts(string sender, string receiver)
    {
      var requestResponse = this.Driver.RequestContact(sender, receiver);
      Assert.AreEqual(ResponseCode.Success, requestResponse.Code);

      var acceptResponse = this.Driver.AcceptContact(receiver, sender);
      Assert.AreEqual(ResponseCode.Success, acceptResponse.Code);
    }

    [Then(@"""(.*)"" should be able to read the message ""(.*)"" from ""(.*)""")]
    public void ThenShouldBeAbleToReadTheMessage(string receiver, string message, string sender)
    {
      var response = this.Driver.GetMessages(receiver, sender);
      Assert.AreEqual(message, response.Messages[0].Message);
    }

    [When(@"""(.*)"" sends the message ""(.*)"" to ""(.*)""")]
    public void WhenSendsTheMessage(string sender, string message, string receiver)
    {
      var response = this.Driver.SendMessage(sender, message, receiver);
      Assert.AreEqual(ResponseCode.Success, response.Code);
    }
  }
}