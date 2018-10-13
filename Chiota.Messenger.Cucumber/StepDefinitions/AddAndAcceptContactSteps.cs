namespace Chiota.Messenger.Cucumber.StepDefinitions
{
  using System;
  using System.Linq;

  using Chiota.Messenger.Cucumber.Drivers;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using TechTalk.SpecFlow;

  [Binding]
  public class AddAndAcceptContactSteps
  {
    public AddAndAcceptContactSteps(UserDriver driver)
    {
      this.Driver = driver ?? throw new ArgumentNullException(nameof(driver));
    }

    private UserDriver Driver { get; set; }

    [Then(@"""(.*)"" should see ""(.*)"" as contact")]
    public void ThenShouldSeeAsContact(string user, string contact)
    {
      var response = this.Driver.GetContacts(user, true);
      Assert.AreEqual(ResponseCode.Success, response.Code);
      Assert.IsTrue(response.ApprovedContacts.Any(c => c.Name == contact));
    }

    [Then(@"""(.*)"" should see ""(.*)""'s contact request as pending")]
    public void ThenShouldSeeSContactRequestAsPending(string user, string contact)
    {
      var response = this.Driver.GetContacts(user, true);

      Assert.AreEqual(ResponseCode.Success, response.Code);
      Assert.IsTrue(response.PendingContactRequests.Any(c => c.Name == contact));
    }

    [When(@"""(.*)"" accepts ""(.*)""'s contact request")]
    public void WhenAcceptsSContactRequest(string receiver, string sender)
    {
      this.Driver.AcceptContact(receiver, sender);
    }

    [When(@"""(.*)"" sends ""(.*)"" a contact request")]
    public void WhenSendsAContactRequest(string sender, string receiver)
    {
      var requestResponse = this.Driver.RequestContact(sender, receiver);
      Assert.AreEqual(ResponseCode.Success, requestResponse.Code);
    }
  }
}