namespace Chiota.Messenger.Cucumber.StepDefinitions
{
  using System;

  using Chiota.Messenger.Cucumber.Drivers;
  using Chiota.Messenger.Usecase;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

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
  }
}