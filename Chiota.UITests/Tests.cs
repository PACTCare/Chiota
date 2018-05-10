namespace Chiota.UITests
{
  using System.Linq;

  using NUnit.Framework;

  using Xamarin.UITest;

  // [TestFixture(Platform.iOS)]
  [TestFixture(Platform.Android)]
  public class Tests
  {
    private IApp app;
    private Platform platform;

    public Tests(Platform platform)
    {
      this.platform = platform;
    }

    [SetUp]
    public void BeforeEachTest()
    {
      this.app = AppInitializer.StartApp(this.platform);
    }

    [Test]
    public void AppLaunches()
    {
      this.app.Screenshot("First screen.");
    }

    [Test]
    public void Login_EmptySeed_NoLogin()
    {
      // Arrange
      this.app.EnterText("RandomSeedId", "WZLV9LHH99ANV9ICQOWGFZZSXVI9OUHOVEPZBNGGYX9CKFYLTUJ9TSU9EJYDWJFNAGDFUZQ9AARWCFFKI");

      // Act
      this.app.Tap("SubmitButtonId");

      // Assert
      var appResult = this.app.Query("ActivityIndicatorId").First(result => result.Text == "Addresses are generated...");
      Assert.IsTrue(appResult != null, "Label is not displaying the correct result");
    }
  }
}

