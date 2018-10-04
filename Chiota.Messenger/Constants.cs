namespace Chiota.Messenger
{
  using Tangle.Net.Cryptography;
  using Tangle.Net.Entity;

  /// <summary>
  /// The constants.
  /// </summary>
  public static class Constants
  {
    public static int MaxMessagesOnAddress = 6;

    public static int MessengerSecurityLevel = SecurityLevel.Medium;

    public static TryteString End => new TryteString("9ENDEGUTALLESGUT9");

    public static TryteString LineBreak => new TryteString("9CHIOTAYOURIOTACHATAPP9");

    public static int MessageCharacterLimit => 247;

    public static Tag Tag => new Tag("CHIOTAYOURIOTACHATAPP");
  }
}