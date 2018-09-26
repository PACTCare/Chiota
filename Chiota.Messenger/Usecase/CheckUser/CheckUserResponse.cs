namespace Chiota.Messenger.Usecase.CheckUser
{
  using Tangle.Net.Entity;

  public class CheckUserResponse : BaseResponse
  {
    public Address PublicKeyAddress { get; set; }
  }
}