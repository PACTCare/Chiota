namespace Chiota.Messenger.Cucumber
{
  using System.Collections.Generic;

  using Chiota.Messenger.Cucumber.Repository;
  using Chiota.Messenger.Encryption;
  using Chiota.Messenger.Repository;
  using Chiota.Messenger.Service;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Messenger.Usecase.CreateUser;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.Messenger.Usecase.SendMessage;

  using Tangle.Net.Cryptography;
  using Tangle.Net.Cryptography.Curl;
  using Tangle.Net.Cryptography.Signing;
  using Tangle.Net.ProofOfWork.Service;
  using Tangle.Net.Repository;

  public static class InstanceBag
  {
    public static CreateUserInteractor CreateUserInteractor =>
      new CreateUserInteractor(Messenger, new AddressGenerator(), NtruEncryption.Key, new SignatureFragmentGenerator(new Kerl()));

    public static AddContactInteractor AddContactInteractor => new AddContactInteractor(ContactRepository, Messenger);

    public static GetContactsInteractor GetContactsInteractor => new GetContactsInteractor(ContactRepository, Messenger);

    public static AcceptContactInteractor AcceptContactInteractor => new AcceptContactInteractor(ContactRepository, Messenger, NtruEncryption.Key);

    public static SendMessageInteractor SendMessageInteractor => new SendMessageInteractor(Messenger, NtruEncryption.Default);

    public static GetMessagesInteractor GetMessagesInteractor => new GetMessagesInteractor(Messenger, NtruEncryption.Default);

    private static IContactRepository ContactRepository => new EmptyContactRepository(IotaRepository, new SignatureValidator());

    private static IMessenger Messenger => new TangleMessenger(IotaRepository, new InMemoryTransactionCache());

    private static IIotaRepository IotaRepository =>
      new RestIotaRepository(
        new MessengerIotaClient(
          new List<string>
            {
              "https://field.deviota.com:443",
              "https://peanut.iotasalad.org:14265",
              "http://node04.iotatoken.nl:14265",
              "http://node05.iotatoken.nl:16265",
              "https://nodes.thetangle.org:443",
              "http://iota1.heidger.eu:14265",
              "https://nodes.iota.cafe:443",
              "https://potato.iotasalad.org:14265",
              "https://durian.iotasalad.org:14265",
              "https://turnip.iotasalad.org:14265",
              "https://nodes.iota.fm:443",
              "https://tuna.iotasalad.org:14265",
              "https://iotanode2.jlld.at:443",
              "https://node.iota.moe:443",
              "https://wallet1.iota.town:443",
              "https://wallet2.iota.town:443",
              "http://node03.iotatoken.nl:15265",
              "https://node.iota-tangle.io:14265",
              "https://pow4.iota.community:443",
              "https://dyn.tangle-nodes.com:443",
              "https://pow5.iota.community:443"
            }),
        new PoWSrvService());
  }
}