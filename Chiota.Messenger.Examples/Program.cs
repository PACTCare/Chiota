namespace Chiota.Messenger.Examples
{
  using System;

  using Chiota.Messenger.Cucumber;
  using Chiota.Messenger.Usecase.AcceptContact;
  using Chiota.Messenger.Usecase.AddContact;
  using Chiota.Messenger.Usecase.CreateUser;
  using Chiota.Messenger.Usecase.GetContacts;
  using Chiota.Messenger.Usecase.GetMessages;
  using Chiota.Messenger.Usecase.SendMessage;

  using Tangle.Net.Entity;

  public static class Program
  {
    /// <summary>
    /// Let's assume we have two people that want to chat with each other. We call them "Kevin" and "Chantal"
    /// This example shows how to establish a secure channel between them, they can use to exchange messages
    /// </summary>
    /// <note>
    /// The example may fail due to request restrictions on the nodes.
    /// </note>
    private static void Main(string[] args)
    {
      Execute();

      Console.WriteLine("Done!");
      Console.ReadKey();
    }

    private static void Execute()
    {
      // 1) First we create our users
      var kevin = InstanceBag.CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = Seed.Random() }).Result;
      var chantal = InstanceBag.CreateUserInteractor.ExecuteAsync(new CreateUserRequest { Seed = Seed.Random() }).Result;

      // 2) To establish a channel between them, one has to send a contact request
      var addResult = InstanceBag.AddContactInteractor.ExecuteAsync(
        new AddContactRequest
          {
            ContactAddress = chantal.PublicKeyAddress,
            ImagePath = "https://i.ytimg.com/vi/ZFlxCSNV5N0/maxresdefault.jpg",
            Name = "Kevin",
            PublicKeyAddress = kevin.PublicKeyAddress,
            RequestAddress = kevin.RequestAddress,
            UserPublicKey = kevin.NtruKeyPair.PublicKey
          }).Result;

      // 3) The request we just sent, will now appear as a pending request for Chantal
      var contacts = InstanceBag.GetContactsInteractor.ExecuteAsync(
                       new GetContactsRequest
                         {
                           KeyPair = chantal.NtruKeyPair, PublicKeyAddress = chantal.PublicKeyAddress, RequestAddress = chantal.RequestAddress
                         }).Result;

      // 4) We only sent one contact request, so we can assume that Kevins request is the first pending contact request. Chantal can now accept it
      var requestedContact = contacts.PendingContactRequests[0];
      var acceptResult = InstanceBag.AcceptContactInteractor.ExecuteAsync(
        new AcceptContactRequest
          {
            ChatAddress = new Address(requestedContact.ChatAddress),
            ChatKeyAddress = new Address(requestedContact.ChatKeyAddress),
            ContactAddress = new Address(requestedContact.ContactAddress),
            ContactPublicKeyAddress = new Address(requestedContact.PublicKeyAddress),
            UserPublicKeyAddress = chantal.PublicKeyAddress,
            UserKeyPair = chantal.NtruKeyPair,
            UserContactAddress = chantal.RequestAddress,
            UserImagePath = "SomeImageUri",
            UserName = "Chantal"
          }).Result;

      // 5) After accepting the contact request, a secure channel between both users has been established. We can now send messages on that channel
      var sendResult = InstanceBag.SendMessageInteractor.ExecuteAsync(
        new SendMessageRequest
          {
            ChatAddress = new Address(requestedContact.ChatAddress),
            ChatKeyAddress = new Address(requestedContact.ChatKeyAddress),
            UserKeyPair = chantal.NtruKeyPair,
            UserPublicKeyAddress = chantal.PublicKeyAddress,
            Message = "Hello, Kevin! Nice to see you are still around!"
          }).Result;

      // 6) Kevin can now receive the message Chantal has sent
      var response = InstanceBag.GetMessagesInteractor.ExecuteAsync(
        new GetMessagesRequest
          {
            ChatAddress = new Address(requestedContact.ChatAddress),
            ChatKeyAddress = new Address(requestedContact.ChatKeyAddress),
            UserKeyPair = kevin.NtruKeyPair
          }).Result;

      response.Messages.ForEach(m => Console.WriteLine(m.Message));
    }
  }
}