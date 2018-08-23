using System;
using System.Collections.Generic;
using System.Text;

namespace Chiota.Messenger.Tests.Compatibility
{
  using Chiota.Models;
  using Chiota.Services.Iota;
  using Chiota.Services.UserServices;

  using Microsoft.VisualStudio.TestTools.UnitTesting;

  using Newtonsoft.Json;

  using Tangle.Net.Entity;

  [TestClass]
    public class ContactCompatibilityTests
    {
      [TestMethod]
      public void TestContactEntityCanBeConvertedToContactViewModel()
      {
        var entityContact = new Messenger.Entity.Contact
                              {
                                ChatAddress = Seed.Random().Value,
                                ChatKeyAddress = Seed.Random().Value,
                                Name = "Hans Peter",
                                ImageHash = "asfdsafasfafasf",
                                ContactAddress = Seed.Random().Value,
                                Requested = true,
                                Rejected = false,
                                NtruKey = null,
                                PublicKeyAddress = Seed.Random().Value
                              };

        var expectedContactViewModel = new Contact
                               {
                                 ChatAddress = entityContact.ChatAddress,
                                 ChatKeyAddress = entityContact.ChatKeyAddress,
                                 Name = "Hans Peter",
                                 ImageHash = "asfdsafasfafasf",
                                 ContactAddress = entityContact.ContactAddress,
                                 Request = true,
                                 Rejected = false,
                                 NtruKey = null,
                                 PublicKeyAddress = entityContact.PublicKeyAddress
        };

        var tryteString = TryteString.FromUtf8String(JsonConvert.SerializeObject(entityContact));
        var actualContactViewModel = JsonConvert.DeserializeObject<Contact>(tryteString.ToUtf8String());

        Assert.AreEqual(expectedContactViewModel.ChatAddress, actualContactViewModel.ChatAddress);
        Assert.AreEqual(expectedContactViewModel.Request, actualContactViewModel.Request);
    }
    }
}
