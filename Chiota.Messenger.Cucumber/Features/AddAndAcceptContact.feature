Feature: Add and Accept Contact
	In order to communicate with someone, I need to be able to send and accept contact requests

Scenario: Add and Accept Contact
	Given There is a user "Kevin"
	And There is a user "Chantal"
  When "Kevin" sends "Chantal" a contact request
  Then "Chantal" should see "Kevin"'s contact request as pending
  When "Chantal" accepts "Kevin"'s contact request
  Then "Chantal" should see "Kevin" as contact
  Then "Kevin" should see "Chantal" as contact