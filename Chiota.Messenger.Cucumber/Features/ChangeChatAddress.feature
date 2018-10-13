Feature: Change Chat Address
	Not all messages should be sent to the same address. Therefore, after 6 messages on an address, it should be changed

Scenario: Change Chat Address
	Given There is a user "Sender"
	And There is a user "Receiver"
  And "Sender" and "Receiver" are approved contacts
  And "Sender" has sent 6 messages to "Receiver"
	When "Sender" sends the message "Hello" to "Receiver"
	Then "Receiver" should be able to read the message "Hello" from "Sender"
  Then ChatAddress should be changed