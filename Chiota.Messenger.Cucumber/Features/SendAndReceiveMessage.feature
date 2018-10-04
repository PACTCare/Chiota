Feature: Send And Receive Message
	In order to communicate with someone, I need to be able to send a message that he/she can receive

Scenario: Send And Receive Message
	Given There is a user "Sender"
	And There is a user "Receiver"
  And "Sender" and "Receiver" are approved contacts
	When "Sender" sends the message "Hello" to "Receiver"
	Then "Receiver" should be able to read the message "Hello" from "Sender"